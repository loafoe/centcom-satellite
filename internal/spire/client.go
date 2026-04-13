package spire

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

// Client manages the connection to the SPIRE workload API.
type Client struct {
	config    *Config
	source    *workloadapi.X509Source
	jwtSource *workloadapi.JWTSource
	mu        sync.RWMutex
}

// NewClient creates a new SPIRE client.
func NewClient(cfg *Config) *Client {
	return &Client{
		config: cfg,
	}
}

// Start connects to the SPIRE workload API and starts watching for SVIDs.
func (c *Client) Start(ctx context.Context) error {
	if !c.config.Enabled {
		slog.Info("SPIRE disabled, skipping workload API connection")
		return nil
	}

	slog.Info("connecting to SPIRE workload API",
		"socket", c.config.AgentSocket,
		"trust_domains", c.config.TrustDomains,
		"jwt_enabled", c.config.JWT.Enabled,
	)

	source, err := workloadapi.NewX509Source(ctx,
		workloadapi.WithClientOptions(
			workloadapi.WithAddr(c.config.AgentSocket),
		),
	)
	if err != nil {
		return fmt.Errorf("failed to create X509 source: %w", err)
	}

	c.mu.Lock()
	c.source = source
	c.mu.Unlock()

	// Log our SPIFFE ID
	svid, err := source.GetX509SVID()
	if err != nil {
		return fmt.Errorf("failed to get initial SVID: %w", err)
	}

	slog.Info("acquired SPIFFE identity",
		"spiffe_id", svid.ID.String(),
		"expires", svid.Certificates[0].NotAfter,
	)

	// Initialize JWT source if JWT auth is enabled
	if c.config.JWT.Enabled {
		jwtSource, err := workloadapi.NewJWTSource(ctx,
			workloadapi.WithClientOptions(
				workloadapi.WithAddr(c.config.AgentSocket),
			),
		)
		if err != nil {
			return fmt.Errorf("failed to create JWT source: %w", err)
		}

		c.mu.Lock()
		c.jwtSource = jwtSource
		c.mu.Unlock()

		slog.Info("JWT-SVID validation enabled",
			"audiences", c.config.JWT.Audiences,
		)
	}

	return nil
}

// Close shuts down the SPIRE client.
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	var errs []error
	if c.source != nil {
		if err := c.source.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if c.jwtSource != nil {
		if err := c.jwtSource.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("errors closing SPIRE client: %v", errs)
	}
	return nil
}

// GetTLSConfig returns a TLS config for the server that requires mTLS
// with SVID verification.
func (c *Client) GetTLSConfig() (*tls.Config, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.source == nil {
		return nil, fmt.Errorf("SPIRE client not started")
	}

	// Parse all configured trust domains
	trustDomains := make([]spiffeid.TrustDomain, 0, len(c.config.TrustDomains))
	for _, tdStr := range c.config.TrustDomains {
		td, err := spiffeid.TrustDomainFromString(tdStr)
		if err != nil {
			return nil, fmt.Errorf("invalid trust domain %q: %w", tdStr, err)
		}
		trustDomains = append(trustDomains, td)
	}

	// Build authorizer that accepts SVIDs from any of the configured trust domains
	authorizer := authorizeMemberOfAny(trustDomains)

	// Create TLS config that:
	// 1. Presents our SVID as server certificate
	// 2. Requires client certificates (mTLS)
	// 3. Validates client SVIDs against configured trust domains
	tlsConfig := tlsconfig.MTLSServerConfig(
		c.source,
		c.source,
		authorizer,
	)

	// Add custom verification to check allowed SPIFFE IDs
	if len(c.config.AllowedSPIFFEIDs) > 0 {
		originalVerify := tlsConfig.VerifyPeerCertificate
		tlsConfig.VerifyPeerCertificate = func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			// First run the original SVID verification
			if originalVerify != nil {
				if err := originalVerify(rawCerts, verifiedChains); err != nil {
					return err
				}
			}

			// Then check against our allowed list
			if len(verifiedChains) > 0 && len(verifiedChains[0]) > 0 {
				cert := verifiedChains[0][0]
				for _, uri := range cert.URIs {
					if c.config.IsIDAllowed(uri.String()) {
						return nil
					}
				}
				return fmt.Errorf("SPIFFE ID not in allowed list")
			}

			return fmt.Errorf("no client certificate provided")
		}
	}

	return tlsConfig, nil
}

// WrapListener wraps a net.Listener with TLS using SPIRE SVIDs.
func (c *Client) WrapListener(listener net.Listener) (net.Listener, error) {
	tlsConfig, err := c.GetTLSConfig()
	if err != nil {
		return nil, err
	}

	return tls.NewListener(listener, tlsConfig), nil
}

// IsEnabled returns whether SPIRE is enabled.
func (c *Client) IsEnabled() bool {
	return c.config.Enabled
}

// GetAllowedIDs returns the list of allowed SPIFFE IDs.
func (c *Client) GetAllowedIDs() []string {
	return c.config.AllowedSPIFFEIDs
}

// IsJWTEnabled returns whether JWT-SVID authentication is enabled.
func (c *Client) IsJWTEnabled() bool {
	return c.config.Enabled && c.config.JWT.Enabled
}

// ValidateJWTToken validates a JWT-SVID token from the Authorization header.
// Returns the validated SPIFFE ID on success.
func (c *Client) ValidateJWTToken(ctx context.Context, token string) (spiffeid.ID, error) {
	c.mu.RLock()
	jwtSource := c.jwtSource
	c.mu.RUnlock()

	if jwtSource == nil {
		return spiffeid.ID{}, fmt.Errorf("JWT source not initialized")
	}

	// Remove "Bearer " prefix if present
	token = strings.TrimPrefix(token, "Bearer ")
	token = strings.TrimPrefix(token, "bearer ")

	// Parse and validate the JWT-SVID
	svid, err := jwtsvid.ParseAndValidate(token, jwtSource, c.config.JWT.Audiences)
	if err != nil {
		return spiffeid.ID{}, fmt.Errorf("JWT validation failed: %w", err)
	}

	// Check if the SPIFFE ID is from an allowed trust domain
	if !c.config.IsTrustDomainAllowed(svid.ID.TrustDomain().Name()) {
		return spiffeid.ID{}, fmt.Errorf("SPIFFE ID %q is not from an allowed trust domain", svid.ID)
	}

	// Check if the SPIFFE ID is in the allowed list (if configured)
	if !c.config.IsIDAllowed(svid.ID.String()) {
		return spiffeid.ID{}, fmt.Errorf("SPIFFE ID %q is not in allowed list", svid.ID)
	}

	slog.Debug("JWT-SVID validated",
		"spiffe_id", svid.ID.String(),
		"audiences", svid.Audience,
	)

	return svid.ID, nil
}

// authorizeMemberOfAny returns an Authorizer that accepts SVIDs from any of the
// specified trust domains. This supports federated SPIFFE deployments.
func authorizeMemberOfAny(trustDomains []spiffeid.TrustDomain) tlsconfig.Authorizer {
	return func(id spiffeid.ID, _ [][]*x509.Certificate) error {
		for _, td := range trustDomains {
			if id.MemberOf(td) {
				return nil
			}
		}
		return fmt.Errorf("SPIFFE ID %q is not a member of any allowed trust domain", id)
	}
}
