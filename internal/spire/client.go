package spire

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"net"
	"sync"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

// Client manages the connection to the SPIRE workload API.
type Client struct {
	config *Config
	source *workloadapi.X509Source
	mu     sync.RWMutex
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
		"trust_domain", c.config.TrustDomain,
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

	return nil
}

// Close shuts down the SPIRE client.
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.source != nil {
		return c.source.Close()
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

	td, err := spiffeid.TrustDomainFromString(c.config.TrustDomain)
	if err != nil {
		return nil, fmt.Errorf("invalid trust domain: %w", err)
	}

	// Create TLS config that:
	// 1. Presents our SVID as server certificate
	// 2. Requires client certificates (mTLS)
	// 3. Validates client SVIDs against our trust domain
	tlsConfig := tlsconfig.MTLSServerConfig(
		c.source,
		c.source,
		tlsconfig.AuthorizeMemberOf(td),
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
