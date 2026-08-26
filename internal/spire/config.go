// Package spire provides SPIFFE/SPIRE integration for workload identity.
package spire

import (
	"fmt"
	"slices"
	"strings"
)

// Config holds SPIRE configuration.
type Config struct {
	// Enabled controls whether SPIRE authentication is active.
	Enabled bool

	// AgentSocket is the path to the SPIRE agent socket.
	// Default: /run/spire/agent/sockets/spire-agent.sock (Kubernetes)
	// or unix:///tmp/spire-agent/public/api.sock (local dev)
	AgentSocket string

	// TrustDomains is the list of SPIFFE trust domains to accept.
	// Supports federated SPIFFE deployments with multiple trust domains.
	// Example: ["example.org", "partner.com"]
	TrustDomains []string

	// AllowedSPIFFEIDs is a list of SPIFFE IDs allowed to connect.
	// If empty, any valid SVID from the configured trust domains is accepted.
	// Example: ["spiffe://example.org/ai-agent", "spiffe://partner.com/service"]
	AllowedSPIFFEIDs []string

	// MTLSEnabled controls whether to use X.509 mTLS for transport security.
	// When false, the server runs plain HTTP and relies on JWT-SVID for auth.
	// Default: true (for backward compatibility)
	MTLSEnabled bool

	// JWT holds configuration for JWT-SVID authentication.
	JWT JWTConfig
}

// JWTConfig holds JWT-SVID specific configuration.
type JWTConfig struct {
	// Enabled controls whether JWT-SVID authentication is active.
	// Can be used alongside or instead of X.509 mTLS.
	Enabled bool

	// Audiences is the list of expected JWT audience values.
	// The JWT must contain at least one of these audiences.
	// Example: ["centcom-satellite", "https://centcom-satellite.example.org"]
	Audiences []string

	// BundleSource selects how the JWT trust bundle is obtained.
	// "workload_api" (default, used when empty) fetches it from the local
	// SPIRE Workload API, exactly as before this field existed. "federation"
	// fetches it from a SPIFFE Federation Bundle Endpoint instead — no
	// local SPIRE Agent required. Explicit, no auto-detection between them.
	BundleSource string

	// FederationBundleEndpoints maps trust domain -> federation bundle
	// endpoint URL (e.g. "example.org" -> "https://spire-server.example.org/bundle").
	// Required, with one entry per trust domain in TrustDomains, when
	// BundleSource is "federation".
	FederationBundleEndpoints map[string]string

	// FederationCABundlePath is an optional PEM file of root CAs to trust
	// when fetching from FederationBundleEndpoints. Empty (default) uses
	// the system trust store — the common case for an endpoint behind a
	// normal ALB/ingress with a publicly-trusted certificate.
	FederationCABundlePath string
}

// Validate checks that the configuration is valid when SPIRE is enabled.
func (c *Config) Validate() error {
	if !c.Enabled {
		return nil
	}

	usesFederation := c.JWT.Enabled && c.JWT.BundleSource == "federation"

	if !usesFederation && c.AgentSocket == "" {
		return fmt.Errorf("SPIRE_AGENT_SOCKET is required when SPIRE is enabled (unless SPIRE_JWT_BUNDLE_SOURCE=federation)")
	}

	if len(c.TrustDomains) == 0 {
		return fmt.Errorf("SPIRE_TRUST_DOMAINS is required when SPIRE is enabled")
	}

	// Validate trust domain format (should not contain spiffe:// prefix)
	for _, td := range c.TrustDomains {
		if strings.HasPrefix(td, "spiffe://") {
			return fmt.Errorf("invalid trust domain format: %s (should not include spiffe:// prefix)", td)
		}
		if td == "" {
			return fmt.Errorf("empty trust domain in SPIRE_TRUST_DOMAINS")
		}
	}

	// Validate SPIFFE ID format
	for _, id := range c.AllowedSPIFFEIDs {
		if !strings.HasPrefix(id, "spiffe://") {
			return fmt.Errorf("invalid SPIFFE ID format: %s (must start with spiffe://)", id)
		}
	}

	// Validate JWT config
	if c.JWT.Enabled {
		if len(c.JWT.Audiences) == 0 {
			return fmt.Errorf("SPIRE_JWT_AUDIENCES is required when JWT-SVID auth is enabled")
		}

		switch c.JWT.BundleSource {
		case "", "workload_api":
			// Default; nothing further to validate — AgentSocket already
			// checked above.
		case "federation":
			if c.MTLSEnabled {
				return fmt.Errorf("SPIRE_MTLS_ENABLED must be false when SPIRE_JWT_BUNDLE_SOURCE=federation (federation mode has no X.509 identity source)")
			}
			if len(c.JWT.FederationBundleEndpoints) == 0 {
				return fmt.Errorf("SPIRE_FEDERATION_BUNDLE_ENDPOINTS is required when SPIRE_JWT_BUNDLE_SOURCE=federation")
			}
			for _, td := range c.TrustDomains {
				if _, ok := c.JWT.FederationBundleEndpoints[td]; !ok {
					return fmt.Errorf("SPIRE_FEDERATION_BUNDLE_ENDPOINTS is missing an entry for trust domain %q", td)
				}
			}
		default:
			return fmt.Errorf(`SPIRE_JWT_BUNDLE_SOURCE must be "workload_api" or "federation", got %q`, c.JWT.BundleSource)
		}
	}

	return nil
}

// IsIDAllowed checks if a SPIFFE ID is in the allowed list.
// Returns true if the allowed list is empty (allow all from trust domains).
func (c *Config) IsIDAllowed(spiffeID string) bool {
	if len(c.AllowedSPIFFEIDs) == 0 {
		return true
	}
	return slices.Contains(c.AllowedSPIFFEIDs, spiffeID)
}

// IsTrustDomainAllowed checks if a trust domain is in the configured list.
func (c *Config) IsTrustDomainAllowed(trustDomain string) bool {
	return slices.Contains(c.TrustDomains, trustDomain)
}
