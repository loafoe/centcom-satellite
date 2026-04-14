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
	// Example: ["pico-agent", "https://pico-agent.example.org"]
	Audiences []string
}

// Validate checks that the configuration is valid when SPIRE is enabled.
func (c *Config) Validate() error {
	if !c.Enabled {
		return nil
	}

	if c.AgentSocket == "" {
		return fmt.Errorf("SPIRE_AGENT_SOCKET is required when SPIRE is enabled")
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
	if c.JWT.Enabled && len(c.JWT.Audiences) == 0 {
		return fmt.Errorf("SPIRE_JWT_AUDIENCES is required when JWT-SVID auth is enabled")
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
