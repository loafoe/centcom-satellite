// Package spire provides SPIFFE/SPIRE integration for workload identity.
package spire

import (
	"fmt"
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

	// TrustDomain is the SPIFFE trust domain.
	// Example: "example.org"
	TrustDomain string

	// AllowedSPIFFEIDs is a list of SPIFFE IDs allowed to connect.
	// If empty, any valid SVID from the trust domain is accepted.
	// Example: ["spiffe://example.org/ai-agent", "spiffe://example.org/monitoring"]
	AllowedSPIFFEIDs []string
}

// Validate checks that the configuration is valid when SPIRE is enabled.
func (c *Config) Validate() error {
	if !c.Enabled {
		return nil
	}

	if c.AgentSocket == "" {
		return fmt.Errorf("SPIRE_AGENT_SOCKET is required when SPIRE is enabled")
	}

	if c.TrustDomain == "" {
		return fmt.Errorf("SPIRE_TRUST_DOMAIN is required when SPIRE is enabled")
	}

	// Validate SPIFFE ID format
	for _, id := range c.AllowedSPIFFEIDs {
		if !strings.HasPrefix(id, "spiffe://") {
			return fmt.Errorf("invalid SPIFFE ID format: %s (must start with spiffe://)", id)
		}
	}

	return nil
}

// IsIDAllowed checks if a SPIFFE ID is in the allowed list.
// Returns true if the allowed list is empty (allow all from trust domain).
func (c *Config) IsIDAllowed(spiffeID string) bool {
	if len(c.AllowedSPIFFEIDs) == 0 {
		return true
	}

	for _, allowed := range c.AllowedSPIFFEIDs {
		if spiffeID == allowed {
			return true
		}
	}

	return false
}
