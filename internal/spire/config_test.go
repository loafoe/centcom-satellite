package spire

import "testing"

func TestConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		config  Config
		wantErr bool
	}{
		{
			name:    "disabled - no validation",
			config:  Config{Enabled: false},
			wantErr: false,
		},
		{
			name: "enabled - valid config with single trust domain",
			config: Config{
				Enabled:      true,
				AgentSocket:  "unix:///run/spire/agent.sock",
				TrustDomains: []string{"example.org"},
			},
			wantErr: false,
		},
		{
			name: "enabled - valid config with multiple trust domains",
			config: Config{
				Enabled:      true,
				AgentSocket:  "unix:///run/spire/agent.sock",
				TrustDomains: []string{"example.org", "partner.com"},
			},
			wantErr: false,
		},
		{
			name: "enabled - with allowed IDs",
			config: Config{
				Enabled:          true,
				AgentSocket:      "unix:///run/spire/agent.sock",
				TrustDomains:     []string{"example.org"},
				AllowedSPIFFEIDs: []string{"spiffe://example.org/ai-agent"},
			},
			wantErr: false,
		},
		{
			name: "enabled - missing socket",
			config: Config{
				Enabled:      true,
				TrustDomains: []string{"example.org"},
			},
			wantErr: true,
		},
		{
			name: "enabled - missing trust domains",
			config: Config{
				Enabled:     true,
				AgentSocket: "unix:///run/spire/agent.sock",
			},
			wantErr: true,
		},
		{
			name: "enabled - invalid trust domain format (has spiffe prefix)",
			config: Config{
				Enabled:      true,
				AgentSocket:  "unix:///run/spire/agent.sock",
				TrustDomains: []string{"spiffe://example.org"},
			},
			wantErr: true,
		},
		{
			name: "enabled - empty trust domain in list",
			config: Config{
				Enabled:      true,
				AgentSocket:  "unix:///run/spire/agent.sock",
				TrustDomains: []string{"example.org", ""},
			},
			wantErr: true,
		},
		{
			name: "enabled - invalid SPIFFE ID format",
			config: Config{
				Enabled:          true,
				AgentSocket:      "unix:///run/spire/agent.sock",
				TrustDomains:     []string{"example.org"},
				AllowedSPIFFEIDs: []string{"invalid-id"},
			},
			wantErr: true,
		},
		{
			name: "federation bundle source - valid, mtls disabled, endpoint covers trust domain",
			config: Config{
				Enabled:      true,
				TrustDomains: []string{"example.org"},
				MTLSEnabled:  false,
				JWT: JWTConfig{
					Enabled:      true,
					Audiences:    []string{"centcom-satellite"},
					BundleSource: "federation",
					FederationBundleEndpoints: map[string]string{
						"example.org": "https://spire-server.example.org/bundle",
					},
				},
			},
			wantErr: false,
		},
		{
			name: "federation bundle source - does not require AgentSocket",
			config: Config{
				Enabled:      true,
				TrustDomains: []string{"example.org"},
				MTLSEnabled:  false,
				JWT: JWTConfig{
					Enabled:      true,
					Audiences:    []string{"centcom-satellite"},
					BundleSource: "federation",
					FederationBundleEndpoints: map[string]string{
						"example.org": "https://spire-server.example.org/bundle",
					},
				},
			},
			wantErr: false, // AgentSocket is empty here and must NOT trigger a validation error
		},
		{
			name: "federation bundle source - rejected when MTLS also enabled",
			config: Config{
				Enabled:      true,
				AgentSocket:  "unix:///run/spire/agent.sock",
				TrustDomains: []string{"example.org"},
				MTLSEnabled:  true,
				JWT: JWTConfig{
					Enabled:      true,
					Audiences:    []string{"centcom-satellite"},
					BundleSource: "federation",
					FederationBundleEndpoints: map[string]string{
						"example.org": "https://spire-server.example.org/bundle",
					},
				},
			},
			wantErr: true,
		},
		{
			name: "federation bundle source - missing endpoints map entirely",
			config: Config{
				Enabled:      true,
				TrustDomains: []string{"example.org"},
				MTLSEnabled:  false,
				JWT: JWTConfig{
					Enabled:      true,
					Audiences:    []string{"centcom-satellite"},
					BundleSource: "federation",
				},
			},
			wantErr: true,
		},
		{
			name: "federation bundle source - endpoints map missing one trust domain",
			config: Config{
				Enabled:      true,
				TrustDomains: []string{"example.org", "partner.com"},
				MTLSEnabled:  false,
				JWT: JWTConfig{
					Enabled:      true,
					Audiences:    []string{"centcom-satellite"},
					BundleSource: "federation",
					FederationBundleEndpoints: map[string]string{
						"example.org": "https://spire-server.example.org/bundle",
					},
				},
			},
			wantErr: true,
		},
		{
			name: "unrecognized bundle source value",
			config: Config{
				Enabled:      true,
				AgentSocket:  "unix:///run/spire/agent.sock",
				TrustDomains: []string{"example.org"},
				JWT: JWTConfig{
					Enabled:      true,
					Audiences:    []string{"centcom-satellite"},
					BundleSource: "nonsense",
				},
			},
			wantErr: true,
		},
		{
			name: "empty bundle source defaults to workload_api behavior (socket still required)",
			config: Config{
				Enabled:      true,
				TrustDomains: []string{"example.org"},
				JWT: JWTConfig{
					Enabled:   true,
					Audiences: []string{"centcom-satellite"},
					// BundleSource left empty — must behave exactly like "workload_api".
				},
			},
			wantErr: true, // AgentSocket is empty, and workload_api mode requires it
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.wantErr && err == nil {
				t.Error("expected error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestConfig_Validate_WorkloadAPIStillRequiresSocket(t *testing.T) {
	cfg := Config{
		Enabled:      true,
		TrustDomains: []string{"example.org"},
		JWT:          JWTConfig{Enabled: true, Audiences: []string{"x"}},
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error: workload_api (default) bundle source still requires AgentSocket")
	}
}

func TestConfig_IsIDAllowed(t *testing.T) {
	tests := []struct {
		name     string
		config   Config
		spiffeID string
		want     bool
	}{
		{
			name:     "empty allowed list - allow all",
			config:   Config{},
			spiffeID: "spiffe://example.org/anything",
			want:     true,
		},
		{
			name: "ID in allowed list",
			config: Config{
				AllowedSPIFFEIDs: []string{
					"spiffe://example.org/ai-agent",
					"spiffe://example.org/monitoring",
				},
			},
			spiffeID: "spiffe://example.org/ai-agent",
			want:     true,
		},
		{
			name: "ID not in allowed list",
			config: Config{
				AllowedSPIFFEIDs: []string{
					"spiffe://example.org/ai-agent",
				},
			},
			spiffeID: "spiffe://example.org/other-service",
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.config.IsIDAllowed(tt.spiffeID)
			if got != tt.want {
				t.Errorf("IsIDAllowed() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestConfig_IsTrustDomainAllowed(t *testing.T) {
	tests := []struct {
		name        string
		config      Config
		trustDomain string
		want        bool
	}{
		{
			name: "single trust domain - allowed",
			config: Config{
				TrustDomains: []string{"example.org"},
			},
			trustDomain: "example.org",
			want:        true,
		},
		{
			name: "single trust domain - not allowed",
			config: Config{
				TrustDomains: []string{"example.org"},
			},
			trustDomain: "other.org",
			want:        false,
		},
		{
			name: "multiple trust domains - first allowed",
			config: Config{
				TrustDomains: []string{"example.org", "partner.com"},
			},
			trustDomain: "example.org",
			want:        true,
		},
		{
			name: "multiple trust domains - second allowed",
			config: Config{
				TrustDomains: []string{"example.org", "partner.com"},
			},
			trustDomain: "partner.com",
			want:        true,
		},
		{
			name: "multiple trust domains - not allowed",
			config: Config{
				TrustDomains: []string{"example.org", "partner.com"},
			},
			trustDomain: "untrusted.org",
			want:        false,
		},
		{
			name:        "empty trust domains - not allowed",
			config:      Config{},
			trustDomain: "example.org",
			want:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.config.IsTrustDomainAllowed(tt.trustDomain)
			if got != tt.want {
				t.Errorf("IsTrustDomainAllowed() = %v, want %v", got, tt.want)
			}
		})
	}
}
