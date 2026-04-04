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
			name: "enabled - valid config",
			config: Config{
				Enabled:     true,
				AgentSocket: "unix:///run/spire/agent.sock",
				TrustDomain: "example.org",
			},
			wantErr: false,
		},
		{
			name: "enabled - with allowed IDs",
			config: Config{
				Enabled:          true,
				AgentSocket:      "unix:///run/spire/agent.sock",
				TrustDomain:      "example.org",
				AllowedSPIFFEIDs: []string{"spiffe://example.org/ai-agent"},
			},
			wantErr: false,
		},
		{
			name: "enabled - missing socket",
			config: Config{
				Enabled:     true,
				TrustDomain: "example.org",
			},
			wantErr: true,
		},
		{
			name: "enabled - missing trust domain",
			config: Config{
				Enabled:     true,
				AgentSocket: "unix:///run/spire/agent.sock",
			},
			wantErr: true,
		},
		{
			name: "enabled - invalid SPIFFE ID format",
			config: Config{
				Enabled:          true,
				AgentSocket:      "unix:///run/spire/agent.sock",
				TrustDomain:      "example.org",
				AllowedSPIFFEIDs: []string{"invalid-id"},
			},
			wantErr: true,
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
