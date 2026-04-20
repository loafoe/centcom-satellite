package config

import (
	"os"
	"testing"
)

func TestLoad(t *testing.T) {
	tests := []struct {
		name    string
		envVars map[string]string
		wantErr bool
	}{
		{
			name: "valid configuration",
			envVars: map[string]string{
				"WEBHOOK_SECRET": "test-secret",
				"PORT":           "8080",
				"METRICS_PORT":   "9090",
			},
			wantErr: false,
		},
		{
			name: "missing webhook secret",
			envVars: map[string]string{
				"PORT":         "8080",
				"METRICS_PORT": "9090",
			},
			wantErr: true,
		},
		{
			name: "same port and metrics port",
			envVars: map[string]string{
				"WEBHOOK_SECRET": "test-secret",
				"PORT":           "8080",
				"METRICS_PORT":   "8080",
			},
			wantErr: true,
		},
		{
			name: "invalid log level",
			envVars: map[string]string{
				"WEBHOOK_SECRET": "test-secret",
				"LOG_LEVEL":      "invalid",
			},
			wantErr: true,
		},
		{
			name: "invalid log format",
			envVars: map[string]string{
				"WEBHOOK_SECRET": "test-secret",
				"LOG_FORMAT":     "invalid",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clear environment
			os.Clearenv()

			// Set test environment
			for k, v := range tt.envVars {
				_ = os.Setenv(k, v)
			}

			cfg, err := Load()
			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if cfg == nil {
				t.Error("expected config, got nil")
			}
		})
	}
}

func TestConfigDefaults(t *testing.T) {
	os.Clearenv()
	_ = os.Setenv("WEBHOOK_SECRET", "test-secret")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.Port != 8080 {
		t.Errorf("expected default Port 8080, got %d", cfg.Port)
	}

	if cfg.MetricsPort != 9090 {
		t.Errorf("expected default MetricsPort 9090, got %d", cfg.MetricsPort)
	}

	if cfg.LogLevel != "info" {
		t.Errorf("expected default LogLevel 'info', got %s", cfg.LogLevel)
	}

	if cfg.LogFormat != "json" {
		t.Errorf("expected default LogFormat 'json', got %s", cfg.LogFormat)
	}

	if cfg.OTelServiceName != "pico-agent" {
		t.Errorf("expected default OTelServiceName 'pico-agent', got %s", cfg.OTelServiceName)
	}
}

func TestGetEnvInt(t *testing.T) {
	os.Clearenv()

	// Test default
	if got := getEnvInt("MISSING", 42); got != 42 {
		t.Errorf("expected 42, got %d", got)
	}

	// Test valid value
	_ = os.Setenv("TEST_INT", "123")
	if got := getEnvInt("TEST_INT", 42); got != 123 {
		t.Errorf("expected 123, got %d", got)
	}

	// Test invalid value falls back to default
	_ = os.Setenv("TEST_INT", "notanumber")
	if got := getEnvInt("TEST_INT", 42); got != 42 {
		t.Errorf("expected 42, got %d", got)
	}
}
