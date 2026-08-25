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
			name: "valid with SPIRE enabled",
			envVars: map[string]string{
				"SPIRE_ENABLED":       "true",
				"SPIRE_TRUST_DOMAINS": "example.org",
				"PORT":                "8080",
				"METRICS_PORT":        "9090",
			},
			wantErr: false,
		},
		{
			name: "valid with allow unauthenticated",
			envVars: map[string]string{
				"ALLOW_UNAUTHENTICATED": "true",
				"PORT":                  "8080",
				"METRICS_PORT":          "9090",
			},
			wantErr: false,
		},
		{
			name: "invalid - no auth configured",
			envVars: map[string]string{
				"PORT":         "8080",
				"METRICS_PORT": "9090",
			},
			wantErr: true,
		},
		{
			name: "same port and metrics port",
			envVars: map[string]string{
				"ALLOW_UNAUTHENTICATED": "true",
				"PORT":                  "8080",
				"METRICS_PORT":          "8080",
			},
			wantErr: true,
		},
		{
			name: "invalid log level",
			envVars: map[string]string{
				"ALLOW_UNAUTHENTICATED": "true",
				"LOG_LEVEL":             "invalid",
			},
			wantErr: true,
		},
		{
			name: "invalid log format",
			envVars: map[string]string{
				"ALLOW_UNAUTHENTICATED": "true",
				"LOG_FORMAT":            "invalid",
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
	_ = os.Setenv("ALLOW_UNAUTHENTICATED", "true")

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

	if cfg.OTelServiceName != "centcom-satellite" {
		t.Errorf("expected default OTelServiceName 'centcom-satellite', got %s", cfg.OTelServiceName)
	}

	if cfg.AllowUnauthenticated != true {
		t.Errorf("expected AllowUnauthenticated true, got %v", cfg.AllowUnauthenticated)
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

func TestLoad_CloudWatchRCAFlag(t *testing.T) {
	t.Setenv("ALLOW_UNAUTHENTICATED", "true")
	t.Setenv("CLOUDWATCH_RCA_ENABLED", "true")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !cfg.Features.CloudWatchRCAEnabled {
		t.Fatal("CloudWatchRCAEnabled = false, want true")
	}
}

func TestLoad_SecurityHubFlags(t *testing.T) {
	t.Setenv("ALLOW_UNAUTHENTICATED", "true")
	t.Setenv("SECURITYHUB_ENABLED", "true")
	t.Setenv("SECURITYHUB_WRITE_ENABLED", "true")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !cfg.Features.SecurityHubEnabled {
		t.Fatal("SecurityHubEnabled = false, want true")
	}
	if !cfg.Features.SecurityHubWriteEnabled {
		t.Fatal("SecurityHubWriteEnabled = false, want true")
	}
}

func TestLoad_SecurityHubFlagsDefaultFalse(t *testing.T) {
	t.Setenv("ALLOW_UNAUTHENTICATED", "true")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Features.SecurityHubEnabled {
		t.Fatal("SecurityHubEnabled = true, want false by default")
	}
	if cfg.Features.SecurityHubWriteEnabled {
		t.Fatal("SecurityHubWriteEnabled = true, want false by default")
	}
}

func TestLoad_AWSAssumeRoleDefaultsEmpty(t *testing.T) {
	t.Setenv("ALLOW_UNAUTHENTICATED", "true")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.AWSAssumeRole.ARN != "" {
		t.Fatalf("AWSAssumeRole.ARN = %q, want empty by default", cfg.AWSAssumeRole.ARN)
	}
	if cfg.AWSAssumeRole.SessionName != "centcom-satellite" {
		t.Fatalf("AWSAssumeRole.SessionName = %q, want default centcom-satellite", cfg.AWSAssumeRole.SessionName)
	}
}

func TestLoad_AWSAssumeRoleFromEnv(t *testing.T) {
	t.Setenv("ALLOW_UNAUTHENTICATED", "true")
	t.Setenv("AWS_ASSUME_ROLE_ARN", "arn:aws:iam::123456789012:role/centcom-satellite-remote")
	t.Setenv("AWS_ASSUME_ROLE_EXTERNAL_ID", "shared-secret-id")
	t.Setenv("AWS_ASSUME_ROLE_SESSION_NAME", "custom-session")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.AWSAssumeRole.ARN != "arn:aws:iam::123456789012:role/centcom-satellite-remote" {
		t.Fatalf("AWSAssumeRole.ARN = %q, want the configured ARN", cfg.AWSAssumeRole.ARN)
	}
	if cfg.AWSAssumeRole.ExternalID != "shared-secret-id" {
		t.Fatalf("AWSAssumeRole.ExternalID = %q, want shared-secret-id", cfg.AWSAssumeRole.ExternalID)
	}
	if cfg.AWSAssumeRole.SessionName != "custom-session" {
		t.Fatalf("AWSAssumeRole.SessionName = %q, want custom-session", cfg.AWSAssumeRole.SessionName)
	}
}

func TestLoad_AWSAssumeRoleARNMustLookLikeIAMRoleARN(t *testing.T) {
	t.Setenv("ALLOW_UNAUTHENTICATED", "true")
	t.Setenv("AWS_ASSUME_ROLE_ARN", "not-an-arn")
	if _, err := Load(); err == nil {
		t.Fatal("expected error for malformed AWS_ASSUME_ROLE_ARN, got nil")
	}
}
