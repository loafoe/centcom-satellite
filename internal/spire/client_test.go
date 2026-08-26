package spire

import (
	"context"
	"strings"
	"testing"
)

func TestClient_HealthCheck_NilClient(t *testing.T) {
	var client *Client
	err := client.HealthCheck(context.Background())
	if err != nil {
		t.Fatalf("expected nil error when client is nil, got %v", err)
	}
}

func TestClient_HealthCheck_NilConfig(t *testing.T) {
	client := &Client{}
	err := client.HealthCheck(context.Background())
	if err != nil {
		t.Fatalf("expected nil error when client config is nil, got %v", err)
	}
}

func TestClient_HealthCheck_Disabled(t *testing.T) {
	cfg := &Config{Enabled: false}
	client := NewClient(cfg)

	err := client.HealthCheck(context.Background())
	if err != nil {
		t.Fatalf("expected nil error when SPIRE is disabled, got %v", err)
	}
}

func TestClient_HealthCheck_Enabled_UninitializedSource(t *testing.T) {
	cfg := &Config{Enabled: true, MTLSEnabled: true}
	client := NewClient(cfg)

	err := client.HealthCheck(context.Background())
	if err == nil {
		t.Fatalf("expected error when MTLS is enabled but source is nil, got nil")
	}
	if !strings.Contains(err.Error(), "SPIRE X509 source not initialized") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestClient_HealthCheck_JWTOnly_SkipsX509Check(t *testing.T) {
	// MTLSEnabled=false, JWT.Enabled=true, jwtSource never initialized.
	// Before this fix, HealthCheck failed on the X.509 source check first,
	// masking what should be a JWT-specific error. After this fix, with
	// MTLS disabled, the X.509 check is skipped entirely and the JWT
	// check's own error surfaces instead.
	cfg := &Config{
		Enabled:     true,
		MTLSEnabled: false,
		JWT:         JWTConfig{Enabled: true},
	}
	client := NewClient(cfg)

	err := client.HealthCheck(context.Background())
	if err == nil {
		t.Fatal("expected error when JWT is enabled but jwtSource is uninitialized")
	}
	if strings.Contains(err.Error(), "X509") {
		t.Errorf("X.509 must not be checked when MTLSEnabled=false, got: %v", err)
	}
	if !strings.Contains(err.Error(), "SPIRE JWT source not initialized") {
		t.Errorf("expected JWT-specific error, got: %v", err)
	}
}

func TestClient_HealthCheck_NeitherMTLSNorJWT_NoOp(t *testing.T) {
	// Enabled=true but nothing configured to check — must not error just
	// because the (unused) X.509 source was never initialized.
	cfg := &Config{Enabled: true}
	client := NewClient(cfg)

	if err := client.HealthCheck(context.Background()); err != nil {
		t.Fatalf("expected nil error when neither MTLS nor JWT is enabled, got: %v", err)
	}
}
