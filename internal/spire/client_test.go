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
	cfg := &Config{Enabled: true}
	client := NewClient(cfg)

	err := client.HealthCheck(context.Background())
	if err == nil {
		t.Fatalf("expected error when SPIRE is enabled but source is nil, got nil")
	}
	if !strings.Contains(err.Error(), "SPIRE X509 source not initialized") {
		t.Errorf("unexpected error message: %v", err)
	}
}
