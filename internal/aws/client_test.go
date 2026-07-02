package aws

import (
	"context"
	"testing"
)

func TestLoadConfig_AppliesRegion(t *testing.T) {
	cfg, err := LoadConfig(context.Background(), Options{Region: "eu-west-1"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Region != "eu-west-1" {
		t.Fatalf("region = %q, want eu-west-1", cfg.Region)
	}
}

func TestLoadConfig_EmptyOptionsOK(t *testing.T) {
	if _, err := LoadConfig(context.Background(), Options{}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestHasCredentials_EnvIndicator(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIAEXAMPLE")
	if !HasCredentials() {
		t.Fatal("HasCredentials() = false, want true when AWS_ACCESS_KEY_ID set")
	}
}
