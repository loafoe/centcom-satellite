package aws

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
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

// fakeCredentialsProvider lets tests assert LoadConfig wired in a specific
// shared provider instance, without making any real AWS/network call.
type fakeCredentialsProvider struct{}

func (f *fakeCredentialsProvider) Retrieve(_ context.Context) (aws.Credentials, error) {
	return aws.Credentials{AccessKeyID: "fake"}, nil
}

func TestLoadConfig_UsesSharedAssumeRoleCredentialsWhenConfigured(t *testing.T) {
	fake := &fakeCredentialsProvider{}
	prev := assumeRoleCredentials
	assumeRoleCredentials = fake
	defer func() { assumeRoleCredentials = prev }()

	cfg, err := LoadConfig(context.Background(), Options{Region: "eu-west-1"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Credentials != fake {
		t.Fatalf("cfg.Credentials = %v, want the shared fake provider", cfg.Credentials)
	}
}

func TestLoadConfig_RepeatedCallsReuseSameCredentialsInstance(t *testing.T) {
	fake := &fakeCredentialsProvider{}
	prev := assumeRoleCredentials
	assumeRoleCredentials = fake
	defer func() { assumeRoleCredentials = prev }()

	cfg1, _ := LoadConfig(context.Background(), Options{Region: "eu-west-1"})
	cfg2, _ := LoadConfig(context.Background(), Options{Region: "us-east-1"})
	if cfg1.Credentials != cfg2.Credentials {
		t.Fatal("expected both LoadConfig calls to reuse the identical cached credentials instance, not build a new one per call")
	}
}

func TestLoadConfig_UsesAssumeRoleRegionWhenNoPerCallOverride(t *testing.T) {
	fake := &fakeCredentialsProvider{}
	prevCreds, prevRegion := assumeRoleCredentials, assumeRoleRegion
	assumeRoleCredentials = fake
	assumeRoleRegion = "us-east-1"
	defer func() { assumeRoleCredentials, assumeRoleRegion = prevCreds, prevRegion }()

	cfg, err := LoadConfig(context.Background(), Options{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Region != "us-east-1" {
		t.Fatalf("region = %q, want us-east-1 (the AssumeRole region default)", cfg.Region)
	}
}

func TestLoadConfig_PerCallRegionOverridesAssumeRoleRegion(t *testing.T) {
	fake := &fakeCredentialsProvider{}
	prevCreds, prevRegion := assumeRoleCredentials, assumeRoleRegion
	assumeRoleCredentials = fake
	assumeRoleRegion = "us-east-1"
	defer func() { assumeRoleCredentials, assumeRoleRegion = prevCreds, prevRegion }()

	cfg, err := LoadConfig(context.Background(), Options{Region: "eu-west-2"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Region != "eu-west-2" {
		t.Fatalf("region = %q, want eu-west-2 (explicit per-call Region must win)", cfg.Region)
	}
}

func TestLoadConfig_AssumeRoleRegionHasNoEffectOutsideAssumeRoleMode(t *testing.T) {
	// assumeRoleRegion must never apply when AssumeRole isn't configured
	// (assumeRoleCredentials nil) — this is the "only for cluster-less
	// mode" requirement: without it, a stray assumeRoleRegion value could
	// leak into the base-account code path. Pins the ambient region
	// explicitly via env var (rather than assuming it's unset) since the
	// SDK also consults ~/.aws/config, which varies by machine.
	t.Setenv("AWS_REGION", "ap-southeast-2")
	prevCreds, prevRegion := assumeRoleCredentials, assumeRoleRegion
	assumeRoleCredentials = nil
	assumeRoleRegion = "us-east-1"
	defer func() { assumeRoleCredentials, assumeRoleRegion = prevCreds, prevRegion }()

	cfg, err := LoadConfig(context.Background(), Options{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Region != "ap-southeast-2" {
		t.Fatalf("region = %q, want ap-southeast-2 (ambient) — assumeRoleRegion must not apply when assumeRoleCredentials is nil", cfg.Region)
	}
}

func TestInit_NoopWhenARNEmpty(t *testing.T) {
	prev := assumeRoleCredentials
	defer func() { assumeRoleCredentials = prev }()
	assumeRoleCredentials = nil

	if err := Init(context.Background(), AssumeRoleOptions{}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if assumeRoleCredentials != nil {
		t.Fatal("expected assumeRoleCredentials to remain nil when ARN is empty (no-op, no network call)")
	}
}

type fakeSTSAPI struct {
	out *sts.GetCallerIdentityOutput
	err error
}

func (f *fakeSTSAPI) GetCallerIdentity(_ context.Context, _ *sts.GetCallerIdentityInput, _ ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
	return f.out, f.err
}

func TestVerifyCallerIdentity_ReturnsAccountID(t *testing.T) {
	api := &fakeSTSAPI{out: &sts.GetCallerIdentityOutput{Account: aws.String("999999999999")}}
	accountID, err := verifyCallerIdentity(context.Background(), api)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if accountID != "999999999999" {
		t.Fatalf("accountID = %q, want 999999999999", accountID)
	}
}

func TestVerifyCallerIdentity_PropagatesError(t *testing.T) {
	api := &fakeSTSAPI{err: errors.New("access denied")}
	if _, err := verifyCallerIdentity(context.Background(), api); err == nil {
		t.Fatal("expected error to propagate, got nil")
	}
}
