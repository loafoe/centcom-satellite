package account_info

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"github.com/loafoe/centcom-satellite/internal/task/cluster_info"
)

type fakeAPI struct {
	out *sts.GetCallerIdentityOutput
	err error
}

func (f *fakeAPI) GetCallerIdentity(_ context.Context, _ *sts.GetCallerIdentityInput, _ ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
	return f.out, f.err
}

func newTestTask(assumeRoleARN string, a api) *Task {
	return NewWithClientFactory(assumeRoleARN, func(_ context.Context) (api, string, error) {
		return a, "eu-west-1", nil
	})
}

func TestExecute_ReturnsAssumedRoleAccount(t *testing.T) {
	// This is the core requirement: when AssumeRole is configured, the
	// account reported must be the one resolved by the (already
	// assumed-role-aware) client factory, not some other local account.
	api := &fakeAPI{out: &sts.GetCallerIdentityOutput{
		Account: aws.String("009160061746"),
		Arn:     aws.String("arn:aws:sts::009160061746:assumed-role/centcom-satellite-dip-ce-k3s-eu/centcom-satellite-obs-ct"),
	}}
	res, err := newTestTask("arn:aws:iam::009160061746:role/centcom-satellite-dip-ce-k3s-eu", api).Execute(context.Background(), json.RawMessage(`{}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.Success {
		t.Fatalf("expected success, got error: %s", res.Error)
	}
	info := res.Details.(Info)
	if info.AWSAccountID != "009160061746" {
		t.Errorf("AWSAccountID = %q, want 009160061746", info.AWSAccountID)
	}
	if info.AssumeRoleARN != "arn:aws:iam::009160061746:role/centcom-satellite-dip-ce-k3s-eu" {
		t.Errorf("AssumeRoleARN = %q, want the configured role ARN", info.AssumeRoleARN)
	}
	if info.Region != "eu-west-1" {
		t.Errorf("Region = %q, want eu-west-1", info.Region)
	}
}

func TestExecute_NoAssumeRoleConfigured(t *testing.T) {
	api := &fakeAPI{out: &sts.GetCallerIdentityOutput{Account: aws.String("010526241823")}}
	res, err := newTestTask("", api).Execute(context.Background(), json.RawMessage(`{}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	info := res.Details.(Info)
	if info.AWSAccountID != "010526241823" {
		t.Errorf("AWSAccountID = %q, want 010526241823", info.AWSAccountID)
	}
	if info.AssumeRoleARN != "" {
		t.Errorf("AssumeRoleARN = %q, want empty when AssumeRole isn't configured", info.AssumeRoleARN)
	}
}

func TestExecute_PropagatesSTSError(t *testing.T) {
	api := &fakeAPI{err: errors.New("access denied")}
	_, err := newTestTask("", api).Execute(context.Background(), json.RawMessage(`{}`))
	if err == nil {
		t.Fatal("expected error to propagate, got nil")
	}
}

func TestExecute_ReportsCapabilities(t *testing.T) {
	// Capabilities must flow through even without a Kubernetes client —
	// this is the only capabilities source on a cluster-less satellite,
	// where cluster_info isn't registered at all.
	api := &fakeAPI{out: &sts.GetCallerIdentityOutput{Account: aws.String("009160061746")}}
	tsk := newTestTask("", api).WithCapabilities(cluster_info.Capabilities{
		SecurityHub: true,
		GuardDuty:   true,
	})
	res, err := tsk.Execute(context.Background(), json.RawMessage(`{}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	info := res.Details.(Info)
	if !info.Capabilities.SecurityHub {
		t.Error("expected Capabilities.SecurityHub = true")
	}
	if !info.Capabilities.GuardDuty {
		t.Error("expected Capabilities.GuardDuty = true")
	}
	if info.Capabilities.CloudWatchRCA {
		t.Error("expected Capabilities.CloudWatchRCA = false (not set)")
	}
}

func TestExecute_AvailablePathLeavesAWSAvailableNil(t *testing.T) {
	// A response from the AWS-available path must stay byte-for-byte what
	// an older centcom expects: no aws_available field in the JSON at all
	// (a nil *bool serializes as omitted, not false), so this is a
	// regression guard against accidentally always setting it.
	api := &fakeAPI{out: &sts.GetCallerIdentityOutput{Account: aws.String("010526241823")}}
	res, err := newTestTask("", api).Execute(context.Background(), json.RawMessage(`{}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	info := res.Details.(Info)
	if info.AWSAvailable != nil {
		t.Errorf("AWSAvailable = %v, want nil on the AWS-available path", *info.AWSAvailable)
	}
	raw, err := json.Marshal(info)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if bytes.Contains(raw, []byte("aws_available")) {
		t.Errorf("expected no aws_available key in JSON, got %s", raw)
	}
}

func TestExecute_Unavailable(t *testing.T) {
	// NewUnavailable must never touch the AWS API at all - clientFactory is
	// left nil, so a regression that fell through to the normal path would
	// nil-pointer panic here rather than silently calling AWS.
	tsk := NewUnavailable("no AWS credentials detected on this satellite").WithCapabilities(cluster_info.Capabilities{
		HttpRequest: true,
	})
	res, err := tsk.Execute(context.Background(), json.RawMessage(`{}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.Success {
		t.Fatalf("expected success, got error: %s", res.Error)
	}
	info := res.Details.(Info)
	if info.AWSAvailable == nil || *info.AWSAvailable {
		t.Errorf("AWSAvailable = %v, want a pointer to false", info.AWSAvailable)
	}
	if info.Reason != "no AWS credentials detected on this satellite" {
		t.Errorf("Reason = %q, want the configured reason", info.Reason)
	}
	if info.AWSAccountID != "" || info.AWSCallerArn != "" || info.Region != "" {
		t.Errorf("expected no AWS identity fields set, got %+v", info)
	}
	if !info.Capabilities.HttpRequest {
		t.Error("expected Capabilities.HttpRequest = true to still flow through when AWS is unavailable")
	}

	raw, err := json.Marshal(info)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !bytes.Contains(raw, []byte(`"aws_available":false`)) {
		t.Errorf("expected aws_available:false in JSON, got %s", raw)
	}
}
