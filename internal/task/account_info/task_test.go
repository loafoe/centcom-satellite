package account_info

import (
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
