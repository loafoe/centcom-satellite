package securityhub_list_standards

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/securityhub"
	"github.com/aws/aws-sdk-go-v2/service/securityhub/types"
)

type fakeAPI struct {
	describeHubOut       *securityhub.DescribeHubOutput
	describeStandardsOut *securityhub.DescribeStandardsOutput
	enabledStandardsOut  *securityhub.GetEnabledStandardsOutput
}

func (f *fakeAPI) DescribeHub(_ context.Context, _ *securityhub.DescribeHubInput, _ ...func(*securityhub.Options)) (*securityhub.DescribeHubOutput, error) {
	return f.describeHubOut, nil
}

func (f *fakeAPI) DescribeStandards(_ context.Context, _ *securityhub.DescribeStandardsInput, _ ...func(*securityhub.Options)) (*securityhub.DescribeStandardsOutput, error) {
	return f.describeStandardsOut, nil
}

func (f *fakeAPI) GetEnabledStandards(_ context.Context, _ *securityhub.GetEnabledStandardsInput, _ ...func(*securityhub.Options)) (*securityhub.GetEnabledStandardsOutput, error) {
	return f.enabledStandardsOut, nil
}

func newTestTask(a api) *Task {
	return NewWithClientFactory(func(_ context.Context, _ string) (api, error) { return a, nil })
}

func TestExecute_JoinsCatalogWithSubscriptions(t *testing.T) {
	api := &fakeAPI{
		describeHubOut: &securityhub.DescribeHubOutput{
			HubArn:                  aws.String("arn:aws:securityhub:us-east-1:123456789012:hub/default"),
			SubscribedAt:            aws.String("2026-01-01T00:00:00Z"),
			AutoEnableControls:      aws.Bool(true),
			ControlFindingGenerator: types.ControlFindingGeneratorSecurityControl,
		},
		describeStandardsOut: &securityhub.DescribeStandardsOutput{
			Standards: []types.Standard{
				{StandardsArn: aws.String("arn:std/cis"), Name: aws.String("CIS"), EnabledByDefault: aws.Bool(false)},
				{StandardsArn: aws.String("arn:std/fsbp"), Name: aws.String("FSBP"), EnabledByDefault: aws.Bool(true)},
			},
		},
		enabledStandardsOut: &securityhub.GetEnabledStandardsOutput{
			StandardsSubscriptions: []types.StandardsSubscription{
				{StandardsArn: aws.String("arn:std/fsbp"), StandardsStatus: types.StandardsStatusReady},
			},
		},
	}

	res, err := newTestTask(api).Execute(context.Background(), json.RawMessage(`{}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.Success {
		t.Fatalf("expected success, got error: %s", res.Error)
	}
	list := res.Details.(StandardsList)
	if list.Hub.HubArn != "arn:aws:securityhub:us-east-1:123456789012:hub/default" {
		t.Errorf("Hub.HubArn = %q", list.Hub.HubArn)
	}
	if list.Total != 2 {
		t.Fatalf("Total = %d, want 2", list.Total)
	}
	byArn := map[string]string{}
	for _, s := range list.Standards {
		byArn[s.StandardsArn] = s.Status
	}
	if byArn["arn:std/fsbp"] != "READY" {
		t.Errorf("fsbp status = %q, want READY", byArn["arn:std/fsbp"])
	}
	if byArn["arn:std/cis"] != "" {
		t.Errorf("cis status = %q, want empty (not subscribed)", byArn["arn:std/cis"])
	}
}

func TestExecute_InvalidPayload(t *testing.T) {
	res, err := newTestTask(&fakeAPI{}).Execute(context.Background(), json.RawMessage(`{`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Success {
		t.Fatal("expected success=false for invalid payload")
	}
}
