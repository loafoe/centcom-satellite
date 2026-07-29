package securityhub_get_findings

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/securityhub"
	"github.com/aws/aws-sdk-go-v2/service/securityhub/types"
)

type fakeAPI struct {
	lastInput      *securityhub.GetFindingsInput
	getFindingsOut *securityhub.GetFindingsOutput
}

func (f *fakeAPI) GetFindings(_ context.Context, in *securityhub.GetFindingsInput, _ ...func(*securityhub.Options)) (*securityhub.GetFindingsOutput, error) {
	f.lastInput = in
	return f.getFindingsOut, nil
}

func newTestTask(a api) *Task {
	return NewWithClientFactory(func(_ context.Context, _ string) (api, string, error) { return a, "eu-west-1", nil })
}

func TestExecute_ReturnsNormalizedFindings(t *testing.T) {
	api := &fakeAPI{
		getFindingsOut: &securityhub.GetFindingsOutput{
			Findings: []types.AwsSecurityFinding{
				{Id: aws.String("f1"), ProductArn: aws.String("arn:p1"), Severity: &types.Severity{Label: types.SeverityLabelHigh}},
				{Id: aws.String("f2"), ProductArn: aws.String("arn:p1"), Severity: &types.Severity{Label: types.SeverityLabelLow}},
			},
			NextToken: aws.String("nt"),
		},
	}
	res, err := newTestTask(api).Execute(context.Background(), json.RawMessage(`{"filter":{"severity_labels":["HIGH"]}}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.Success {
		t.Fatalf("expected success, got error: %s", res.Error)
	}
	list := res.Details.(FindingList)
	if list.Total != 2 || list.NextToken != "nt" {
		t.Fatalf("unexpected result: %+v", list)
	}
	if len(api.lastInput.Filters.SeverityLabel) != 1 {
		t.Errorf("expected severity_labels to be translated into Filters, got %+v", api.lastInput.Filters)
	}
	if aws.ToInt32(api.lastInput.MaxResults) != 100 {
		t.Errorf("MaxResults = %d, want default 100", aws.ToInt32(api.lastInput.MaxResults))
	}
}

func TestExecute_MaxResultsClampedToUpperBound(t *testing.T) {
	api := &fakeAPI{getFindingsOut: &securityhub.GetFindingsOutput{}}
	_, _ = newTestTask(api).Execute(context.Background(), json.RawMessage(`{"max_results":500}`))
	if aws.ToInt32(api.lastInput.MaxResults) != 100 {
		t.Errorf("MaxResults = %d, want clamped to 100", aws.ToInt32(api.lastInput.MaxResults))
	}
}

func TestExecute_NextTokenPassedThrough(t *testing.T) {
	api := &fakeAPI{getFindingsOut: &securityhub.GetFindingsOutput{}}
	_, _ = newTestTask(api).Execute(context.Background(), json.RawMessage(`{"next_token":"page2"}`))
	if aws.ToString(api.lastInput.NextToken) != "page2" {
		t.Errorf("NextToken = %q, want page2", aws.ToString(api.lastInput.NextToken))
	}
}

func TestExecute_EmptyResultsAreNonNil(t *testing.T) {
	api := &fakeAPI{getFindingsOut: &securityhub.GetFindingsOutput{Findings: nil}}
	res, _ := newTestTask(api).Execute(context.Background(), json.RawMessage(`{}`))
	list := res.Details.(FindingList)
	if list.Findings == nil {
		t.Fatal("expected non-nil findings slice")
	}
}

// TestExecute_ConstrainsToResolvedRegion verifies the region the client
// factory resolved to (not the raw payload.Region, which may be empty and
// fall back to AWS_REGION) is applied as a Region filter — required because
// Security Hub cross-region finding aggregators can otherwise return
// findings from every linked region, not just the one this satellite runs
// in. See securityhub_common.Filter.Region's doc comment.
func TestExecute_ConstrainsToResolvedRegion(t *testing.T) {
	api := &fakeAPI{getFindingsOut: &securityhub.GetFindingsOutput{}}
	_, _ = newTestTask(api).Execute(context.Background(), json.RawMessage(`{}`))
	if len(api.lastInput.Filters.Region) != 1 || aws.ToString(api.lastInput.Filters.Region[0].Value) != "eu-west-1" {
		t.Errorf("Region filter = %+v, want [eu-west-1]", api.lastInput.Filters.Region)
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
