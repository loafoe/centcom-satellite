package guardduty_list_findings

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/guardduty"
)

type fakeAPI struct {
	listDetectorsOut *guardduty.ListDetectorsOutput
	lastInput        *guardduty.ListFindingsInput
	listFindingsOut  *guardduty.ListFindingsOutput
}

func (f *fakeAPI) ListDetectors(_ context.Context, _ *guardduty.ListDetectorsInput, _ ...func(*guardduty.Options)) (*guardduty.ListDetectorsOutput, error) {
	return f.listDetectorsOut, nil
}

func (f *fakeAPI) ListFindings(_ context.Context, in *guardduty.ListFindingsInput, _ ...func(*guardduty.Options)) (*guardduty.ListFindingsOutput, error) {
	f.lastInput = in
	return f.listFindingsOut, nil
}

func newTestTask(a api) *Task {
	return NewWithClientFactory(func(_ context.Context, _ string) (api, error) { return a, nil })
}

func TestExecute_ResolvesDetectorAndReturnsIDs(t *testing.T) {
	api := &fakeAPI{
		listDetectorsOut: &guardduty.ListDetectorsOutput{DetectorIds: []string{"det-x"}},
		listFindingsOut:  &guardduty.ListFindingsOutput{FindingIds: []string{"a", "b"}, NextToken: aws.String("nt")},
	}
	res, err := newTestTask(api).Execute(context.Background(), json.RawMessage(`{"filter":{"min_severity":7}}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.Success {
		t.Fatalf("expected success, got error: %s", res.Error)
	}
	list := res.Details.(FindingIDList)
	if list.DetectorID != "det-x" || list.Total != 2 || list.NextToken != "nt" {
		t.Fatalf("unexpected result: %+v", list)
	}
	// The filter must have been translated into FindingCriteria.
	if api.lastInput.FindingCriteria == nil || api.lastInput.FindingCriteria.Criterion["severity"].GreaterThanOrEqual == nil {
		t.Errorf("expected severity criterion, got %+v", api.lastInput.FindingCriteria)
	}
	if aws.ToString(api.lastInput.DetectorId) != "det-x" {
		t.Errorf("detector id = %q", aws.ToString(api.lastInput.DetectorId))
	}
}

func TestExecute_NoDetector(t *testing.T) {
	api := &fakeAPI{listDetectorsOut: &guardduty.ListDetectorsOutput{}}
	res, err := newTestTask(api).Execute(context.Background(), json.RawMessage(`{}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Success {
		t.Fatal("expected failure when no detector present")
	}
}

func TestExecute_EmptyResultsAreNonNil(t *testing.T) {
	api := &fakeAPI{
		listDetectorsOut: &guardduty.ListDetectorsOutput{DetectorIds: []string{"det-x"}},
		listFindingsOut:  &guardduty.ListFindingsOutput{FindingIds: nil},
	}
	res, _ := newTestTask(api).Execute(context.Background(), json.RawMessage(`{}`))
	list := res.Details.(FindingIDList)
	if list.FindingIDs == nil {
		t.Fatal("expected non-nil finding_ids slice")
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
