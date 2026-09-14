package guardduty_findings

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/guardduty"
	gdtypes "github.com/aws/aws-sdk-go-v2/service/guardduty/types"
)

type fakeAPI struct {
	listOut   *guardduty.ListFindingsOutput
	listErr   error
	getOut    *guardduty.GetFindingsOutput
	getCalled bool
}

func (f *fakeAPI) ListDetectors(_ context.Context, _ *guardduty.ListDetectorsInput, _ ...func(*guardduty.Options)) (*guardduty.ListDetectorsOutput, error) {
	return &guardduty.ListDetectorsOutput{DetectorIds: []string{"det-1"}}, nil
}

func (f *fakeAPI) ListFindings(_ context.Context, _ *guardduty.ListFindingsInput, _ ...func(*guardduty.Options)) (*guardduty.ListFindingsOutput, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	return f.listOut, nil
}

func (f *fakeAPI) GetFindings(_ context.Context, _ *guardduty.GetFindingsInput, _ ...func(*guardduty.Options)) (*guardduty.GetFindingsOutput, error) {
	f.getCalled = true
	return f.getOut, nil
}

func newTestTask(a api) *Task {
	return NewWithClientFactory(func(_ context.Context, _ string) (api, error) { return a, nil })
}

func TestExecute_ListsThenHydrates(t *testing.T) {
	api := &fakeAPI{
		listOut: &guardduty.ListFindingsOutput{FindingIds: []string{"f1"}, NextToken: aws.String("nt")},
		getOut: &guardduty.GetFindingsOutput{Findings: []gdtypes.Finding{
			{Id: aws.String("f1"), Type: aws.String("t"), Severity: aws.Float64(8)},
		}},
	}
	res, err := newTestTask(api).Execute(context.Background(), json.RawMessage(`{}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.Success {
		t.Fatalf("expected success, got error: %s", res.Error)
	}
	list := res.Details.(FindingList)
	if list.Total != 1 || list.Findings[0].ID != "f1" || list.NextToken != "nt" {
		t.Fatalf("unexpected result: %+v", list)
	}
	if list.Findings[0].SeverityLabel != "High" {
		t.Errorf("severity label = %q", list.Findings[0].SeverityLabel)
	}
}

func TestExecute_NoFindingsSkipsHydration(t *testing.T) {
	api := &fakeAPI{listOut: &guardduty.ListFindingsOutput{FindingIds: nil}}
	res, err := newTestTask(api).Execute(context.Background(), json.RawMessage(`{}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	list := res.Details.(FindingList)
	if list.Total != 0 || list.Findings == nil {
		t.Fatalf("expected empty non-nil findings, got %+v", list)
	}
	if api.getCalled {
		t.Error("GetFindings should not be called when there are no IDs")
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

// TestExecute_AWSErrorSurfacesAsResultNotGoError guards against a corrupted
// or expired NextToken (or any other AWS-rejected input) turning into an
// opaque HTTP 500 ("task execution failed") via HandleTask's generic error
// path. It must come back as a normal unsuccessful Result carrying the real
// AWS error text, so the client actually learns what went wrong.
func TestExecute_AWSErrorSurfacesAsResultNotGoError(t *testing.T) {
	api := &fakeAPI{listErr: errors.New("InvalidInputException: Invalid NextToken")}
	res, err := newTestTask(api).Execute(context.Background(), json.RawMessage(`{"next_token":"corrupted"}`))
	if err != nil {
		t.Fatalf("expected a Result, not a Go error: %v", err)
	}
	if res.Success {
		t.Fatal("expected success=false when AWS rejects the request")
	}
	if !strings.Contains(res.Error, "Invalid NextToken") {
		t.Fatalf("expected the real AWS error to be preserved, got %q", res.Error)
	}
}
