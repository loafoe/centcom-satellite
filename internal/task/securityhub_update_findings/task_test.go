package securityhub_update_findings

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/securityhub"
	"github.com/aws/aws-sdk-go-v2/service/securityhub/types"
)

type fakeAPI struct {
	lastInput *securityhub.BatchUpdateFindingsInput
	out       *securityhub.BatchUpdateFindingsOutput
}

func (f *fakeAPI) BatchUpdateFindings(_ context.Context, in *securityhub.BatchUpdateFindingsInput, _ ...func(*securityhub.Options)) (*securityhub.BatchUpdateFindingsOutput, error) {
	f.lastInput = in
	return f.out, nil
}

func newTestTask(a api) *Task {
	return NewWithClientFactory(func(_ context.Context, _ string) (api, error) { return a, nil })
}

func TestExecute_SetsWorkflowStatusAndNote(t *testing.T) {
	api := &fakeAPI{
		out: &securityhub.BatchUpdateFindingsOutput{
			ProcessedFindings: []types.AwsSecurityFindingIdentifier{
				{Id: aws.String("f1"), ProductArn: aws.String("arn:p1")},
			},
		},
	}
	payload := `{
		"findings": [{"id":"f1","product_arn":"arn:p1"}],
		"workflow_status": "RESOLVED",
		"note": "fixed via automation",
		"note_updated_by": "centcom-satellite"
	}`
	res, err := newTestTask(api).Execute(context.Background(), json.RawMessage(payload))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.Success {
		t.Fatalf("expected success, got error: %s", res.Error)
	}
	if api.lastInput.Workflow == nil || api.lastInput.Workflow.Status != types.WorkflowStatusResolved {
		t.Errorf("Workflow = %+v, want status RESOLVED", api.lastInput.Workflow)
	}
	if api.lastInput.Note == nil || aws.ToString(api.lastInput.Note.Text) != "fixed via automation" {
		t.Errorf("Note = %+v", api.lastInput.Note)
	}
	if aws.ToString(api.lastInput.Note.UpdatedBy) != "centcom-satellite" {
		t.Errorf("Note.UpdatedBy = %q", aws.ToString(api.lastInput.Note.UpdatedBy))
	}
	if len(api.lastInput.FindingIdentifiers) != 1 || aws.ToString(api.lastInput.FindingIdentifiers[0].Id) != "f1" {
		t.Errorf("FindingIdentifiers = %+v", api.lastInput.FindingIdentifiers)
	}

	result := res.Details.(UpdateResult)
	if len(result.Processed) != 1 || result.Processed[0].ID != "f1" {
		t.Errorf("Processed = %+v", result.Processed)
	}
}

func TestExecute_SurfacesUnprocessedFindings(t *testing.T) {
	api := &fakeAPI{
		out: &securityhub.BatchUpdateFindingsOutput{
			UnprocessedFindings: []types.BatchUpdateFindingsUnprocessedFinding{
				{
					FindingIdentifier: &types.AwsSecurityFindingIdentifier{Id: aws.String("f2"), ProductArn: aws.String("arn:p2")},
					ErrorCode:         aws.String("INVALID_INPUT"),
					ErrorMessage:      aws.String("bad finding"),
				},
			},
		},
	}
	payload := `{"findings":[{"id":"f2","product_arn":"arn:p2"}],"workflow_status":"NOTIFIED"}`
	res, err := newTestTask(api).Execute(context.Background(), json.RawMessage(payload))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	result := res.Details.(UpdateResult)
	if len(result.Unprocessed) != 1 || result.Unprocessed[0].ErrorCode != "INVALID_INPUT" {
		t.Errorf("Unprocessed = %+v", result.Unprocessed)
	}
}

func TestExecute_RejectsMoreThan100Findings(t *testing.T) {
	refs := make([]map[string]string, 101)
	for i := range refs {
		refs[i] = map[string]string{"id": "f", "product_arn": "arn:p"}
	}
	body, _ := json.Marshal(map[string]any{"findings": refs, "workflow_status": "NEW"})
	res, err := newTestTask(&fakeAPI{}).Execute(context.Background(), body)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Success {
		t.Fatal("expected failure for >100 findings")
	}
	if !strings.Contains(res.Error, "100") {
		t.Errorf("error = %q, want it to mention the 100-item limit", res.Error)
	}
}

func TestExecute_RejectsEmptyFindings(t *testing.T) {
	res, err := newTestTask(&fakeAPI{}).Execute(context.Background(), json.RawMessage(`{"workflow_status":"NEW"}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Success {
		t.Fatal("expected failure for empty findings list")
	}
}

func TestExecute_RejectsNeitherWorkflowStatusNorNote(t *testing.T) {
	payload := `{"findings":[{"id":"f1","product_arn":"arn:p1"}]}`
	res, err := newTestTask(&fakeAPI{}).Execute(context.Background(), json.RawMessage(payload))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Success {
		t.Fatal("expected failure when neither workflow_status nor note is set")
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
