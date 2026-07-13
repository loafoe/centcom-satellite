package guardduty_get_findings

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/guardduty"
	gdtypes "github.com/aws/aws-sdk-go-v2/service/guardduty/types"
)

type fakeAPI struct {
	getOut *guardduty.GetFindingsOutput
	lastIn *guardduty.GetFindingsInput
}

func (f *fakeAPI) ListDetectors(_ context.Context, _ *guardduty.ListDetectorsInput, _ ...func(*guardduty.Options)) (*guardduty.ListDetectorsOutput, error) {
	return &guardduty.ListDetectorsOutput{DetectorIds: []string{"det-auto"}}, nil
}

func (f *fakeAPI) GetFindings(_ context.Context, in *guardduty.GetFindingsInput, _ ...func(*guardduty.Options)) (*guardduty.GetFindingsOutput, error) {
	f.lastIn = in
	return f.getOut, nil
}

func newTestTask(a api) *Task {
	return NewWithClientFactory(func(_ context.Context, _ string) (api, error) { return a, nil })
}

func TestExecute_HydratesFindings(t *testing.T) {
	api := &fakeAPI{getOut: &guardduty.GetFindingsOutput{Findings: []gdtypes.Finding{
		{Id: aws.String("f1"), Type: aws.String("t1"), Severity: aws.Float64(8.0)},
	}}}
	res, err := newTestTask(api).Execute(context.Background(), json.RawMessage(`{"finding_ids":["f1"]}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.Success {
		t.Fatalf("expected success, got error: %s", res.Error)
	}
	list := res.Details.(FindingList)
	if list.DetectorID != "det-auto" || list.Total != 1 || list.Findings[0].SeverityLabel != "High" {
		t.Fatalf("unexpected result: %+v", list)
	}
	if len(api.lastIn.FindingIds) != 1 || api.lastIn.FindingIds[0] != "f1" {
		t.Errorf("finding ids passed through wrong: %v", api.lastIn.FindingIds)
	}
}

func TestExecute_RequiresFindingIDs(t *testing.T) {
	res, _ := newTestTask(&fakeAPI{}).Execute(context.Background(), json.RawMessage(`{}`))
	if res.Success {
		t.Fatal("expected failure when finding_ids omitted")
	}
}

func TestExecute_RejectsTooMany(t *testing.T) {
	ids := make([]string, 51)
	for i := range ids {
		ids[i] = "x"
	}
	payload, _ := json.Marshal(Payload{FindingIDs: ids})
	res, _ := newTestTask(&fakeAPI{}).Execute(context.Background(), payload)
	if res.Success {
		t.Fatal("expected failure for >50 finding ids")
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
