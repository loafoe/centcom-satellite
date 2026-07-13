package guardduty_get_findings_statistics

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/guardduty"
	gdtypes "github.com/aws/aws-sdk-go-v2/service/guardduty/types"
)

type fakeAPI struct {
	lastIn *guardduty.GetFindingsStatisticsInput
	out    *guardduty.GetFindingsStatisticsOutput
}

func (f *fakeAPI) ListDetectors(_ context.Context, _ *guardduty.ListDetectorsInput, _ ...func(*guardduty.Options)) (*guardduty.ListDetectorsOutput, error) {
	return &guardduty.ListDetectorsOutput{DetectorIds: []string{"det-1"}}, nil
}

func (f *fakeAPI) GetFindingsStatistics(_ context.Context, in *guardduty.GetFindingsStatisticsInput, _ ...func(*guardduty.Options)) (*guardduty.GetFindingsStatisticsOutput, error) {
	f.lastIn = in
	return f.out, nil
}

func newTestTask(a api) *Task {
	return NewWithClientFactory(func(_ context.Context, _ string) (api, error) { return a, nil })
}

func TestExecute_SeverityBuckets(t *testing.T) {
	api := &fakeAPI{out: &guardduty.GetFindingsStatisticsOutput{
		FindingStatistics: &gdtypes.FindingStatistics{
			GroupedBySeverity: []gdtypes.SeverityStatistics{
				{Severity: aws.Float64(8), TotalFindings: aws.Int32(4)},
				{Severity: aws.Float64(5), TotalFindings: aws.Int32(2)},
			},
		},
	}}
	res, err := newTestTask(api).Execute(context.Background(), json.RawMessage(`{}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.Success {
		t.Fatalf("expected success, got error: %s", res.Error)
	}
	stats := res.Details.(Statistics)
	if stats.GroupBy != "SEVERITY" || stats.Total != 6 || len(stats.Counts) != 2 {
		t.Fatalf("unexpected stats: %+v", stats)
	}
	if stats.Counts[0].Key != "8" || stats.Counts[0].Count != 4 {
		t.Errorf("bucket0 = %+v", stats.Counts[0])
	}
	// Default group_by must have been sent as SEVERITY.
	if string(api.lastIn.GroupBy) != "SEVERITY" {
		t.Errorf("group_by = %q, want SEVERITY", api.lastIn.GroupBy)
	}
}

func TestExecute_FindingTypeBuckets(t *testing.T) {
	api := &fakeAPI{out: &guardduty.GetFindingsStatisticsOutput{
		FindingStatistics: &gdtypes.FindingStatistics{
			GroupedByFindingType: []gdtypes.FindingTypeStatistics{
				{FindingType: aws.String("Recon:EC2/Portscan"), TotalFindings: aws.Int32(3)},
			},
		},
	}}
	res, _ := newTestTask(api).Execute(context.Background(), json.RawMessage(`{"group_by":"FINDING_TYPE"}`))
	stats := res.Details.(Statistics)
	if len(stats.Counts) != 1 || stats.Counts[0].Key != "Recon:EC2/Portscan" || stats.Counts[0].Count != 3 {
		t.Fatalf("unexpected buckets: %+v", stats.Counts)
	}
}

func TestExecute_RejectsBadGroupBy(t *testing.T) {
	res, _ := newTestTask(&fakeAPI{}).Execute(context.Background(), json.RawMessage(`{"group_by":"BOGUS"}`))
	if res.Success {
		t.Fatal("expected failure for unsupported group_by")
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
