package securityhub_get_findings_statistics

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/securityhub"
	"github.com/aws/aws-sdk-go-v2/service/securityhub/types"
)

type fakeAPI struct {
	pages   [][]types.AwsSecurityFinding
	tokens  []string // NextToken to return after each page; "" means no more pages
	callIdx int
}

func (f *fakeAPI) GetFindings(_ context.Context, in *securityhub.GetFindingsInput, _ ...func(*securityhub.Options)) (*securityhub.GetFindingsOutput, error) {
	idx := f.callIdx
	f.callIdx++
	out := &securityhub.GetFindingsOutput{Findings: f.pages[idx]}
	if idx < len(f.tokens) && f.tokens[idx] != "" {
		out.NextToken = aws.String(f.tokens[idx])
	}
	return out, nil
}

func newTestTask(a api) *Task {
	return NewWithClientFactory(func(_ context.Context, _ string) (api, error) { return a, nil })
}

func sevFinding(label types.SeverityLabel) types.AwsSecurityFinding {
	return types.AwsSecurityFinding{Id: aws.String("f"), ProductArn: aws.String("arn"), Severity: &types.Severity{Label: label}}
}

func TestExecute_AggregatesBySeverityDefault(t *testing.T) {
	api := &fakeAPI{
		pages: [][]types.AwsSecurityFinding{
			{sevFinding(types.SeverityLabelHigh), sevFinding(types.SeverityLabelHigh), sevFinding(types.SeverityLabelLow)},
		},
	}
	res, err := newTestTask(api).Execute(context.Background(), json.RawMessage(`{}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.Success {
		t.Fatalf("expected success, got error: %s", res.Error)
	}
	stats := res.Details.(Statistics)
	if stats.GroupBy != "SEVERITY" {
		t.Errorf("GroupBy = %q, want SEVERITY", stats.GroupBy)
	}
	counts := map[string]int32{}
	for _, c := range stats.Counts {
		counts[c.Key] = c.Count
	}
	if counts["HIGH"] != 2 || counts["LOW"] != 1 {
		t.Errorf("counts = %+v, want HIGH:2 LOW:1", counts)
	}
	if stats.Total != 3 {
		t.Errorf("Total = %d, want 3", stats.Total)
	}
	if stats.Truncated {
		t.Error("expected Truncated=false when all pages consumed")
	}
}

func TestExecute_TruncatesAtPageCap(t *testing.T) {
	pages := make([][]types.AwsSecurityFinding, 11)
	tokens := make([]string, 11)
	for i := range pages {
		pages[i] = []types.AwsSecurityFinding{sevFinding(types.SeverityLabelMedium)}
		tokens[i] = "more" // every page claims there's more
	}
	api := &fakeAPI{pages: pages, tokens: tokens}
	res, _ := newTestTask(api).Execute(context.Background(), json.RawMessage(`{}`))
	stats := res.Details.(Statistics)
	if !stats.Truncated {
		t.Error("expected Truncated=true when page cap is hit with more pages remaining")
	}
	if stats.NextToken == "" {
		t.Error("expected NextToken to be set when truncated")
	}
	if stats.Total != 10 {
		t.Errorf("Total = %d, want 10 (10 pages x 1 finding, capped)", stats.Total)
	}
}

func TestExecute_UnsupportedGroupBy(t *testing.T) {
	res, err := newTestTask(&fakeAPI{}).Execute(context.Background(), json.RawMessage(`{"group_by":"BOGUS"}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
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
