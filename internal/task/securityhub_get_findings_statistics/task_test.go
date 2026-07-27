package securityhub_get_findings_statistics

import (
	"context"
	"encoding/json"
	"testing"
	"time"

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

// noSleep is the test seam for the inter-page delay: tests exercise many
// pages and must not actually wait interPageDelay between each one.
func noSleep(context.Context, time.Duration) {}

func newTestTask(a api) *Task {
	return NewWithClientFactoryAndSleep(func(_ context.Context, _ string) (api, error) { return a, nil }, noSleep)
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
}

// TestExecute_PaginatesExhaustivelyPastFormerCap verifies statistics counts
// every finding across many pages with no upper bound — the whole point of
// removing the old maxPages cap. 15 pages exceeds the former 10-page limit;
// every finding across all of them must be counted.
func TestExecute_PaginatesExhaustivelyPastFormerCap(t *testing.T) {
	const pages = 15
	fakePages := make([][]types.AwsSecurityFinding, pages)
	tokens := make([]string, pages)
	for i := range fakePages {
		fakePages[i] = []types.AwsSecurityFinding{sevFinding(types.SeverityLabelMedium)}
		if i < pages-1 {
			tokens[i] = "more"
		}
	}
	api := &fakeAPI{pages: fakePages, tokens: tokens}
	res, err := newTestTask(api).Execute(context.Background(), json.RawMessage(`{}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	stats := res.Details.(Statistics)
	if stats.Total != int32(pages) {
		t.Errorf("Total = %d, want %d (no cap should truncate this)", stats.Total, pages)
	}
	if api.callIdx != pages {
		t.Errorf("GetFindings called %d times, want %d (one per page, no early cutoff)", api.callIdx, pages)
	}
}

// TestExecute_SleepsBetweenPagesButNotBeforeFirst verifies the inter-page
// delay is invoked once per page transition (pages-1 times for N pages),
// not before the first request — pacing exists to protect against
// back-to-back throttling across a scan, not to slow down a single call.
func TestExecute_SleepsBetweenPagesButNotBeforeFirst(t *testing.T) {
	fake := &fakeAPI{
		pages: [][]types.AwsSecurityFinding{
			{sevFinding(types.SeverityLabelHigh)},
			{sevFinding(types.SeverityLabelHigh)},
			{sevFinding(types.SeverityLabelHigh)},
		},
		tokens: []string{"p2", "p3", ""},
	}
	var sleepCalls int
	task := NewWithClientFactoryAndSleep(func(_ context.Context, _ string) (api, error) { return fake, nil }, func(context.Context, time.Duration) {
		sleepCalls++
	})
	_, err := task.Execute(context.Background(), json.RawMessage(`{}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sleepCalls != 2 {
		t.Errorf("sleep called %d times for 3 pages, want 2 (between pages, not before the first)", sleepCalls)
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

// TestExecute_ContextCancelledDuringPagination verifies a cancelled context
// aborts the scan promptly rather than sitting through the remainder of a
// long scan's inter-page delays.
func TestExecute_ContextCancelledDuringPagination(t *testing.T) {
	fake := &fakeAPI{
		pages: [][]types.AwsSecurityFinding{
			{sevFinding(types.SeverityLabelHigh)},
			{sevFinding(types.SeverityLabelHigh)},
		},
		tokens: []string{"more", ""},
	}
	ctx, cancel := context.WithCancel(context.Background())
	task := NewWithClientFactoryAndSleep(func(_ context.Context, _ string) (api, error) { return fake, nil }, func(context.Context, time.Duration) {
		cancel() // simulate cancellation arriving during the inter-page wait
	})
	_, err := task.Execute(ctx, json.RawMessage(`{}`))
	if err == nil {
		t.Fatal("expected an error when context is cancelled mid-scan")
	}
}
