package securityhub_get_findings_statistics

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/securityhub"
	"github.com/aws/aws-sdk-go-v2/service/securityhub/types"

	shc "github.com/loafoe/centcom-satellite/internal/task/securityhub_common"
)

// bucketFakeAPI serves the SEVERITY/WORKFLOW_STATUS capped per-bucket calls:
// it inspects the incoming filter's SeverityLabel/WorkflowStatus equals-value
// and returns however many findings + whether to signal a NextToken for that
// bucket. Used by tests exercising the capped-bucket path.
type bucketFakeAPI struct {
	// severityCounts / workflowCounts map a bucket value to how many findings
	// to report for it. A value >= pageSize also sets NextToken on the response
	// (capped); values are clamped to at most pageSize actual findings returned,
	// matching what MaxResults would do.
	severityCounts map[string]int32
	workflowCounts map[string]int32
	calls          []*securityhub.GetFindingsInput
}

func (f *bucketFakeAPI) GetFindings(_ context.Context, in *securityhub.GetFindingsInput, _ ...func(*securityhub.Options)) (*securityhub.GetFindingsOutput, error) {
	f.calls = append(f.calls, in)

	var value string
	var total int32
	switch {
	case len(in.Filters.SeverityLabel) > 0:
		value = aws.ToString(in.Filters.SeverityLabel[0].Value)
		total = f.severityCounts[value]
	case len(in.Filters.WorkflowStatus) > 0:
		value = aws.ToString(in.Filters.WorkflowStatus[0].Value)
		total = f.workflowCounts[value]
	}

	returned := total
	if returned > pageSize {
		returned = pageSize
	}
	out := &securityhub.GetFindingsOutput{
		Findings: make([]types.AwsSecurityFinding, returned),
	}
	if total > pageSize {
		out.NextToken = aws.String("more")
	}
	return out, nil
}

// pagedFakeAPI serves the TYPE/PRODUCT exhaustive-pagination path.
type pagedFakeAPI struct {
	pages   [][]types.AwsSecurityFinding
	tokens  []string // NextToken to return after each page; "" means no more pages
	callIdx int
}

func (f *pagedFakeAPI) GetFindings(_ context.Context, in *securityhub.GetFindingsInput, _ ...func(*securityhub.Options)) (*securityhub.GetFindingsOutput, error) {
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
	return NewWithClientFactoryAndSleep(func(_ context.Context, _ string) (api, string, error) { return a, "eu-west-1", nil }, noSleep)
}

// statCounts re-keys a Statistics' Counts by bucket key, dropping Key from
// the value since it's already the map key, for concise test comparisons.
func statCounts(stats Statistics) map[string]shc.StatCount {
	m := map[string]shc.StatCount{}
	for _, c := range stats.Counts {
		m[c.Key] = shc.StatCount{Count: c.Count, Capped: c.Capped}
	}
	return m
}

func TestExecute_SeverityDefault_ExactCounts(t *testing.T) {
	api := &bucketFakeAPI{severityCounts: map[string]int32{"HIGH": 2, "LOW": 1}}
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
	counts := statCounts(stats)
	if counts["HIGH"] != (shc.StatCount{Count: 2}) || counts["LOW"] != (shc.StatCount{Count: 1}) {
		t.Errorf("counts = %+v, want HIGH:2 LOW:1, neither capped", counts)
	}
	if stats.Total != 3 {
		t.Errorf("Total = %d, want 3", stats.Total)
	}
	// 5 severity buckets queried, one call each, regardless of how many are empty.
	if len(api.calls) != 5 {
		t.Errorf("GetFindings called %d times, want 5 (one per severity bucket)", len(api.calls))
	}
}

func TestExecute_Severity_CappedBucketReported(t *testing.T) {
	api := &bucketFakeAPI{severityCounts: map[string]int32{"CRITICAL": 145, "LOW": 3}}
	res, err := newTestTask(api).Execute(context.Background(), json.RawMessage(`{"group_by":"SEVERITY"}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	stats := res.Details.(Statistics)
	counts := statCounts(stats)
	if got := counts["CRITICAL"]; got.Count != pageSize || !got.Capped {
		t.Errorf("CRITICAL = %+v, want Count=%d Capped=true", got, pageSize)
	}
	if got := counts["LOW"]; got.Count != 3 || got.Capped {
		t.Errorf("LOW = %+v, want Count=3 Capped=false", got)
	}
	// Total is a lower bound: pageSize (capped) + 3 (exact), not 145+3.
	if want := pageSize + 3; stats.Total != want {
		t.Errorf("Total = %d, want %d (capped bucket contributes pageSize, not its true count)", stats.Total, want)
	}
}

func TestExecute_WorkflowStatus_MixedCappedAndExact(t *testing.T) {
	api := &bucketFakeAPI{workflowCounts: map[string]int32{"NEW": 250, "RESOLVED": 10}}
	res, err := newTestTask(api).Execute(context.Background(), json.RawMessage(`{"group_by":"WORKFLOW_STATUS"}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	stats := res.Details.(Statistics)
	if stats.GroupBy != "WORKFLOW_STATUS" {
		t.Errorf("GroupBy = %q, want WORKFLOW_STATUS", stats.GroupBy)
	}
	counts := statCounts(stats)
	if got := counts["NEW"]; got.Count != pageSize || !got.Capped {
		t.Errorf("NEW = %+v, want Count=%d Capped=true", got, pageSize)
	}
	if got := counts["RESOLVED"]; got.Count != 10 || got.Capped {
		t.Errorf("RESOLVED = %+v, want Count=10 Capped=false", got)
	}
	// 4 workflow_status buckets queried, one call each.
	if len(api.calls) != 4 {
		t.Errorf("GetFindings called %d times, want 4 (one per workflow_status bucket)", len(api.calls))
	}
}

func TestExecute_EmptyBucketsOmittedFromCounts(t *testing.T) {
	api := &bucketFakeAPI{severityCounts: map[string]int32{"HIGH": 1}}
	res, err := newTestTask(api).Execute(context.Background(), json.RawMessage(`{}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	stats := res.Details.(Statistics)
	if len(stats.Counts) != 1 {
		t.Errorf("Counts = %+v, want exactly 1 bucket (empty buckets omitted)", stats.Counts)
	}
}

// TestExecute_SeverityBucketsConstrainedToResolvedRegion verifies every
// per-bucket GetFindings call carries a Region filter for the client
// factory's resolved region — required because Security Hub cross-region
// finding aggregators can otherwise return findings from every linked
// region, not just the one this satellite runs in. See
// securityhub_common.Filter.Region's doc comment.
func TestExecute_SeverityBucketsConstrainedToResolvedRegion(t *testing.T) {
	api := &bucketFakeAPI{severityCounts: map[string]int32{"HIGH": 1}}
	_, err := newTestTask(api).Execute(context.Background(), json.RawMessage(`{}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(api.calls) == 0 {
		t.Fatal("expected at least one GetFindings call")
	}
	for _, call := range api.calls {
		if len(call.Filters.Region) != 1 || aws.ToString(call.Filters.Region[0].Value) != "eu-west-1" {
			t.Errorf("call Region filter = %+v, want [eu-west-1]", call.Filters.Region)
		}
	}
}

func typeFinding(typ string) types.AwsSecurityFinding {
	return types.AwsSecurityFinding{Id: aws.String("f"), ProductArn: aws.String("arn"), Types: []string{typ}}
}

func productFinding(product string) types.AwsSecurityFinding {
	return types.AwsSecurityFinding{Id: aws.String("f"), ProductArn: aws.String("arn"), ProductName: aws.String(product)}
}

func TestExecute_Type_AggregatesExhaustively(t *testing.T) {
	api := &pagedFakeAPI{
		pages: [][]types.AwsSecurityFinding{
			{typeFinding("Software and Configuration Checks"), typeFinding("Software and Configuration Checks"), typeFinding("TTPs")},
		},
	}
	res, err := newTestTask(api).Execute(context.Background(), json.RawMessage(`{"group_by":"TYPE"}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	stats := res.Details.(Statistics)
	if stats.GroupBy != "TYPE" {
		t.Errorf("GroupBy = %q, want TYPE", stats.GroupBy)
	}
	counts := map[string]int32{}
	for _, c := range stats.Counts {
		counts[c.Key] = c.Count
		if c.Capped {
			t.Errorf("TYPE bucket %q reported Capped=true, want exhaustive counting (never capped)", c.Key)
		}
	}
	if counts["Software and Configuration Checks"] != 2 || counts["TTPs"] != 1 {
		t.Errorf("counts = %+v, want 2/1", counts)
	}
	if stats.Total != 3 {
		t.Errorf("Total = %d, want 3", stats.Total)
	}
}

// TestExecute_Product_PaginatesExhaustivelyPastFormerCap verifies statistics
// counts every finding across many pages with no upper bound for the
// exhaustive (PRODUCT) path.
func TestExecute_Product_PaginatesExhaustivelyPastFormerCap(t *testing.T) {
	const pages = 15
	fakePages := make([][]types.AwsSecurityFinding, pages)
	tokens := make([]string, pages)
	for i := range fakePages {
		fakePages[i] = []types.AwsSecurityFinding{productFinding("GuardDuty")}
		if i < pages-1 {
			tokens[i] = "more"
		}
	}
	api := &pagedFakeAPI{pages: fakePages, tokens: tokens}
	res, err := newTestTask(api).Execute(context.Background(), json.RawMessage(`{"group_by":"PRODUCT"}`))
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

// TestExecute_Product_SleepsBetweenPagesButNotBeforeFirst verifies the
// inter-page delay is invoked once per page transition (pages-1 times for N
// pages), not before the first request.
func TestExecute_Product_SleepsBetweenPagesButNotBeforeFirst(t *testing.T) {
	fake := &pagedFakeAPI{
		pages: [][]types.AwsSecurityFinding{
			{productFinding("GuardDuty")},
			{productFinding("GuardDuty")},
			{productFinding("GuardDuty")},
		},
		tokens: []string{"p2", "p3", ""},
	}
	var sleepCalls int
	task := NewWithClientFactoryAndSleep(func(_ context.Context, _ string) (api, string, error) { return fake, "eu-west-1", nil }, func(context.Context, time.Duration) {
		sleepCalls++
	})
	_, err := task.Execute(context.Background(), json.RawMessage(`{"group_by":"PRODUCT"}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sleepCalls != 2 {
		t.Errorf("sleep called %d times for 3 pages, want 2 (between pages, not before the first)", sleepCalls)
	}
}

func TestExecute_UnsupportedGroupBy(t *testing.T) {
	res, err := newTestTask(&pagedFakeAPI{}).Execute(context.Background(), json.RawMessage(`{"group_by":"BOGUS"}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Success {
		t.Fatal("expected failure for unsupported group_by")
	}
}

func TestExecute_InvalidPayload(t *testing.T) {
	res, err := newTestTask(&pagedFakeAPI{}).Execute(context.Background(), json.RawMessage(`{`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Success {
		t.Fatal("expected success=false for invalid payload")
	}
}

// TestExecute_Product_ContextCancelledDuringPagination verifies a cancelled
// context aborts the scan promptly rather than sitting through the remainder
// of a long scan's inter-page delays.
func TestExecute_Product_ContextCancelledDuringPagination(t *testing.T) {
	fake := &pagedFakeAPI{
		pages: [][]types.AwsSecurityFinding{
			{productFinding("GuardDuty")},
			{productFinding("GuardDuty")},
		},
		tokens: []string{"more", ""},
	}
	ctx, cancel := context.WithCancel(context.Background())
	task := NewWithClientFactoryAndSleep(func(_ context.Context, _ string) (api, string, error) { return fake, "eu-west-1", nil }, func(context.Context, time.Duration) {
		cancel() // simulate cancellation arriving during the inter-page wait
	})
	_, err := task.Execute(ctx, json.RawMessage(`{"group_by":"PRODUCT"}`))
	if err == nil {
		t.Fatal("expected an error when context is cancelled mid-scan")
	}
}
