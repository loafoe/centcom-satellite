package securityhub_get_findings_statistics

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
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
// TestExecute_ScanBudgetTruncatesExhaustiveScan is the regression test for
// the live incident (2026-10-30): an unfiltered group_by=TITLE scan on a
// real account paged for 4m59s before an external caller's own 5-minute
// timeout killed it with no result at all. A scan whose own budget elapses
// must stop pagination and return a partial, Truncated result instead.
func TestExecute_ScanBudgetTruncatesExhaustiveScan(t *testing.T) {
	pages := make([][]types.AwsSecurityFinding, 10)
	tokens := make([]string, 10)
	for i := range pages {
		pages[i] = []types.AwsSecurityFinding{productFinding("GuardDuty")}
		if i < len(pages)-1 {
			tokens[i] = "more"
		}
	}
	fake := &pagedFakeAPI{pages: pages, tokens: tokens}
	tk := newTestTask(fake)
	tk.scanBudget = 1 * time.Nanosecond

	res, err := tk.Execute(context.Background(), json.RawMessage(`{"group_by":"PRODUCT"}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.Success {
		t.Fatalf("expected success (partial), got error: %s", res.Error)
	}
	stats := res.Details.(Statistics)
	if !stats.Truncated {
		t.Error("Truncated = false, want true")
	}
	if fake.callIdx >= len(pages) {
		t.Errorf("GetFindings called %d times, want fewer than all %d pages — budget should stop pagination early", fake.callIdx, len(pages))
	}
	if stats.Total == 0 {
		t.Error("Total = 0, want at least the first page's worth of findings")
	}
}

// TestExecute_DefaultScanBudgetNeverTruncatesAFastScan guards against a
// regression where the budget fires on ordinary small scans — the default
// (45s) must never trip for the handful of pages exercised by every other
// test in this file.
func TestExecute_DefaultScanBudgetNeverTruncatesAFastScan(t *testing.T) {
	fake := &pagedFakeAPI{
		pages:  [][]types.AwsSecurityFinding{{productFinding("GuardDuty")}, {productFinding("GuardDuty")}},
		tokens: []string{"more", ""},
	}
	res, err := newTestTask(fake).Execute(context.Background(), json.RawMessage(`{"group_by":"PRODUCT"}`))
	if err != nil || !res.Success {
		t.Fatalf("err=%v success=%v", err, res.Success)
	}
	if res.Details.(Statistics).Truncated {
		t.Error("Truncated = true, want false for a fast, 2-page scan under the default 45s budget")
	}
}

// tokenedFakeAPI serves pages keyed by the NextToken used to request them
// ("" for the first page) — unlike pagedFakeAPI (which just serves pages in
// call order and ignores the request), this lets a test prove a resume call
// jumps straight to the right page instead of silently restarting from the
// first one.
type tokenedFakeAPI struct {
	pages map[string]tokenedPage
	calls []string // the NextToken requested on each call, in order
}

type tokenedPage struct {
	findings  []types.AwsSecurityFinding
	nextToken string // "" means no more pages
}

func (f *tokenedFakeAPI) GetFindings(_ context.Context, in *securityhub.GetFindingsInput, _ ...func(*securityhub.Options)) (*securityhub.GetFindingsOutput, error) {
	key := aws.ToString(in.NextToken)
	f.calls = append(f.calls, key)
	page, ok := f.pages[key]
	if !ok {
		return nil, fmt.Errorf("tokenedFakeAPI: no page registered for token %q", key)
	}
	out := &securityhub.GetFindingsOutput{Findings: page.findings}
	if page.nextToken != "" {
		out.NextToken = aws.String(page.nextToken)
	}
	return out, nil
}

// TestExecute_ScanBudgetReturnsResumableNextToken is the regression test for
// the continuation-cursor gap: a Truncated response used to discard AWS's
// own NextToken, so a caller's only path forward was narrowing the filter —
// repeating the same call just rescanned from page one and truncated at the
// same point every time. Now NextToken is returned, and feeding it back as
// Payload.NextToken resumes exactly where the previous call stopped.
func TestExecute_ScanBudgetReturnsResumableNextToken(t *testing.T) {
	fake := &tokenedFakeAPI{pages: map[string]tokenedPage{
		"":   {findings: []types.AwsSecurityFinding{productFinding("GuardDuty")}, nextToken: "p1"},
		"p1": {findings: []types.AwsSecurityFinding{productFinding("Inspector")}, nextToken: "p2"},
		"p2": {findings: []types.AwsSecurityFinding{productFinding("Macie")}, nextToken: ""},
	}}
	tk := newTestTask(fake)
	tk.scanBudget = 1 * time.Nanosecond

	res, err := tk.Execute(context.Background(), json.RawMessage(`{"group_by":"PRODUCT"}`))
	if err != nil || !res.Success {
		t.Fatalf("call 1: err=%v success=%v", err, res.Success)
	}
	stats := res.Details.(Statistics)
	if !stats.Truncated {
		t.Fatal("call 1: Truncated = false, want true")
	}
	if stats.NextToken != "p1" {
		t.Errorf("call 1: NextToken = %q, want %q", stats.NextToken, "p1")
	}
	if stats.Total != 1 {
		t.Errorf("call 1: Total = %d, want 1 (only the \"\" page before the budget check)", stats.Total)
	}

	res2, err := tk.Execute(context.Background(), json.RawMessage(fmt.Sprintf(`{"group_by":"PRODUCT","next_token":%q}`, stats.NextToken)))
	if err != nil || !res2.Success {
		t.Fatalf("call 2 (resume): err=%v success=%v", err, res2.Success)
	}
	stats2 := res2.Details.(Statistics)
	if !stats2.Truncated {
		t.Fatal("call 2 (resume): Truncated = false, want true")
	}
	if stats2.NextToken != "p2" {
		t.Errorf("call 2 (resume): NextToken = %q, want %q", stats2.NextToken, "p2")
	}
	if stats2.Total != 1 {
		t.Errorf("call 2 (resume): Total = %d, want 1 (only the \"p1\" page — proves it resumed, didn't restart from \"\")", stats2.Total)
	}

	if want := []string{"", "p1"}; !reflect.DeepEqual(fake.calls, want) {
		t.Errorf("GetFindings called with tokens %v, want %v (call 1 fetches \"\", call 2 resumes straight at \"p1\")", fake.calls, want)
	}
}

// TestExecute_FinishedScanNeverReturnsANextToken guards against a resume
// cursor being handed out when there is nothing left to resume — a client
// that blindly retries on any Truncated==false response must never see a
// stray NextToken either.
func TestExecute_FinishedScanNeverReturnsANextToken(t *testing.T) {
	fake := &pagedFakeAPI{
		pages:  [][]types.AwsSecurityFinding{{productFinding("GuardDuty")}},
		tokens: []string{""},
	}
	res, err := newTestTask(fake).Execute(context.Background(), json.RawMessage(`{"group_by":"PRODUCT"}`))
	if err != nil || !res.Success {
		t.Fatalf("err=%v success=%v", err, res.Success)
	}
	stats := res.Details.(Statistics)
	if stats.Truncated || stats.NextToken != "" {
		t.Errorf("Truncated=%v NextToken=%q, want false/\"\" for a scan that finished on its own", stats.Truncated, stats.NextToken)
	}
}

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

func TestExecute_ResourceType_CountsFirstResource(t *testing.T) {
	api := &pagedFakeAPI{
		pages:  [][]types.AwsSecurityFinding{{resourceFinding("AwsEc2Instance", "AwsEc2Volume"), resourceFinding("AwsEc2Instance")}, {resourceFinding("AwsS3Bucket"), resourceFinding()}},
		tokens: []string{"p2", ""},
	}
	res, err := newTestTask(api).Execute(context.Background(), json.RawMessage(`{"group_by":"RESOURCE_TYPE"}`))
	if err != nil || !res.Success {
		t.Fatalf("err=%v res=%+v", err, res)
	}
	got := statCounts(res.Details.(Statistics))
	want := map[string]int32{"AwsEc2Instance": 2, "AwsS3Bucket": 1, "": 1}
	for k, v := range want {
		if got[k].Count != v {
			t.Errorf("counts[%q] = %d, want %d (all: %+v)", k, got[k].Count, v, got)
		}
	}
}

func resourceFinding(resourceTypes ...string) types.AwsSecurityFinding {
	f := types.AwsSecurityFinding{}
	for _, rt := range resourceTypes {
		f.Resources = append(f.Resources, types.Resource{Type: aws.String(rt)})
	}
	return f
}
