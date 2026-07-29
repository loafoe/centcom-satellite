package securityhub_get_insight_statistics

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/securityhub"
	"github.com/aws/aws-sdk-go-v2/service/securityhub/types"
)

type fakeAPI struct {
	insightPages   [][]types.Insight
	insightTokens  []string // NextToken after each GetInsights page; "" means no more pages
	getInsightsIdx int

	createErr    error
	created      *securityhub.CreateInsightInput
	createdArn   string
	createCalled int

	resultValues     []types.InsightResultValue
	getResultsCalled int
	lastResultsArn   string
}

func (f *fakeAPI) GetInsights(_ context.Context, in *securityhub.GetInsightsInput, _ ...func(*securityhub.Options)) (*securityhub.GetInsightsOutput, error) {
	idx := f.getInsightsIdx
	f.getInsightsIdx++
	var page []types.Insight
	if idx < len(f.insightPages) {
		page = f.insightPages[idx]
	}
	out := &securityhub.GetInsightsOutput{Insights: page}
	if idx < len(f.insightTokens) && f.insightTokens[idx] != "" {
		out.NextToken = aws.String(f.insightTokens[idx])
	}
	return out, nil
}

func (f *fakeAPI) CreateInsight(_ context.Context, in *securityhub.CreateInsightInput, _ ...func(*securityhub.Options)) (*securityhub.CreateInsightOutput, error) {
	f.createCalled++
	f.created = in
	if f.createErr != nil {
		return nil, f.createErr
	}
	arn := f.createdArn
	if arn == "" {
		arn = "arn:aws:securityhub:us-east-1:111111111111:insight/111111111111/custom/new"
	}
	return &securityhub.CreateInsightOutput{InsightArn: aws.String(arn)}, nil
}

func (f *fakeAPI) GetInsightResults(_ context.Context, in *securityhub.GetInsightResultsInput, _ ...func(*securityhub.Options)) (*securityhub.GetInsightResultsOutput, error) {
	f.getResultsCalled++
	f.lastResultsArn = aws.ToString(in.InsightArn)
	return &securityhub.GetInsightResultsOutput{
		InsightResults: &types.InsightResults{
			InsightArn:       in.InsightArn,
			GroupByAttribute: aws.String("SeverityLabel"),
			ResultValues:     f.resultValues,
		},
	}, nil
}

func newTestTask(a api) *Task {
	return NewWithClientFactory(func(_ context.Context, _ string) (api, string, error) { return a, "us-east-1", nil })
}

func insight(name, arn string) types.Insight {
	return types.Insight{Name: aws.String(name), InsightArn: aws.String(arn), GroupByAttribute: aws.String("SeverityLabel")}
}

func resultValue(key string, count int32) types.InsightResultValue {
	return types.InsightResultValue{GroupByAttributeValue: aws.String(key), Count: aws.Int32(count)}
}

func TestExecute_ReusesExistingInsightByName(t *testing.T) {
	fake := &fakeAPI{
		insightPages: [][]types.Insight{{
			insight("some-other-insight", "arn:other"),
			insight("centcom-satellite-stats-severity-us-east-1", "arn:existing"),
		}},
		resultValues: []types.InsightResultValue{
			resultValue("CRITICAL", 3521), resultValue("HIGH", 19837), resultValue("MEDIUM", 34010),
			resultValue("LOW", 3078), resultValue("INFORMATIONAL", 1899),
		},
	}
	res, err := newTestTask(fake).Execute(context.Background(), json.RawMessage(`{}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.Success {
		t.Fatalf("expected success, got error: %s", res.Error)
	}
	if fake.createCalled != 0 {
		t.Errorf("CreateInsight called %d times, want 0 (existing insight should be reused)", fake.createCalled)
	}
	if fake.lastResultsArn != "arn:existing" {
		t.Errorf("GetInsightResults called with arn %q, want arn:existing", fake.lastResultsArn)
	}
	stats := res.Details.(Statistics)
	if stats.InsightArn != "arn:existing" {
		t.Errorf("InsightArn = %q, want arn:existing", stats.InsightArn)
	}
	counts := map[string]int32{}
	for _, c := range stats.Counts {
		counts[c.Key] = c.Count
		if c.Capped {
			t.Errorf("bucket %q reported Capped=true, want insight results to never be capped", c.Key)
		}
	}
	want := map[string]int32{"CRITICAL": 3521, "HIGH": 19837, "MEDIUM": 34010, "LOW": 3078, "INFORMATIONAL": 1899}
	for k, v := range want {
		if counts[k] != v {
			t.Errorf("counts[%s] = %d, want %d", k, counts[k], v)
		}
	}
	if stats.Total != 3521+19837+34010+3078+1899 {
		t.Errorf("Total = %d, want sum of all buckets", stats.Total)
	}
}

func TestExecute_CreatesInsightWhenMissing(t *testing.T) {
	fake := &fakeAPI{
		insightPages: [][]types.Insight{{insight("unrelated", "arn:unrelated")}},
		createdArn:   "arn:new-severity-insight",
		resultValues: []types.InsightResultValue{resultValue("HIGH", 5)},
	}
	res, err := newTestTask(fake).Execute(context.Background(), json.RawMessage(`{"group_by":"SEVERITY"}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.Success {
		t.Fatalf("expected success, got error: %s", res.Error)
	}
	if fake.createCalled != 1 {
		t.Fatalf("CreateInsight called %d times, want 1", fake.createCalled)
	}
	if got := aws.ToString(fake.created.Name); got != "centcom-satellite-stats-severity-us-east-1" {
		t.Errorf("insight name = %q, want centcom-satellite-stats-severity-us-east-1", got)
	}
	if got := aws.ToString(fake.created.GroupByAttribute); got != "SeverityLabel" {
		t.Errorf("group by attribute = %q, want SeverityLabel", got)
	}
	if fake.lastResultsArn != "arn:new-severity-insight" {
		t.Errorf("GetInsightResults called with arn %q, want the newly created insight's arn", fake.lastResultsArn)
	}
}

// TestExecute_MultipleNameMatchesUsesFirst verifies that when more than one
// insight shares the expected name (AWS does not enforce uniqueness), the
// task deterministically uses the first match rather than erroring.
func TestExecute_MultipleNameMatchesUsesFirst(t *testing.T) {
	fake := &fakeAPI{
		insightPages: [][]types.Insight{{
			insight("centcom-satellite-stats-severity-us-east-1", "arn:first-match"),
			insight("centcom-satellite-stats-severity-us-east-1", "arn:second-match"),
		}},
		resultValues: []types.InsightResultValue{resultValue("HIGH", 1)},
	}
	_, err := newTestTask(fake).Execute(context.Background(), json.RawMessage(`{}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fake.createCalled != 0 {
		t.Errorf("CreateInsight called %d times, want 0", fake.createCalled)
	}
	if fake.lastResultsArn != "arn:first-match" {
		t.Errorf("used arn %q, want the first match arn:first-match", fake.lastResultsArn)
	}
}

// TestExecute_PaginatesInsightLookupAcrossPages verifies the name search
// continues across GetInsights pages before deciding to create.
func TestExecute_PaginatesInsightLookupAcrossPages(t *testing.T) {
	fake := &fakeAPI{
		insightPages: [][]types.Insight{
			{insight("page1-a", "arn:p1a")},
			{insight("centcom-satellite-stats-severity-us-east-1", "arn:p2-match")},
		},
		insightTokens: []string{"more", ""},
		resultValues:  []types.InsightResultValue{resultValue("HIGH", 1)},
	}
	_, err := newTestTask(fake).Execute(context.Background(), json.RawMessage(`{}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fake.getInsightsIdx != 2 {
		t.Errorf("GetInsights called %d times, want 2 (paginated to find the match on page 2)", fake.getInsightsIdx)
	}
	if fake.createCalled != 0 {
		t.Errorf("CreateInsight called %d times, want 0", fake.createCalled)
	}
	if fake.lastResultsArn != "arn:p2-match" {
		t.Errorf("used arn %q, want arn:p2-match", fake.lastResultsArn)
	}
}

func TestExecute_QuotaExceededReturnsClearError(t *testing.T) {
	fake := &fakeAPI{
		insightPages: [][]types.Insight{{}},
		createErr:    &types.LimitExceededException{Message: aws.String("quota exceeded")},
	}
	res, err := newTestTask(fake).Execute(context.Background(), json.RawMessage(`{}`))
	if err != nil {
		t.Fatalf("unexpected transport error: %v", err)
	}
	if res.Success {
		t.Fatal("expected failure when the insight quota is exhausted")
	}
	if fake.getResultsCalled != 0 {
		t.Errorf("GetInsightResults called %d times, want 0 (should never be reached after create failure)", fake.getResultsCalled)
	}
}

// TestExecute_CreatedInsightConstrainedToResolvedRegion verifies a newly
// created Insight's Filters include a Region filter for the client
// factory's resolved region — required because Security Hub cross-region
// finding aggregators can otherwise let GetInsightResults return findings
// from every linked region, not just the one this satellite runs in.
func TestExecute_CreatedInsightConstrainedToResolvedRegion(t *testing.T) {
	fake := &fakeAPI{
		insightPages: [][]types.Insight{{}},
		resultValues: []types.InsightResultValue{resultValue("HIGH", 1)},
	}
	_, err := newTestTask(fake).Execute(context.Background(), json.RawMessage(`{}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fake.created == nil {
		t.Fatal("expected CreateInsight to be called")
	}
	region := fake.created.Filters.Region
	if len(region) != 1 || aws.ToString(region[0].Value) != "us-east-1" {
		t.Errorf("created insight Region filter = %+v, want [us-east-1]", region)
	}
}

// TestExecute_StaleUnregionedNameNotReused verifies an Insight named without
// the region suffix (as this task named Insights before region-scoping was
// added) is never matched by name and reused — it would carry a stale,
// unregioned filter. A fresh, correctly-named-and-filtered Insight must be
// created instead.
func TestExecute_StaleUnregionedNameNotReused(t *testing.T) {
	fake := &fakeAPI{
		insightPages: [][]types.Insight{{
			insight("centcom-satellite-stats-severity", "arn:stale-unregioned"),
		}},
		createdArn:   "arn:new-regioned",
		resultValues: []types.InsightResultValue{resultValue("HIGH", 1)},
	}
	res, err := newTestTask(fake).Execute(context.Background(), json.RawMessage(`{}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fake.createCalled != 1 {
		t.Fatalf("CreateInsight called %d times, want 1 (stale unregioned insight must not be reused)", fake.createCalled)
	}
	if fake.lastResultsArn != "arn:new-regioned" {
		t.Errorf("used arn %q, want the newly created arn:new-regioned", fake.lastResultsArn)
	}
	stats := res.Details.(Statistics)
	if stats.InsightArn == "arn:stale-unregioned" {
		t.Error("result used the stale unregioned insight")
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
