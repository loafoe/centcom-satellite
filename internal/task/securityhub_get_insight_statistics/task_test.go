package securityhub_get_insight_statistics

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/securityhub"
	"github.com/aws/aws-sdk-go-v2/service/securityhub/types"

	shc "github.com/loafoe/centcom-satellite/internal/task/securityhub_common"
)

// fakeAPI is an in-memory Security Hub holding custom Insights. Its
// results depend on the Insight's current group-by attribute, so a test can
// tell whose query a result answers.
type fakeAPI struct {
	insights []types.Insight
	nextID   int

	createErr    error
	deleteErr    error
	createCalled int
	updateCalled int
	deleted      []string

	results map[string][]types.InsightResultValue // GroupByAttribute -> values
	// onResults runs after GetInsightResults (simulates another process
	// rewriting the slot between our update and our read-back).
	onResults func(f *fakeAPI)
}

func (f *fakeAPI) GetInsights(_ context.Context, in *securityhub.GetInsightsInput, _ ...func(*securityhub.Options)) (*securityhub.GetInsightsOutput, error) {
	if len(in.InsightArns) == 0 {
		return &securityhub.GetInsightsOutput{Insights: append([]types.Insight(nil), f.insights...)}, nil
	}
	out := &securityhub.GetInsightsOutput{}
	for _, i := range f.insights {
		if aws.ToString(i.InsightArn) == in.InsightArns[0] {
			out.Insights = append(out.Insights, i)
		}
	}
	return out, nil
}

func (f *fakeAPI) CreateInsight(_ context.Context, in *securityhub.CreateInsightInput, _ ...func(*securityhub.Options)) (*securityhub.CreateInsightOutput, error) {
	f.createCalled++
	if f.createErr != nil {
		return nil, f.createErr
	}
	f.nextID++
	arn := fmt.Sprintf("arn:new-%d", f.nextID)
	f.insights = append(f.insights, types.Insight{InsightArn: aws.String(arn), Name: in.Name, GroupByAttribute: in.GroupByAttribute, Filters: in.Filters})
	return &securityhub.CreateInsightOutput{InsightArn: aws.String(arn)}, nil
}

func (f *fakeAPI) UpdateInsight(_ context.Context, in *securityhub.UpdateInsightInput, _ ...func(*securityhub.Options)) (*securityhub.UpdateInsightOutput, error) {
	f.updateCalled++
	for i := range f.insights {
		if aws.ToString(f.insights[i].InsightArn) == aws.ToString(in.InsightArn) {
			f.insights[i].Name, f.insights[i].GroupByAttribute, f.insights[i].Filters = in.Name, in.GroupByAttribute, in.Filters
			return &securityhub.UpdateInsightOutput{}, nil
		}
	}
	return nil, &types.ResourceNotFoundException{}
}

func (f *fakeAPI) DeleteInsight(_ context.Context, in *securityhub.DeleteInsightInput, _ ...func(*securityhub.Options)) (*securityhub.DeleteInsightOutput, error) {
	if f.deleteErr != nil {
		return nil, f.deleteErr
	}
	arn := aws.ToString(in.InsightArn)
	f.deleted = append(f.deleted, arn)
	for i := range f.insights {
		if aws.ToString(f.insights[i].InsightArn) == arn {
			f.insights = append(f.insights[:i], f.insights[i+1:]...)
			break
		}
	}
	return &securityhub.DeleteInsightOutput{InsightArn: in.InsightArn}, nil
}

func (f *fakeAPI) GetInsightResults(_ context.Context, in *securityhub.GetInsightResultsInput, _ ...func(*securityhub.Options)) (*securityhub.GetInsightResultsOutput, error) {
	var attr string
	for _, i := range f.insights {
		if aws.ToString(i.InsightArn) == aws.ToString(in.InsightArn) {
			attr = aws.ToString(i.GroupByAttribute)
		}
	}
	if attr == "" {
		return nil, &types.ResourceNotFoundException{}
	}
	out := &securityhub.GetInsightResultsOutput{InsightResults: &types.InsightResults{
		InsightArn: in.InsightArn, GroupByAttribute: aws.String(attr), ResultValues: f.results[attr],
	}}
	if f.onResults != nil {
		f.onResults(f)
	}
	return out, nil
}

func (f *fakeAPI) named(prefix string) []types.Insight {
	var out []types.Insight
	for _, i := range f.insights {
		if len(aws.ToString(i.Name)) >= len(prefix) && aws.ToString(i.Name)[:len(prefix)] == prefix {
			out = append(out, i)
		}
	}
	return out
}

func insight(name, arn, attr string) types.Insight {
	return types.Insight{Name: aws.String(name), InsightArn: aws.String(arn), GroupByAttribute: aws.String(attr)}
}

func resultValue(key string, count int32) types.InsightResultValue {
	return types.InsightResultValue{GroupByAttributeValue: aws.String(key), Count: aws.Int32(count)}
}

// testRegion is unique per test so the process-wide once-per-region
// cleanup state doesn't leak between tests.
var testRegionN int

func newTestTask(a api) (*Task, string) {
	testRegionN++
	region := fmt.Sprintf("test-region-%d", testRegionN)
	return NewWithClientFactory(func(context.Context, string) (api, string, error) { return a, region, nil }), region
}

func run(t *testing.T, tk *Task, payload string) Statistics {
	t.Helper()
	res, err := tk.Execute(context.Background(), json.RawMessage(payload))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.Success {
		t.Fatalf("expected success, got error: %s", res.Error)
	}
	return res.Details.(Statistics)
}

func TestExecute_CreatesOneSlotAndReusesIt(t *testing.T) {
	fake := &fakeAPI{results: map[string][]types.InsightResultValue{
		"SeverityLabel": {resultValue("CRITICAL", 3), resultValue("HIGH", 4)},
		"ResourceType":  {resultValue("AwsEcrContainerImage", 9)},
	}}
	tk, region := newTestTask(fake)

	s := run(t, tk, `{}`)
	if fake.createCalled != 1 || s.Total != 7 {
		t.Fatalf("first call: created=%d total=%d, want 1/7", fake.createCalled, s.Total)
	}
	// Same query again: no create, no update.
	run(t, tk, `{}`)
	if fake.createCalled != 1 || fake.updateCalled != 0 {
		t.Errorf("repeat call: created=%d updated=%d, want 1/0", fake.createCalled, fake.updateCalled)
	}
	// Different group_by and filter: same slot, rewritten.
	s = run(t, tk, `{"group_by":"RESOURCE_TYPE","filter":{"severity_labels":["CRITICAL"]}}`)
	if fake.createCalled != 1 || fake.updateCalled != 1 {
		t.Errorf("new query: created=%d updated=%d, want 1/1", fake.createCalled, fake.updateCalled)
	}
	if s.Total != 9 || s.Counts[0].Key != "AwsEcrContainerImage" {
		t.Errorf("new query answered with %+v", s)
	}
	if n := len(fake.named(insightNamePrefix)); n != 1 {
		t.Errorf("%d statistics insights exist, want exactly 1", n)
	}
	slot := fake.named(slotPrefix(region))[0]
	sev := slot.Filters.SeverityLabel
	if len(sev) != 1 || aws.ToString(sev[0].Value) != "CRITICAL" {
		t.Errorf("slot filter = %+v, want the new query's filter", sev)
	}
	if r := slot.Filters.Region; len(r) != 1 || aws.ToString(r[0].Value) != region {
		t.Errorf("slot Region filter = %+v, want [%s]", r, region)
	}
}

func TestExecute_DeletesLeftoversOnce(t *testing.T) {
	fake := &fakeAPI{results: map[string][]types.InsightResultValue{"SeverityLabel": {resultValue("LOW", 1)}}}
	tk, region := newTestTask(fake)
	fake.insights = []types.Insight{
		insight("someone-elses-insight", "arn:user", "SeverityLabel"),
		insight("centcom-satellite-stats-severity", "arn:old1", "SeverityLabel"),
		insight("centcom-satellite-stats-resource_type-"+region+"-5a55b0518b12", "arn:old2", "ResourceType"),
		insight(slotPrefix(region)+"type-aaaaaaaaaaaa", "arn:slot", "Type"),
		insight(slotPrefix(region)+"type-bbbbbbbbbbbb", "arn:dup", "Type"),
	}
	s := run(t, tk, `{}`)
	if s.InsightArn != "arn:slot" || fake.createCalled != 0 {
		t.Errorf("used %s (created %d), want the existing slot arn:slot", s.InsightArn, fake.createCalled)
	}
	want := map[string]bool{"arn:old1": true, "arn:old2": true, "arn:dup": true}
	if len(fake.deleted) != 3 {
		t.Fatalf("deleted %v, want old1, old2, dup", fake.deleted)
	}
	for _, d := range fake.deleted {
		if !want[d] {
			t.Errorf("deleted %s, which is not a leftover", d)
		}
	}
	// Never touches a user's own Insight, and cleans up only once.
	fake.insights = append(fake.insights, insight("centcom-satellite-stats-late", "arn:late", "Type"))
	run(t, tk, `{}`)
	if len(fake.deleted) != 3 {
		t.Errorf("second call deleted again: %v", fake.deleted)
	}
}

func TestExecute_DeleteDeniedIsNotFatal(t *testing.T) {
	fake := &fakeAPI{deleteErr: fmt.Errorf("AccessDeniedException: explicit deny in SCP"),
		results: map[string][]types.InsightResultValue{"SeverityLabel": {resultValue("LOW", 1)}}}
	tk, _ := newTestTask(fake)
	fake.insights = []types.Insight{insight("centcom-satellite-stats-severity", "arn:old", "SeverityLabel")}
	if s := run(t, tk, `{}`); s.Total != 1 {
		t.Errorf("total = %d, want 1", s.Total)
	}
}

// TestExecute_RetriesWhenSlotRewrittenConcurrently: another process
// rewrites the slot right after our read, so the read may be theirs; the
// task must retry and only return a result read while the slot held ours.
func TestExecute_RetriesWhenSlotRewrittenConcurrently(t *testing.T) {
	fake := &fakeAPI{results: map[string][]types.InsightResultValue{
		"SeverityLabel": {resultValue("CRITICAL", 5)},
		"Type":          {resultValue("TTPs", 99)},
	}}
	tk, region := newTestTask(fake)
	hijacks := 1
	fake.onResults = func(f *fakeAPI) {
		if hijacks == 0 {
			return
		}
		hijacks--
		for i := range f.insights {
			f.insights[i].Name = aws.String(slotPrefix(region) + "type-ffffffffffff")
			f.insights[i].GroupByAttribute = aws.String("Type")
		}
	}
	s := run(t, tk, `{}`)
	if s.Total != 5 || s.Counts[0].Key != "CRITICAL" {
		t.Errorf("result = %+v, want our SEVERITY counts after a retry", s)
	}
	if fake.updateCalled != 1 {
		t.Errorf("updateCalled = %d, want 1 (rewrite after the hijack)", fake.updateCalled)
	}

	// Permanently contended: give up with a clear error, not wrong data.
	fake.onResults = func(f *fakeAPI) {
		for i := range f.insights {
			f.insights[i].Name = aws.String(slotPrefix(region) + "type-ffffffffffff")
		}
	}
	res, err := tk.Execute(context.Background(), json.RawMessage(`{}`))
	if err != nil || res.Success {
		t.Errorf("contended: err=%v success=%v, want an error result", err, res.Success)
	}
}

func TestExecute_QuotaExceededReturnsClearError(t *testing.T) {
	fake := &fakeAPI{createErr: &types.LimitExceededException{Message: aws.String("limit")}}
	tk, _ := newTestTask(fake)
	res, err := tk.Execute(context.Background(), json.RawMessage(`{}`))
	if err != nil || res.Success {
		t.Fatalf("err=%v success=%v, want an error result", err, res.Success)
	}
}

func TestExecute_ResourceIDGroupByTruncation(t *testing.T) {
	var vals []types.InsightResultValue
	for i := 0; i < maxInsightValues; i++ {
		vals = append(vals, resultValue(fmt.Sprintf("arn:aws:ec2:eu-west-2:123456789012:instance/i-%d", i), 1))
	}
	fake := &fakeAPI{results: map[string][]types.InsightResultValue{"ResourceId": vals}}
	tk, _ := newTestTask(fake)
	s := run(t, tk, `{"group_by":"RESOURCE_ID"}`)
	if s.GroupBy != "RESOURCE_ID" {
		t.Errorf("group_by = %s", s.GroupBy)
	}
	if !s.Truncated || len(s.Counts) != maxInsightValues {
		t.Errorf("truncated=%v counts=%d, want true/%d", s.Truncated, len(s.Counts), maxInsightValues)
	}
}

// TestExecute_TitleGroupByRejectedBeforeAnyAPICall verifies group_by=TITLE
// returns the satellite's own clear error (and points callers at
// title_prefix) without ever calling CreateInsight/UpdateInsight — AWS
// itself rejects "Title" as an Insight GroupByAttribute with
// InvalidInputException: Invalid Aggregations, so this must be caught
// before any AWS call, not surfaced as an opaque AWS error.
func TestExecute_TitleGroupByRejectedBeforeAnyAPICall(t *testing.T) {
	fake := &fakeAPI{}
	tk, _ := newTestTask(fake)
	res, err := tk.Execute(context.Background(), json.RawMessage(`{"group_by":"TITLE"}`))
	if err != nil || res.Success {
		t.Fatalf("err=%v success=%v, want a clear error result", err, res.Success)
	}
	if !strings.Contains(res.Error, "title_prefix") {
		t.Errorf("error = %q, want it to mention title_prefix", res.Error)
	}
	if fake.createCalled != 0 || fake.updateCalled != 0 {
		t.Errorf("createCalled=%d updateCalled=%d, want 0 (rejected before any AWS call)", fake.createCalled, fake.updateCalled)
	}
}

func TestFilterKey_EquivalentFiltersMatch(t *testing.T) {
	a := shc.Filter{WorkflowStatus: []string{"NEW", "NOTIFIED"}, SeverityLabels: []string{"CRITICAL"}, Region: "us-east-1"}
	b := shc.Filter{WorkflowStatus: []string{"NOTIFIED", "NEW", "NEW"}, SeverityLabels: []string{"CRITICAL"}, RecordState: "ACTIVE", Region: "us-east-1"}
	if filterKey(a) != filterKey(b) {
		t.Errorf("equivalent filters hash differently: %s vs %s", filterKey(a), filterKey(b))
	}
	if filterKey(a) == filterKey(shc.Filter{Region: "us-east-1"}) {
		t.Error("different filters hash the same")
	}
	if a.WorkflowStatus[0] != "NEW" || b.WorkflowStatus[0] != "NOTIFIED" {
		t.Error("filterKey mutated its input")
	}
}

func TestExecute_UnsupportedGroupByAndInvalidPayload(t *testing.T) {
	tk, _ := newTestTask(&fakeAPI{})
	for _, p := range []string{`{"group_by":"BOGUS"}`, `{`} {
		res, err := tk.Execute(context.Background(), json.RawMessage(p))
		if err != nil || res.Success {
			t.Errorf("%s: err=%v success=%v, want an error result", p, err, res.Success)
		}
	}
}
