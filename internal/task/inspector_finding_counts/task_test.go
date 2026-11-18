package inspector_finding_counts

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/inspector2"
	itypes "github.com/aws/aws-sdk-go-v2/service/inspector2/types"
	"github.com/aws/aws-sdk-go-v2/service/securityhub"
	shtypes "github.com/aws/aws-sdk-go-v2/service/securityhub/types"
)

type fakeInspector struct {
	counts   map[itypes.AggregationResourceType]itypes.SeverityCounts
	aggErr   map[itypes.AggregationResourceType]error
	findings []itypes.Finding // all findings; ListFindings filters by firstObservedAt window
}

func (f *fakeInspector) ListFindingAggregations(_ context.Context, in *inspector2.ListFindingAggregationsInput, _ ...func(*inspector2.Options)) (*inspector2.ListFindingAggregationsOutput, error) {
	rt := in.AggregationRequest.(*itypes.AggregationRequestMemberAccountAggregation).Value.ResourceType
	if err := f.aggErr[rt]; err != nil {
		return nil, err
	}
	sc := f.counts[rt]
	return &inspector2.ListFindingAggregationsOutput{Responses: []itypes.AggregationResponse{
		&itypes.AggregationResponseMemberAccountAggregation{Value: itypes.AccountAggregationResponse{
			AccountId: aws.String("111122223333"), SeverityCounts: &sc, ExploitAvailableCount: aws.Int64(3), FixAvailableCount: aws.Int64(4),
		}},
	}}, nil
}

func (f *fakeInspector) ListFindings(_ context.Context, in *inspector2.ListFindingsInput, _ ...func(*inspector2.Options)) (*inspector2.ListFindingsOutput, error) {
	w := in.FilterCriteria.FirstObservedAt[0]
	out := &inspector2.ListFindingsOutput{}
	for _, fd := range f.findings {
		t := aws.ToTime(fd.FirstObservedAt)
		if !t.Before(*w.StartInclusive) && !t.After(*w.EndInclusive) && len(out.Findings) < int(aws.ToInt32(in.MaxResults)) {
			out.Findings = append(out.Findings, fd)
		}
	}
	return out, nil
}

type fakeSecurityHub struct {
	have  map[string]bool
	err   error
	calls int
}

func (f *fakeSecurityHub) GetFindings(_ context.Context, in *securityhub.GetFindingsInput, _ ...func(*securityhub.Options)) (*securityhub.GetFindingsOutput, error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	if len(in.Filters.Id) > 20 {
		return nil, errors.New("more than 20 Id values")
	}
	out := &securityhub.GetFindingsOutput{}
	for _, flt := range in.Filters.Id {
		if f.have[aws.ToString(flt.Value)] {
			out.Findings = append(out.Findings, shtypes.AwsSecurityFinding{Id: flt.Value})
		}
	}
	return out, nil
}

func newTask(i *fakeInspector, sh *fakeSecurityHub) *Task {
	return &Task{
		clients: func(context.Context, string) (clients, error) {
			return clients{insp: i, sh: sh, region: "us-east-1", account: "111122223333"}, nil
		},
		budget: 5 * time.Second,
	}
}

func run(t *testing.T, tk *Task, payload string) Report {
	t.Helper()
	res, err := tk.Execute(context.Background(), []byte(payload))
	if err != nil || !res.Success {
		t.Fatalf("unexpected failure: %v %+v", err, res)
	}
	return res.Details.(Report)
}

func TestExecute_CountsAndSyncSample(t *testing.T) {
	fixed := time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)
	defer func(orig func() time.Time) { now = orig }(now)
	now = func() time.Time { return fixed }

	finding := func(arn string, age time.Duration) itypes.Finding {
		return itypes.Finding{FindingArn: aws.String(arn), FirstObservedAt: aws.Time(fixed.Add(-age))}
	}
	i := &fakeInspector{
		counts: map[itypes.AggregationResourceType]itypes.SeverityCounts{
			itypes.AggregationResourceTypeAwsEcrContainerImage: {All: aws.Int64(10), High: aws.Int64(6), Untriaged: aws.Int64(4)},
		},
		findings: []itypes.Finding{
			finding("fresh", 5*time.Minute), // younger than 15m: never sampled
			finding("a", 30*time.Minute), finding("b", 2*time.Hour), finding("c", 5*time.Hour), finding("old", 30*time.Hour),
		},
	}
	sh := &fakeSecurityHub{have: map[string]bool{"a": true, "old": true}}
	r := run(t, newTask(i, sh), `{}`)

	if len(r.ResourceTypes) != 3 || r.ResourceTypes[0].ResourceType != "AWS_ECR_CONTAINER_IMAGE" {
		t.Fatalf("resource types = %+v", r.ResourceTypes)
	}
	if got := r.ResourceTypes[0].SeverityCounts; got.All != 10 || got.High != 6 || got.Untriaged != 4 {
		t.Fatalf("ECR counts = %+v", got)
	}
	s := r.SecurityHubSync
	if s == nil || s.Sampled != 4 || s.Missing != 2 || sh.calls != 1 {
		t.Fatalf("sync = %+v (calls %d), want 4 sampled / 2 missing in one Security Hub call", s, sh.calls)
	}
	if want := fixed.Add(-5 * time.Hour).Format(time.RFC3339); s.OldestMissingFirstObservedAt != want {
		t.Fatalf("oldest missing = %q, want %q", s.OldestMissingFirstObservedAt, want)
	}
	if s.Windows[1].Label != "1h-3h" || s.Windows[1].Missing != 1 || s.Windows[4].Missing != 0 {
		t.Fatalf("windows = %+v", s.Windows)
	}
}

func TestExecute_SecurityHubErrorDoesNotFailCounts(t *testing.T) {
	i := &fakeInspector{findings: []itypes.Finding{{FindingArn: aws.String("x"), FirstObservedAt: aws.Time(time.Now().Add(-time.Hour))}}}
	r := run(t, newTask(i, &fakeSecurityHub{err: errors.New("AccessDenied")}), `{}`)
	if r.SecurityHubSync == nil || r.SecurityHubSync.Error == "" {
		t.Fatalf("expected securityhub_sync.error, got %+v", r.SecurityHubSync)
	}
	if r2 := run(t, newTask(i, &fakeSecurityHub{}), `{"skip_securityhub_sync":true}`); r2.SecurityHubSync != nil {
		t.Fatalf("skip_securityhub_sync: got %+v", r2.SecurityHubSync)
	}
}

func TestExecute_AllCountsFailingIsAnErrorResult(t *testing.T) {
	denied := &itypes.AccessDeniedException{Message: aws.String("not authorized to perform inspector2:ListFindingAggregations")}
	i := &fakeInspector{aggErr: map[itypes.AggregationResourceType]error{}}
	for _, rt := range ResourceTypes {
		i.aggErr[rt] = denied
	}
	res, err := newTask(i, &fakeSecurityHub{}).Execute(context.Background(), nil)
	if err != nil || res.Success {
		t.Fatalf("want a client-fault error result (no false 500), got res=%+v err=%v", res, err)
	}
	// One failing resource type keeps the others.
	i.aggErr = map[itypes.AggregationResourceType]error{itypes.AggregationResourceTypeAwsLambdaFunction: denied}
	r := run(t, newTask(i, &fakeSecurityHub{}), `{"skip_securityhub_sync":true}`)
	if r.ResourceTypes[2].Error == "" || r.ResourceTypes[0].Error != "" {
		t.Fatalf("partial failure: %+v", r.ResourceTypes)
	}
}
