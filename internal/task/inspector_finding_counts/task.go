// Package inspector_finding_counts reports exact, live Amazon Inspector
// finding counts per resource type (ECR images, EC2 instances, Lambda
// functions) straight from Inspector's own aggregation API — no Security Hub
// in between — plus how far Security Hub's copy of Inspector findings lags.
//
// Why: Security Hub ingests Inspector findings asynchronously, and the delay
// varies a lot per account/region (measured 2026-11-18: ~0 min on some
// accounts, ~2 h on others, 8-9 h on one). Counting through Security Hub
// therefore hides the newest findings for hours; Inspector's ACCOUNT
// aggregation (one call per resource type, ~4 s each, run in parallel) is
// exact and current, and needs no Security Hub Insight slot.
//
// Security Hub sync is checked by sampling (see SecurityHubSync). A
// Security Hub failure (not enabled, no permission) never fails the task:
// the counts still come back with securityhub_sync.error set.
package inspector_finding_counts

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/inspector2"
	itypes "github.com/aws/aws-sdk-go-v2/service/inspector2/types"
	"github.com/aws/aws-sdk-go-v2/service/securityhub"
	shtypes "github.com/aws/aws-sdk-go-v2/service/securityhub/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	awshelper "github.com/loafoe/centcom-satellite/internal/aws"
	"github.com/loafoe/centcom-satellite/internal/task"
)

const TaskName = "inspector_finding_counts"

// TimeBudget keeps the call well inside the satellite's HTTP write timeout.
const TimeBudget = 30 * time.Second

// ResourceTypes are the Inspector resource types counted, in display order.
var ResourceTypes = []itypes.AggregationResourceType{
	itypes.AggregationResourceTypeAwsEcrContainerImage,
	itypes.AggregationResourceTypeAwsEc2Instance,
	itypes.AggregationResourceTypeAwsLambdaFunction,
}

// Payload for inspector_finding_counts.
type Payload struct {
	Region string `json:"region,omitempty"`
	// SkipSecurityHubSync skips the Security Hub sync sample (6 calls).
	SkipSecurityHubSync bool `json:"skip_securityhub_sync,omitempty"`
}

// SeverityCounts are Inspector's active finding counts by severity.
type SeverityCounts struct {
	All           int64 `json:"all"`
	Critical      int64 `json:"critical"`
	High          int64 `json:"high"`
	Medium        int64 `json:"medium"`
	Low           int64 `json:"low"`
	Informational int64 `json:"informational"`
	// Untriaged findings have no severity yet — typically the newest CVEs,
	// before the vendor/NVD has scored them.
	Untriaged int64 `json:"untriaged"`
}

// ResourceTypeCounts is one resource type's row.
type ResourceTypeCounts struct {
	ResourceType     string         `json:"resource_type"`
	SeverityCounts   SeverityCounts `json:"severity_counts"`
	ExploitAvailable int64          `json:"exploit_available"`
	FixAvailable     int64          `json:"fix_available"`
	Error            string         `json:"error,omitempty"`
}

// SyncWindow is one age window of the Security Hub sync sample.
type SyncWindow struct {
	// Label is the age range, e.g. "1h-3h" (age = now - Inspector firstObservedAt).
	Label   string `json:"label"`
	Sampled int    `json:"sampled"`
	Missing int    `json:"missing"`
}

// SecurityHubSync says whether recent Inspector findings have reached
// Security Hub, from a sample of the newest findings in a few age windows
// looked up in Security Hub by ID. Security Hub doesn't ingest in order (it
// can process brand-new findings while an hours-old backlog waits), so a
// per-window sample is used instead of comparing newest timestamps.
type SecurityHubSync struct {
	Sampled int          `json:"sampled"`
	Missing int          `json:"missing"`
	Windows []SyncWindow `json:"windows"`
	// OldestMissingFirstObservedAt is the oldest sampled Inspector finding
	// Security Hub doesn't have yet (RFC 3339) — "Security Hub is missing
	// findings from as far back as ...".
	OldestMissingFirstObservedAt string `json:"oldest_missing_first_observed_at,omitempty"`
	Error                        string `json:"error,omitempty"`
}

// Report is the task result payload.
type Report struct {
	Region          string               `json:"region"`
	AccountID       string               `json:"account_id"`
	ResourceTypes   []ResourceTypeCounts `json:"resource_types"`
	SecurityHubSync *SecurityHubSync     `json:"securityhub_sync,omitempty"`
}

type inspectorAPI interface {
	ListFindingAggregations(context.Context, *inspector2.ListFindingAggregationsInput, ...func(*inspector2.Options)) (*inspector2.ListFindingAggregationsOutput, error)
	ListFindings(context.Context, *inspector2.ListFindingsInput, ...func(*inspector2.Options)) (*inspector2.ListFindingsOutput, error)
}

type securityHubAPI interface {
	GetFindings(context.Context, *securityhub.GetFindingsInput, ...func(*securityhub.Options)) (*securityhub.GetFindingsOutput, error)
}

type clients struct {
	insp    inspectorAPI
	sh      securityHubAPI
	region  string
	account string
}

// Task implements inspector_finding_counts.
type Task struct {
	clients func(ctx context.Context, region string) (clients, error)
	budget  time.Duration
}

func New() *Task {
	return &Task{
		clients: func(ctx context.Context, region string) (clients, error) {
			cfg, err := awshelper.LoadConfig(ctx, awshelper.Options{Region: region})
			if err != nil {
				return clients{}, err
			}
			id, err := sts.NewFromConfig(cfg).GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
			if err != nil {
				return clients{}, fmt.Errorf("get caller identity: %w", err)
			}
			return clients{insp: inspector2.NewFromConfig(cfg), sh: securityhub.NewFromConfig(cfg), region: cfg.Region, account: aws.ToString(id.Account)}, nil
		},
		budget: TimeBudget,
	}
}

func (t *Task) Name() string { return TaskName }

func (t *Task) Execute(ctx context.Context, rawPayload json.RawMessage) (*task.Result, error) {
	var p Payload
	if len(rawPayload) > 0 {
		if err := json.Unmarshal(rawPayload, &p); err != nil {
			return task.NewErrorResult(fmt.Sprintf("invalid payload: %v", err)), nil
		}
	}
	c, err := t.clients(ctx, p.Region)
	if err != nil {
		return nil, fmt.Errorf("failed to build AWS clients: %w", err)
	}
	ctx, cancel := context.WithTimeout(ctx, t.budget)
	defer cancel()

	rep := Report{Region: c.region, AccountID: c.account, ResourceTypes: make([]ResourceTypeCounts, len(ResourceTypes))}
	errs := make([]error, len(ResourceTypes))
	var wg sync.WaitGroup
	for i, rt := range ResourceTypes {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rep.ResourceTypes[i], errs[i] = countResourceType(ctx, c.insp, rt)
		}()
	}
	if !p.SkipSecurityHubSync {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rep.SecurityHubSync = sampleSync(ctx, c.insp, c.sh, now())
		}()
	}
	wg.Wait()

	failed := 0
	var firstErr error
	for i, err := range errs {
		if err != nil {
			failed++
			rep.ResourceTypes[i].Error = err.Error()
			if firstErr == nil {
				firstErr = err
			}
		}
	}
	if failed == len(ResourceTypes) {
		// Nothing to show: surface the real cause (e.g. AccessDenied on
		// inspector2:ListFindingAggregations) as a client-fault result, or a
		// real error for a server fault.
		return awshelper.WrapError("inspector finding counts", firstErr)
	}
	msg := fmt.Sprintf("Inspector finding counts for %d resource types (account %s, region %s)", len(ResourceTypes)-failed, c.account, c.region)
	return &task.Result{Success: true, Message: msg, Details: rep}, nil
}

func countResourceType(ctx context.Context, insp inspectorAPI, rt itypes.AggregationResourceType) (ResourceTypeCounts, error) {
	row := ResourceTypeCounts{ResourceType: string(rt)}
	out, err := insp.ListFindingAggregations(ctx, &inspector2.ListFindingAggregationsInput{
		AggregationType:    itypes.AggregationTypeAccount,
		AggregationRequest: &itypes.AggregationRequestMemberAccountAggregation{Value: itypes.AccountAggregation{ResourceType: rt}},
	})
	if err != nil {
		return row, err
	}
	for _, r := range out.Responses {
		a, ok := r.(*itypes.AggregationResponseMemberAccountAggregation)
		if !ok {
			continue
		}
		if sc := a.Value.SeverityCounts; sc != nil {
			row.SeverityCounts.All += aws.ToInt64(sc.All)
			row.SeverityCounts.Critical += aws.ToInt64(sc.Critical)
			row.SeverityCounts.High += aws.ToInt64(sc.High)
			row.SeverityCounts.Medium += aws.ToInt64(sc.Medium)
			row.SeverityCounts.Low += aws.ToInt64(sc.Low)
			row.SeverityCounts.Informational += aws.ToInt64(sc.Informational)
			row.SeverityCounts.Untriaged += aws.ToInt64(sc.Untriaged)
		}
		row.ExploitAvailable += aws.ToInt64(a.Value.ExploitAvailableCount)
		row.FixAvailable += aws.ToInt64(a.Value.FixAvailableCount)
	}
	return row, nil
}

// syncWindows are the sampled age windows (younger than 15 minutes is
// normal ingestion latency, not lag); samplePerWindow findings each, so the
// whole sample fits Security Hub's 20-values-per-filter limit in one call.
var syncWindows = []struct {
	label    string
	from, to time.Duration
}{
	{"15m-1h", 15 * time.Minute, time.Hour},
	{"1h-3h", time.Hour, 3 * time.Hour},
	{"3h-6h", 3 * time.Hour, 6 * time.Hour},
	{"6h-24h", 6 * time.Hour, 24 * time.Hour},
	{"24h-72h", 24 * time.Hour, 72 * time.Hour},
}

const samplePerWindow = 4

// now is the clock the sync sample measures ages against (a var for tests).
var now = time.Now

func sampleSync(ctx context.Context, insp inspectorAPI, sh securityHubAPI, at time.Time) *SecurityHubSync {
	out := &SecurityHubSync{Windows: make([]SyncWindow, len(syncWindows))}
	type sample struct {
		window int
		arn    string
		first  time.Time
	}
	var samples []sample
	for i, w := range syncWindows {
		out.Windows[i].Label = w.label
		res, err := insp.ListFindings(ctx, &inspector2.ListFindingsInput{
			MaxResults: aws.Int32(samplePerWindow),
			FilterCriteria: &itypes.FilterCriteria{
				FindingStatus:   []itypes.StringFilter{{Comparison: itypes.StringComparisonEquals, Value: aws.String("ACTIVE")}},
				FirstObservedAt: []itypes.DateFilter{{StartInclusive: aws.Time(at.Add(-w.to)), EndInclusive: aws.Time(at.Add(-w.from))}},
			},
			SortCriteria: &itypes.SortCriteria{Field: itypes.SortFieldFirstObservedAt, SortOrder: itypes.SortOrderDesc},
		})
		if err != nil {
			out.Error = "inspector: " + err.Error()
			return out
		}
		for _, f := range res.Findings {
			if f.FindingArn != nil {
				samples = append(samples, sample{window: i, arn: *f.FindingArn, first: aws.ToTime(f.FirstObservedAt)})
			}
		}
	}
	if len(samples) == 0 {
		return out // no recent Inspector findings: nothing for Security Hub to be missing
	}
	filters := make([]shtypes.StringFilter, 0, len(samples))
	for _, s := range samples {
		filters = append(filters, shtypes.StringFilter{Value: aws.String(s.arn), Comparison: shtypes.StringFilterComparisonEquals})
	}
	res, err := sh.GetFindings(ctx, &securityhub.GetFindingsInput{
		Filters:    &shtypes.AwsSecurityFindingFilters{Id: filters},
		MaxResults: aws.Int32(100),
	})
	if err != nil {
		out.Error = "securityhub: " + err.Error()
		return out
	}
	present := map[string]bool{}
	for _, f := range res.Findings {
		present[aws.ToString(f.Id)] = true
	}
	var oldest time.Time
	for _, s := range samples {
		out.Sampled++
		out.Windows[s.window].Sampled++
		if present[s.arn] {
			continue
		}
		out.Missing++
		out.Windows[s.window].Missing++
		if !s.first.IsZero() && (oldest.IsZero() || s.first.Before(oldest)) {
			oldest = s.first
		}
	}
	if !oldest.IsZero() {
		out.OldestMissingFirstObservedAt = oldest.UTC().Format(time.RFC3339)
	}
	return out
}
