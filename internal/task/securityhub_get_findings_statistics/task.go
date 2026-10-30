// Package securityhub_get_findings_statistics aggregates Security Hub finding
// counts (by severity/type/workflow-status/product) for dashboard summary
// widgets. Security Hub has no server-side groupBy/statistics API (unlike
// GuardDuty's GetFindingsStatistics).
//
// SEVERITY and WORKFLOW_STATUS are closed enums (5 and 4 known values), so
// each bucket is queried directly: one GetFindings call per value with
// MaxResults capped at pageSize and no further pagination. This trades exact
// totals for speed — a bucket's count is reported as Capped when the query
// returned a NextToken, meaning there are more than pageSize findings in that
// bucket. This is intentionally a UI-summary approximation; exhaustive counts
// remain available via the securityhub_get_findings task (paginated) or the
// UI/MCP tooling built on it.
//
// TYPE, PRODUCT and RESOURCE_TYPE are open-ended free-form strings with no enumerable value
// set, so they keep the exhaustive client-side aggregation: page through
// GetFindings and count every matching finding, paced by interPageDelay to
// stay under AWS's throttling limit.
package securityhub_get_findings_statistics

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/securityhub"
	"github.com/aws/aws-sdk-go-v2/service/securityhub/types"

	awshelper "github.com/loafoe/centcom-satellite/internal/aws"
	"github.com/loafoe/centcom-satellite/internal/task"
	shc "github.com/loafoe/centcom-satellite/internal/task/securityhub_common"
)

const TaskName = "securityhub_get_findings_statistics"

const pageSize int32 = 100

// interPageDelay is a fixed pause between successive GetFindings calls within
// an exhaustive (TYPE/PRODUCT) scan. Empirically, AWS's GetFindings
// throttling limit sits somewhere around 40-50 back-to-back requests
// (observed via the AWS CLI against a real account with ~4,700 findings /
// ~47 pages); this delay keeps a full scan of an account that size well
// under that threshold without relying solely on the SDK's default
// retry-after-throttle behavior.
const interPageDelay = 200 * time.Millisecond

// defaultExhaustiveScanBudget bounds how long exhaustiveStats (TYPE/PRODUCT/
// RESOURCE_TYPE/TITLE/RESOURCE_ID group_by) pages through GetFindings before
// giving up and returning a partial, Truncated result instead of a hard
// error. Hit live 2026-10-30: an unfiltered group_by=TITLE scan on a real
// account (ops-sandbox) was still paging past 25s when deliberately cut off,
// and a real run ran a full 4m59s before an external caller's own 5-minute
// timeout killed it with no result at all (hermes-agent's hardcoded MCP
// tool-call timeout) — the task itself had no budget of its own. 45s matches
// the CloudTrail tasks' own time-budget convention and leaves ample margin
// under both the satellite's HTTP write timeout and any caller's timeout.
const defaultExhaustiveScanBudget = 45 * time.Second

// groupByExtractors covers the exhaustive-scan group_by values (TYPE,
// PRODUCT, RESOURCE_TYPE): open-ended strings with no fixed value set to query per-bucket.
var groupByExtractors = map[string]func(types.AwsSecurityFinding) string{
	"TYPE": func(f types.AwsSecurityFinding) string {
		if len(f.Types) == 0 {
			return ""
		}
		return f.Types[0]
	},
	"PRODUCT": func(f types.AwsSecurityFinding) string {
		return aws.ToString(f.ProductName)
	},
	// The first resource, like the console's and the CLI's
	// Findings[].Resources[0].Type.
	"RESOURCE_TYPE": func(f types.AwsSecurityFinding) string {
		if len(f.Resources) == 0 {
			return ""
		}
		return aws.ToString(f.Resources[0].Type)
	},
	"TITLE": func(f types.AwsSecurityFinding) string {
		return aws.ToString(f.Title)
	},
	"RESOURCE_ID": func(f types.AwsSecurityFinding) string {
		if len(f.Resources) == 0 {
			return ""
		}
		return aws.ToString(f.Resources[0].Id)
	},
}

// severityBuckets are the fixed SeverityLabel values queried directly when
// group_by=SEVERITY.
var severityBuckets = []string{
	string(types.SeverityLabelInformational),
	string(types.SeverityLabelLow),
	string(types.SeverityLabelMedium),
	string(types.SeverityLabelHigh),
	string(types.SeverityLabelCritical),
}

// workflowStatusBuckets are the fixed WorkflowStatus values queried directly
// when group_by=WORKFLOW_STATUS.
var workflowStatusBuckets = []string{
	string(types.WorkflowStatusNew),
	string(types.WorkflowStatusNotified),
	string(types.WorkflowStatusResolved),
	string(types.WorkflowStatusSuppressed),
}

type api interface {
	GetFindings(context.Context, *securityhub.GetFindingsInput, ...func(*securityhub.Options)) (*securityhub.GetFindingsOutput, error)
}

// Payload for securityhub_get_findings_statistics.
type Payload struct {
	Region  string     `json:"region,omitempty"`
	Filter  shc.Filter `json:"filter,omitempty"`
	GroupBy string     `json:"group_by,omitempty"` // default SEVERITY
}

// Statistics is the task result payload. For SEVERITY/WORKFLOW_STATUS, a
// bucket's Count may be capped at pageSize (see StatCount.Capped) rather than
// exhaustive; for TYPE/PRODUCT, counts are always exhaustive over every
// finding matching the filter. Total sums the (possibly capped) bucket
// counts, so it is a lower bound whenever any bucket is capped. Truncated
// is set when an exhaustive (TYPE/PRODUCT/RESOURCE_TYPE/TITLE/RESOURCE_ID)
// scan hit defaultExhaustiveScanBudget before finishing — Total/Counts then
// cover only the findings seen before the budget ran out, a lower bound
// like a capped bucket. Narrow the filter (e.g. title_prefix) to make an
// exhaustive group_by finish within budget.
type Statistics struct {
	GroupBy   string          `json:"group_by"`
	Total     int32           `json:"total"`
	Truncated bool            `json:"truncated,omitempty"`
	Counts    []shc.StatCount `json:"counts"`
}

type Task struct {
	// clientFactory returns the securityhub client plus the AWS region it
	// actually resolved to — Execute uses that to constrain results via
	// Filter.Region so a Security Hub cross-region finding aggregator can't
	// silently leak other regions' findings into these buckets. See
	// securityhub_common.Filter.Region's doc comment.
	clientFactory func(ctx context.Context, region string) (api, string, error)
	sleep         func(ctx context.Context, d time.Duration)
	// scanBudget overrides defaultExhaustiveScanBudget when set (test seam).
	scanBudget time.Duration
}

func New() *Task {
	return &Task{
		clientFactory: func(ctx context.Context, region string) (api, string, error) {
			cfg, err := awshelper.LoadConfig(ctx, awshelper.Options{Region: region})
			if err != nil {
				return nil, "", err
			}
			return securityhub.NewFromConfig(cfg), cfg.Region, nil
		},
		sleep: ctxSleep,
	}
}

func NewWithClientFactory(f func(ctx context.Context, region string) (api, string, error)) *Task {
	return &Task{clientFactory: f, sleep: ctxSleep}
}

// NewWithClientFactoryAndSleep is the test seam: injects a no-op or
// instrumented sleep so pagination tests don't actually wait interPageDelay
// per page.
func NewWithClientFactoryAndSleep(f func(ctx context.Context, region string) (api, string, error), sleep func(ctx context.Context, d time.Duration)) *Task {
	return &Task{clientFactory: f, sleep: sleep}
}

// ctxSleep pauses for d or until ctx is cancelled, whichever comes first —
// so a cancelled request doesn't sit through the remainder of a long scan's
// inter-page delays.
func ctxSleep(ctx context.Context, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
	case <-ctx.Done():
	}
}

func (t *Task) Name() string { return TaskName }

func (t *Task) Execute(ctx context.Context, rawPayload json.RawMessage) (*task.Result, error) {
	var payload Payload
	if len(rawPayload) > 0 {
		if err := json.Unmarshal(rawPayload, &payload); err != nil {
			return task.NewErrorResult(fmt.Sprintf("invalid payload: %v", err)), nil
		}
	}

	groupByStr := payload.GroupBy
	if groupByStr == "" {
		groupByStr = "SEVERITY"
	}

	client, resolvedRegion, err := t.clientFactory(ctx, payload.Region)
	if err != nil {
		return nil, fmt.Errorf("failed to build securityhub client: %w", err)
	}
	filter := payload.Filter.WithResolvedRegion(resolvedRegion)

	var result Statistics
	switch groupByStr {
	case "SEVERITY":
		result, err = t.cappedBucketStats(ctx, client, filter, groupByStr, severityBuckets, addSeverityLabelFilter)
	case "WORKFLOW_STATUS":
		result, err = t.cappedBucketStats(ctx, client, filter, groupByStr, workflowStatusBuckets, addWorkflowStatusFilter)
	default:
		extract, ok := groupByExtractors[groupByStr]
		if !ok {
			return task.NewErrorResult(fmt.Sprintf("unsupported group_by %q (allowed: SEVERITY, TYPE, WORKFLOW_STATUS, PRODUCT, RESOURCE_TYPE, TITLE, RESOURCE_ID)", groupByStr)), nil
		}
		result, err = t.exhaustiveStats(ctx, client, filter, groupByStr, extract)
	}
	if err != nil {
		return awshelper.WrapError("get findings statistics", err)
	}

	msg := fmt.Sprintf("statistics grouped by %s: %d buckets", groupByStr, len(result.Counts))
	if result.Truncated {
		msg += " (partial — scan time-bounded; narrow the filter, e.g. title_prefix, for an exact count)"
	}
	return task.NewSuccessResultWithDetails(msg, result), nil
}

// addSeverityLabelFilter and addWorkflowStatusFilter constrain an
// already-built AwsSecurityFindingFilters to one bucket value, on top of
// whatever the caller's own filter already specifies.
func addSeverityLabelFilter(f *types.AwsSecurityFindingFilters, value string) {
	f.SeverityLabel = []types.StringFilter{equalsFilter(value)}
}

func addWorkflowStatusFilter(f *types.AwsSecurityFindingFilters, value string) {
	f.WorkflowStatus = []types.StringFilter{equalsFilter(value)}
}

func equalsFilter(value string) types.StringFilter {
	return types.StringFilter{Value: aws.String(value), Comparison: types.StringFilterComparisonEquals}
}

// cappedBucketStats queries each known bucket value directly (one GetFindings
// call per bucket, MaxResults=pageSize, no further pagination). A bucket's
// Count is capped at pageSize when the response includes a NextToken.
func (t *Task) cappedBucketStats(ctx context.Context, client api, filter shc.Filter, groupBy string, buckets []string, constrain func(*types.AwsSecurityFindingFilters, string)) (Statistics, error) {
	result := Statistics{GroupBy: groupBy, Counts: []shc.StatCount{}}

	for _, bucket := range buckets {
		filters := filter.BuildFilters()
		constrain(filters, bucket)

		out, err := client.GetFindings(ctx, &securityhub.GetFindingsInput{
			Filters:    filters,
			MaxResults: aws.Int32(pageSize),
		})
		if err != nil {
			return Statistics{}, fmt.Errorf("get findings: %w", err)
		}

		count := int32(len(out.Findings))
		if count == 0 {
			continue
		}
		capped := out.NextToken != nil && aws.ToString(out.NextToken) != ""
		result.Counts = append(result.Counts, shc.StatCount{Key: bucket, Count: count, Capped: capped})
		result.Total += count
	}

	return result, nil
}

// exhaustiveStats pages through every matching finding and aggregates counts
// client-side — used for TYPE/PRODUCT, which have no fixed value set to query
// per-bucket the way SEVERITY/WORKFLOW_STATUS do. Bounded by scanBudget (see
// defaultExhaustiveScanBudget): once it elapses, pagination stops and the
// result is returned as a partial, Truncated count rather than continuing to
// page (potentially for minutes on an account with many findings and no
// narrowing filter) or erroring out with nothing to show.
func (t *Task) exhaustiveStats(ctx context.Context, client api, filter shc.Filter, groupBy string, extract func(types.AwsSecurityFinding) string) (Statistics, error) {
	budget := t.scanBudget
	if budget <= 0 {
		budget = defaultExhaustiveScanBudget
	}
	scanCtx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()

	counts := map[string]int32{}
	result := Statistics{GroupBy: groupBy, Counts: []shc.StatCount{}}

	var nextToken *string
	for page := 0; ; page++ {
		if page > 0 {
			t.sleep(scanCtx, interPageDelay)
			if scanCtx.Err() != nil {
				if ctx.Err() != nil {
					return Statistics{}, fmt.Errorf("get findings: %w", ctx.Err())
				}
				result.Truncated = true
				break
			}
		}

		input := &securityhub.GetFindingsInput{
			Filters:    filter.BuildFilters(),
			MaxResults: aws.Int32(pageSize),
		}
		if nextToken != nil {
			input.NextToken = nextToken
		}

		out, err := client.GetFindings(scanCtx, input)
		if err != nil {
			if scanCtx.Err() != nil && ctx.Err() == nil {
				// Our own scan budget elapsed mid-call, not the caller's own
				// context — a partial result, not a failure.
				result.Truncated = true
				break
			}
			return Statistics{}, fmt.Errorf("get findings: %w", err)
		}
		for _, f := range out.Findings {
			key := extract(f)
			counts[key]++
			result.Total++
		}

		if out.NextToken == nil || aws.ToString(out.NextToken) == "" {
			break
		}
		nextToken = out.NextToken
	}

	for key, count := range counts {
		result.Counts = append(result.Counts, shc.StatCount{Key: key, Count: count})
	}

	return result, nil
}
