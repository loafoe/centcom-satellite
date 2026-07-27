// Package securityhub_get_findings_statistics aggregates Security Hub finding
// counts (by severity/type/workflow-status/product) for dashboard summary
// widgets. Security Hub has no server-side groupBy/statistics API (unlike
// GuardDuty's GetFindingsStatistics), so this task pages through GetFindings
// and aggregates client-side, exhaustively — every matching finding is
// counted, never a capped subset. A small inter-page delay keeps this safe
// against AWS's per-account GetFindings rate limit even on accounts with
// thousands of findings (dozens of pages): unlike CloudWatch/GuardDuty tasks
// that make one or a handful of calls per invocation, this one is genuinely
// call-heavy, so pacing is load-bearing here, not optional.
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
// one statistics scan. Empirically, AWS's GetFindings throttling limit sits
// somewhere around 40-50 back-to-back requests (observed via the AWS CLI
// against a real account with ~4,700 findings / ~47 pages); this delay keeps
// a full scan of an account that size well under that threshold without
// relying solely on the SDK's default retry-after-throttle behavior.
const interPageDelay = 200 * time.Millisecond

var groupByExtractors = map[string]func(types.AwsSecurityFinding) string{
	"SEVERITY": func(f types.AwsSecurityFinding) string {
		if f.Severity == nil {
			return ""
		}
		return string(f.Severity.Label)
	},
	"TYPE": func(f types.AwsSecurityFinding) string {
		if len(f.Types) == 0 {
			return ""
		}
		return f.Types[0]
	},
	"WORKFLOW_STATUS": func(f types.AwsSecurityFinding) string {
		if f.Workflow == nil {
			return ""
		}
		return string(f.Workflow.Status)
	},
	"PRODUCT": func(f types.AwsSecurityFinding) string {
		return aws.ToString(f.ProductName)
	},
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

// Statistics is the task result payload. Counts are always exhaustive over
// every finding matching the filter — there is no truncation or partial-scan
// case to represent.
type Statistics struct {
	GroupBy string          `json:"group_by"`
	Total   int32           `json:"total"`
	Counts  []shc.StatCount `json:"counts"`
}

type Task struct {
	clientFactory func(ctx context.Context, region string) (api, error)
	sleep         func(ctx context.Context, d time.Duration)
}

func New() *Task {
	return &Task{
		clientFactory: func(ctx context.Context, region string) (api, error) {
			cfg, err := awshelper.LoadConfig(ctx, awshelper.Options{Region: region})
			if err != nil {
				return nil, err
			}
			return securityhub.NewFromConfig(cfg), nil
		},
		sleep: ctxSleep,
	}
}

func NewWithClientFactory(f func(ctx context.Context, region string) (api, error)) *Task {
	return &Task{clientFactory: f, sleep: ctxSleep}
}

// NewWithClientFactoryAndSleep is the test seam: injects a no-op or
// instrumented sleep so pagination tests don't actually wait interPageDelay
// per page.
func NewWithClientFactoryAndSleep(f func(ctx context.Context, region string) (api, error), sleep func(ctx context.Context, d time.Duration)) *Task {
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
	extract, ok := groupByExtractors[groupByStr]
	if !ok {
		return task.NewErrorResult(fmt.Sprintf("unsupported group_by %q (allowed: SEVERITY, TYPE, WORKFLOW_STATUS, PRODUCT)", groupByStr)), nil
	}

	client, err := t.clientFactory(ctx, payload.Region)
	if err != nil {
		return nil, fmt.Errorf("failed to build securityhub client: %w", err)
	}

	counts := map[string]int32{}
	result := Statistics{GroupBy: groupByStr, Counts: []shc.StatCount{}}

	var nextToken *string
	for page := 0; ; page++ {
		if page > 0 {
			t.sleep(ctx, interPageDelay)
			if ctx.Err() != nil {
				return nil, fmt.Errorf("get findings: %w", ctx.Err())
			}
		}

		input := &securityhub.GetFindingsInput{
			Filters:    payload.Filter.BuildFilters(),
			MaxResults: aws.Int32(pageSize),
		}
		if nextToken != nil {
			input.NextToken = nextToken
		}

		out, err := client.GetFindings(ctx, input)
		if err != nil {
			return nil, fmt.Errorf("get findings: %w", err)
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

	return task.NewSuccessResultWithDetails(fmt.Sprintf("statistics grouped by %s: %d buckets", groupByStr, len(result.Counts)), result), nil
}
