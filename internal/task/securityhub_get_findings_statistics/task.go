// Package securityhub_get_findings_statistics aggregates Security Hub finding
// counts (by severity/type/workflow-status/product) for dashboard summary
// widgets. Security Hub has no server-side groupBy/statistics API (unlike
// GuardDuty's GetFindingsStatistics), so this task pages through GetFindings
// and aggregates client-side, capped to bound cost and latency.
package securityhub_get_findings_statistics

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/securityhub"
	"github.com/aws/aws-sdk-go-v2/service/securityhub/types"

	awshelper "github.com/loafoe/centcom-satellite/internal/aws"
	"github.com/loafoe/centcom-satellite/internal/task"
	shc "github.com/loafoe/centcom-satellite/internal/task/securityhub_common"
)

const TaskName = "securityhub_get_findings_statistics"

// maxPages caps how many GetFindings pages are aggregated per call (10 pages
// x 100 findings/page = up to 1,000 findings), bounding latency/cost. Hitting
// the cap sets Statistics.Truncated so callers know the counts are a lower
// bound, not silently partial data presented as complete.
const maxPages = 10

const pageSize int32 = 100

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

// Statistics is the task result payload.
type Statistics struct {
	GroupBy   string          `json:"group_by"`
	Total     int32           `json:"total"`
	Counts    []shc.StatCount `json:"counts"`
	Truncated bool            `json:"truncated,omitempty"`
	NextToken string          `json:"next_token,omitempty"`
}

type Task struct {
	clientFactory func(ctx context.Context, region string) (api, error)
}

func New() *Task {
	return &Task{clientFactory: func(ctx context.Context, region string) (api, error) {
		cfg, err := awshelper.LoadConfig(ctx, awshelper.Options{Region: region})
		if err != nil {
			return nil, err
		}
		return securityhub.NewFromConfig(cfg), nil
	}}
}

func NewWithClientFactory(f func(ctx context.Context, region string) (api, error)) *Task {
	return &Task{clientFactory: f}
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
	for page := 0; page < maxPages; page++ {
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

		if page == maxPages-1 {
			result.Truncated = true
			result.NextToken = aws.ToString(nextToken)
		}
	}

	for key, count := range counts {
		result.Counts = append(result.Counts, shc.StatCount{Key: key, Count: count})
	}

	return task.NewSuccessResultWithDetails(fmt.Sprintf("statistics grouped by %s: %d buckets", groupByStr, len(result.Counts)), result), nil
}
