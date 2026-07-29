// Package securityhub_get_insight_statistics gets exact Security Hub finding
// counts via a reused, named Insight (CreateInsight + GetInsightResults)
// rather than the capped-per-bucket or exhaustive-pagination approaches in
// securityhub_get_findings_statistics. Insight results are computed live by
// AWS on every GetInsightResults call — verified empirically against a real
// account (34,010 MEDIUM findings from an Insight matched an independent
// 19-page exhaustive GetFindings scan run at the same moment) — so this task
// trades one extra one-time CreateInsight call for exact, uncapped counts in
// a small, fixed number of calls per request thereafter.
//
// The Insight is found-or-created by a deterministic name
// ("centcom-satellite-stats-<group_by>-<region>", lowercased, where <region>
// is the AWS region the client factory actually resolved to — see
// insightName) and reused across calls to the same (group_by, region) rather
// than recreated every time. The region is baked into both the name and the
// Insight's Filters (see securityhub_common.Filter.Region): Security Hub's
// cross-region finding aggregation means an Insight's GetInsightResults can
// otherwise silently include findings from every linked region, not just
// the one this satellite runs in — and since matching is by name alone, an
// older Insight created before this region-scoping existed must never be
// matched and reused with its stale, unregioned filter. AWS does not enforce
// unique Insight names (verified empirically: calling CreateInsight twice
// with the same name creates two distinct Insights), so on a name collision
// this task uses the first match by list order and leaves any extras alone
// rather than erroring or attempting cleanup. DeleteInsight is commonly
// blocked by account/org policy (verified empirically via an explicit SCP
// deny even under AdministratorAccess), so this task never deletes an
// Insight — Insights it creates are meant to be permanent, reused
// infrastructure, not scoped to one request's lifetime.
package securityhub_get_insight_statistics

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/securityhub"
	"github.com/aws/aws-sdk-go-v2/service/securityhub/types"

	awshelper "github.com/loafoe/centcom-satellite/internal/aws"
	"github.com/loafoe/centcom-satellite/internal/task"
	shc "github.com/loafoe/centcom-satellite/internal/task/securityhub_common"
)

const TaskName = "securityhub_get_insight_statistics"

// insightNamePrefix identifies Insights this task owns, distinguishing them
// from a user's own custom Insights of the same account/region.
const insightNamePrefix = "centcom-satellite-stats-"

// insightName returns the deterministic name for a (group_by, region) pair.
// The region is part of the name — not just the Filters — because
// findOrCreateInsight matches by name alone: an Insight created before this
// task applied a Region filter (or one created against a different resolved
// region) must never be matched and reused with the wrong scope. Baking the
// region into the name guarantees a stale, unregioned Insight is left
// untouched and a fresh, correctly-filtered one is created instead.
func insightName(groupBy, region string) string {
	return insightNamePrefix + strings.ToLower(groupBy) + "-" + strings.ToLower(region)
}

// groupByAttributes maps the same group_by vocabulary used by
// securityhub_get_findings_statistics to the Insight GroupByAttribute string
// AWS expects, keeping both tasks' payloads consistent for callers.
var groupByAttributes = map[string]string{
	"SEVERITY":        "SeverityLabel",
	"TYPE":            "Type",
	"WORKFLOW_STATUS": "WorkflowStatus",
	"PRODUCT":         "ProductName",
}

type api interface {
	GetInsights(context.Context, *securityhub.GetInsightsInput, ...func(*securityhub.Options)) (*securityhub.GetInsightsOutput, error)
	CreateInsight(context.Context, *securityhub.CreateInsightInput, ...func(*securityhub.Options)) (*securityhub.CreateInsightOutput, error)
	GetInsightResults(context.Context, *securityhub.GetInsightResultsInput, ...func(*securityhub.Options)) (*securityhub.GetInsightResultsOutput, error)
}

// Payload for securityhub_get_insight_statistics.
type Payload struct {
	Region  string     `json:"region,omitempty"`
	Filter  shc.Filter `json:"filter,omitempty"`
	GroupBy string     `json:"group_by,omitempty"` // default SEVERITY
}

// Statistics is the task result payload. Unlike
// securityhub_get_findings_statistics, counts here are always exact —
// Insight results have no per-bucket cap — so there is no Capped field.
type Statistics struct {
	GroupBy    string          `json:"group_by"`
	InsightArn string          `json:"insight_arn"`
	Total      int32           `json:"total"`
	Counts     []shc.StatCount `json:"counts"`
}

type Task struct {
	// clientFactory returns the securityhub client plus the AWS region it
	// actually resolved to — Execute both constrains the Insight's Filters to
	// that region (see securityhub_common.Filter.Region) and folds it into
	// the Insight's name (see insightName), so a Security Hub cross-region
	// finding aggregator can't leak other regions' findings into these
	// counts.
	clientFactory func(ctx context.Context, region string) (api, string, error)
}

func New() *Task {
	return &Task{clientFactory: func(ctx context.Context, region string) (api, string, error) {
		cfg, err := awshelper.LoadConfig(ctx, awshelper.Options{Region: region})
		if err != nil {
			return nil, "", err
		}
		return securityhub.NewFromConfig(cfg), cfg.Region, nil
	}}
}

func NewWithClientFactory(f func(ctx context.Context, region string) (api, string, error)) *Task {
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
	attribute, ok := groupByAttributes[groupByStr]
	if !ok {
		return task.NewErrorResult(fmt.Sprintf("unsupported group_by %q (allowed: SEVERITY, TYPE, WORKFLOW_STATUS, PRODUCT)", groupByStr)), nil
	}

	client, resolvedRegion, err := t.clientFactory(ctx, payload.Region)
	if err != nil {
		return nil, fmt.Errorf("failed to build securityhub client: %w", err)
	}

	name := insightName(groupByStr, resolvedRegion)
	filters := payload.Filter.WithResolvedRegion(resolvedRegion).BuildFilters()
	insightArn, err := findOrCreateInsight(ctx, client, name, attribute, filters)
	if err != nil {
		var limitExceeded *types.LimitExceededException
		if errors.As(err, &limitExceeded) {
			return task.NewErrorResult(fmt.Sprintf("cannot create insight %q: account's custom insight quota is exhausted; use securityhub_get_findings_statistics instead", name)), nil
		}
		return nil, fmt.Errorf("find or create insight: %w", err)
	}

	out, err := client.GetInsightResults(ctx, &securityhub.GetInsightResultsInput{InsightArn: aws.String(insightArn)})
	if err != nil {
		return nil, fmt.Errorf("get insight results: %w", err)
	}

	result := Statistics{GroupBy: groupByStr, InsightArn: insightArn, Counts: []shc.StatCount{}}
	if out.InsightResults != nil {
		for _, v := range out.InsightResults.ResultValues {
			count := aws.ToInt32(v.Count)
			result.Counts = append(result.Counts, shc.StatCount{Key: aws.ToString(v.GroupByAttributeValue), Count: count})
			result.Total += count
		}
	}

	return task.NewSuccessResultWithDetails(fmt.Sprintf("insight statistics grouped by %s: %d buckets", groupByStr, len(result.Counts)), result), nil
}

// findOrCreateInsight returns the ARN of the first existing custom Insight
// named name, or creates one with the given group-by attribute and filters
// if none exists. AWS does not enforce unique Insight names, so on multiple
// matches (e.g. a rare create race) this deterministically uses the first
// one returned by GetInsights and leaves any others untouched.
func findOrCreateInsight(ctx context.Context, client api, name, attribute string, filters *types.AwsSecurityFindingFilters) (string, error) {
	var nextToken *string
	for {
		out, err := client.GetInsights(ctx, &securityhub.GetInsightsInput{NextToken: nextToken})
		if err != nil {
			return "", fmt.Errorf("get insights: %w", err)
		}
		for _, insight := range out.Insights {
			if aws.ToString(insight.Name) == name {
				return aws.ToString(insight.InsightArn), nil
			}
		}
		if out.NextToken == nil || aws.ToString(out.NextToken) == "" {
			break
		}
		nextToken = out.NextToken
	}

	created, err := client.CreateInsight(ctx, &securityhub.CreateInsightInput{
		Name:             aws.String(name),
		GroupByAttribute: aws.String(attribute),
		Filters:          filters,
	})
	if err != nil {
		return "", fmt.Errorf("create insight: %w", err)
	}
	return aws.ToString(created.InsightArn), nil
}
