// Package securityhub_get_insight_statistics gets exact Security Hub finding
// counts via an AWS Insight (GetInsightResults) rather than the
// capped-per-bucket or exhaustive-pagination approaches in
// securityhub_get_findings_statistics. Insight results are computed live by
// AWS on every GetInsightResults call — verified empirically against a real
// account (34,010 MEDIUM findings from an Insight matched an independent
// 19-page exhaustive GetFindings scan run at the same moment) — so counts
// are exact in a few calls, even for millions of findings.
//
// Custom Insights are a scarce, account-wide resource (100 per account and
// region, shared with every human and tool), so this task uses exactly ONE
// Insight per account and region — its "slot" — for every query:
//
//   - The slot is named "centcom-satellite-stats-<region>#<fingerprint>",
//     where the fingerprint identifies the query (group_by + a hash of the
//     normalized filter). An Insight's filter is part of the Insight, so the
//     name tells exactly which query the slot currently answers.
//   - A call whose query is already in the slot reads the results directly.
//     Otherwise it rewrites the slot (UpdateInsight: filters, group-by
//     attribute and fingerprinted name) and then reads the results.
//   - After reading, it reads the slot's name back. If another caller (a
//     second replica, or another satellite in the same account) rewrote the
//     slot in between, the results may belong to that caller's query, so it
//     retries (maxAttempts). Calls within one process are serialized per
//     region, so retries are only needed across processes.
//   - Once per process and region, it deletes this task's other Insights:
//     ones from older versions (one per group_by, region or filter) and
//     duplicate slots from a create race. DeleteInsight is commonly blocked
//     by account/org policy (verified empirically via an explicit SCP deny
//     even under AdministratorAccess); that is logged and otherwise ignored
//     — those slots then stay used, but no new ones are taken.
//
// Insights only ever see their own region's findings: the Region filter is
// always set (see securityhub_common.Filter.Region), because Security Hub's
// cross-region finding aggregation can otherwise merge every linked region's
// findings into one region's results.
package securityhub_get_insight_statistics

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/securityhub"
	"github.com/aws/aws-sdk-go-v2/service/securityhub/types"

	awshelper "github.com/loafoe/centcom-satellite/internal/aws"
	"github.com/loafoe/centcom-satellite/internal/task"
	shc "github.com/loafoe/centcom-satellite/internal/task/securityhub_common"
)

const TaskName = "securityhub_get_insight_statistics"

// insightNamePrefix identifies Insights this task owns (current slot and
// any left over from older versions), distinguishing them from a user's
// own custom Insights of the same account/region.
const insightNamePrefix = "centcom-satellite-stats-"

// maxAttempts bounds retries when another process rewrites the slot
// between our update and our read.
const maxAttempts = 3

// slotPrefix is the name prefix of the region's one slot.
func slotPrefix(region string) string {
	return insightNamePrefix + strings.ToLower(region) + "#"
}

// slotName is the slot's name while it answers (groupBy, filter).
func slotName(region, groupBy string, filter shc.Filter) string {
	return slotPrefix(region) + strings.ToLower(groupBy) + "-" + filterKey(filter)
}

// filterKey is a short, stable hash of filter. Filters that select the same
// findings hash the same: list order is irrelevant (values are OR'd) and an
// empty RecordState means ACTIVE.
func filterKey(filter shc.Filter) string {
	f := filter
	if f.RecordState == "" {
		f.RecordState = "ACTIVE"
	}
	for _, l := range []*[]string{&f.SeverityLabels, &f.Types, &f.WorkflowStatus, &f.ResourceIDs} {
		*l = slices.Clone(*l)
		slices.Sort(*l)
		*l = slices.Compact(*l)
	}
	b, _ := json.Marshal(f) // a struct of strings and string slices: cannot fail
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:6])
}

// groupByAttributes maps the same group_by vocabulary used by
// securityhub_get_findings_statistics to the Insight GroupByAttribute string
// AWS expects, keeping both tasks' payloads consistent for callers.
var groupByAttributes = map[string]string{
	"SEVERITY":        "SeverityLabel",
	"TYPE":            "Type",
	"WORKFLOW_STATUS": "WorkflowStatus",
	"PRODUCT":         "ProductName",
	"RESOURCE_TYPE":   "ResourceType",
	// Finding title (for Inspector: "<CVE> - <package>") and resource ID
	// (e.g. one ECR image or EC2 instance). AWS returns at most the top 100
	// values for an Insight, so these two can be truncated.
	"TITLE":       "Title",
	"RESOURCE_ID": "ResourceId",
}

// maxInsightValues is how many result values GetInsightResults returns at
// most; more distinct values than this means the result is truncated.
const maxInsightValues = 100

type api interface {
	GetInsights(context.Context, *securityhub.GetInsightsInput, ...func(*securityhub.Options)) (*securityhub.GetInsightsOutput, error)
	CreateInsight(context.Context, *securityhub.CreateInsightInput, ...func(*securityhub.Options)) (*securityhub.CreateInsightOutput, error)
	UpdateInsight(context.Context, *securityhub.UpdateInsightInput, ...func(*securityhub.Options)) (*securityhub.UpdateInsightOutput, error)
	DeleteInsight(context.Context, *securityhub.DeleteInsightInput, ...func(*securityhub.Options)) (*securityhub.DeleteInsightOutput, error)
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
// Truncated is set when AWS returned its maximum number of values
// (possible for TITLE / RESOURCE_ID): only the top values are listed and
// Total covers those only.
type Statistics struct {
	GroupBy    string          `json:"group_by"`
	InsightArn string          `json:"insight_arn"`
	Total      int32           `json:"total"`
	Truncated  bool            `json:"truncated,omitempty"`
	Counts     []shc.StatCount `json:"counts"`
}

type Task struct {
	// clientFactory returns the securityhub client plus the AWS region it
	// actually resolved to — Execute uses it both for the Region filter and
	// for the slot's name, so a Security Hub cross-region finding aggregator
	// can't leak other regions' findings into these counts.
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

// regionLocks serializes slot use per region within this process; cleaned
// records which regions' leftover Insights were already cleaned up.
var (
	regionLocksMu sync.Mutex
	regionLocks   = map[string]*sync.Mutex{}
	cleaned       = map[string]bool{}
)

func regionLock(region string) *sync.Mutex {
	regionLocksMu.Lock()
	defer regionLocksMu.Unlock()
	if regionLocks[region] == nil {
		regionLocks[region] = &sync.Mutex{}
	}
	return regionLocks[region]
}

func (t *Task) Execute(ctx context.Context, rawPayload json.RawMessage) (*task.Result, error) {
	var payload Payload
	if len(rawPayload) > 0 {
		if err := json.Unmarshal(rawPayload, &payload); err != nil {
			return task.NewErrorResult(fmt.Sprintf("invalid payload: %v", err)), nil
		}
	}

	groupByStr := strings.ToUpper(payload.GroupBy)
	if groupByStr == "" {
		groupByStr = "SEVERITY"
	}
	attribute, ok := groupByAttributes[groupByStr]
	if !ok {
		return task.NewErrorResult(fmt.Sprintf("unsupported group_by %q (allowed: SEVERITY, TYPE, WORKFLOW_STATUS, PRODUCT, RESOURCE_TYPE, TITLE, RESOURCE_ID)", groupByStr)), nil
	}

	client, resolvedRegion, err := t.clientFactory(ctx, payload.Region)
	if err != nil {
		return nil, fmt.Errorf("failed to build securityhub client: %w", err)
	}

	filter := payload.Filter.WithResolvedRegion(resolvedRegion)
	filters := filter.BuildFilters()
	name := slotName(resolvedRegion, groupByStr, filter)

	lock := regionLock(resolvedRegion)
	lock.Lock()
	defer lock.Unlock()

	for attempt := 1; ; attempt++ {
		arn, err := useSlot(ctx, client, resolvedRegion, name, attribute, filters)
		if err != nil {
			var limitExceeded *types.LimitExceededException
			if errors.As(err, &limitExceeded) {
				return task.NewErrorResult("cannot create the statistics insight: the account's custom insight quota (100 per region) is exhausted; use securityhub_get_findings_statistics instead"), nil
			}
			if isNotFound(err) && attempt < maxAttempts {
				continue // slot deleted under us (a duplicate cleaned up elsewhere)
			}
			return nil, fmt.Errorf("prepare insight: %w", err)
		}

		out, err := client.GetInsightResults(ctx, &securityhub.GetInsightResultsInput{InsightArn: aws.String(arn)})
		if err != nil {
			if isNotFound(err) && attempt < maxAttempts {
				continue
			}
			return nil, fmt.Errorf("get insight results: %w", err)
		}
		// The results are only ours if the slot still holds our query.
		current, err := insightNameOf(ctx, client, arn)
		if err != nil && !isNotFound(err) {
			return nil, fmt.Errorf("verify insight: %w", err)
		}
		if current != name {
			if attempt < maxAttempts {
				continue
			}
			return task.NewErrorResult("the statistics insight is busy (other callers keep changing it); retry in a few seconds"), nil
		}

		result := Statistics{GroupBy: groupByStr, InsightArn: arn, Counts: []shc.StatCount{}}
		if out.InsightResults != nil {
			for _, v := range out.InsightResults.ResultValues {
				count := aws.ToInt32(v.Count)
				result.Counts = append(result.Counts, shc.StatCount{Key: aws.ToString(v.GroupByAttributeValue), Count: count})
				result.Total += count
			}
			result.Truncated = len(out.InsightResults.ResultValues) >= maxInsightValues
		}
		msg := fmt.Sprintf("insight statistics grouped by %s: %d buckets", groupByStr, len(result.Counts))
		if result.Truncated {
			msg += fmt.Sprintf(" (top %d only)", maxInsightValues)
		}
		return task.NewSuccessResultWithDetails(msg, result), nil
	}
}

// useSlot returns the region's slot ARN with the slot set to answer name:
// it finds the slot (creating it if this task has none), rewrites it if it
// currently holds a different query, and — once per process and region —
// deletes this task's other, leftover Insights.
func useSlot(ctx context.Context, client api, region, name, attribute string, filters *types.AwsSecurityFindingFilters) (string, error) {
	var slot *types.Insight
	var leftovers []types.Insight
	var nextToken *string
	for {
		out, err := client.GetInsights(ctx, &securityhub.GetInsightsInput{NextToken: nextToken})
		if err != nil {
			return "", fmt.Errorf("get insights: %w", err)
		}
		for i := range out.Insights {
			in := out.Insights[i]
			n := aws.ToString(in.Name)
			switch {
			case slot == nil && strings.HasPrefix(n, slotPrefix(region)):
				slot = &in
			case strings.HasPrefix(n, insightNamePrefix):
				leftovers = append(leftovers, in)
			}
		}
		if aws.ToString(out.NextToken) == "" {
			break
		}
		nextToken = out.NextToken
	}

	var arn string
	switch {
	case slot == nil:
		created, err := client.CreateInsight(ctx, &securityhub.CreateInsightInput{
			Name: aws.String(name), GroupByAttribute: aws.String(attribute), Filters: filters,
		})
		if err != nil {
			return "", fmt.Errorf("create insight: %w", err)
		}
		arn = aws.ToString(created.InsightArn)
	case aws.ToString(slot.Name) != name:
		arn = aws.ToString(slot.InsightArn)
		if _, err := client.UpdateInsight(ctx, &securityhub.UpdateInsightInput{
			InsightArn: aws.String(arn), Name: aws.String(name), GroupByAttribute: aws.String(attribute), Filters: filters,
		}); err != nil {
			return "", fmt.Errorf("update insight: %w", err)
		}
	default:
		arn = aws.ToString(slot.InsightArn)
	}

	cleanupOnce(ctx, client, region, leftovers)
	return arn, nil
}

// cleanupOnce deletes leftover Insights of this task once per process and
// region, returning their quota slots. Failures (typically DeleteInsight
// denied by policy) are logged, never returned.
func cleanupOnce(ctx context.Context, client api, region string, leftovers []types.Insight) {
	regionLocksMu.Lock()
	done := cleaned[region]
	cleaned[region] = true
	regionLocksMu.Unlock()
	if done || len(leftovers) == 0 {
		return
	}
	deleted := 0
	for _, in := range leftovers {
		if _, err := client.DeleteInsight(ctx, &securityhub.DeleteInsightInput{InsightArn: in.InsightArn}); err != nil {
			slog.Warn("could not delete leftover statistics insight; it keeps using a custom insight slot",
				"region", region, "insight", aws.ToString(in.Name), "error", err)
			continue
		}
		deleted++
	}
	slog.Info("cleaned up leftover statistics insights", "region", region, "deleted", deleted, "found", len(leftovers))
}

// insightNameOf reads one Insight's current name.
func insightNameOf(ctx context.Context, client api, arn string) (string, error) {
	out, err := client.GetInsights(ctx, &securityhub.GetInsightsInput{InsightArns: []string{arn}})
	if err != nil {
		return "", err
	}
	if len(out.Insights) == 0 {
		return "", nil
	}
	return aws.ToString(out.Insights[0].Name), nil
}

func isNotFound(err error) bool {
	var nf *types.ResourceNotFoundException
	return errors.As(err, &nf)
}
