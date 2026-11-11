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
// region, shared with every human and tool), so this task caps itself at a
// small, bounded pool of Insights per account and region (maxSlots) — its
// "slots" — rather than claiming the whole quota:
//
//   - Each slot is named "centcom-satellite-stats-<region>#<fingerprint>",
//     where the fingerprint identifies the query (group_by + a hash of the
//     normalized filter). An Insight's filter is part of the Insight, so the
//     name tells exactly which query a slot currently answers.
//   - A call whose query already has a matching slot reads its results
//     directly — no CreateInsight/UpdateInsight, just GetInsightResults.
//     This is what makes switching between a handful of recurring queries
//     (e.g. a dashboard's severity tabs) cheap after the first visit to
//     each: distinct queries get distinct, persistent slots instead of
//     evicting each other on every switch.
//   - A call for a new query reuses a free slot if one exists below
//     maxSlots, or rewrites the least-recently-used slot (UpdateInsight)
//     once the pool is full — "recently used" is tracked in-process (an
//     Insight itself has no last-read timestamp), so this LRU state does
//     not survive a restart and is independent per replica.
//   - After reading, it reads the slot's name back. If another caller (a
//     second replica, or another satellite in the same account) rewrote the
//     slot in between, the results may belong to that caller's query, so it
//     retries (maxAttempts). Calls within one process are serialized per
//     region, so retries are only needed across processes.
//   - Once per process and region, it deletes this task's other Insights:
//     ones from older versions (a different naming scheme) and any slots
//     beyond maxSlots (e.g. left over from a lower cap in a previous
//     release, or a create race). DeleteInsight is commonly blocked by
//     account/org policy (verified empirically via an explicit SCP deny
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
	"sort"
	"strings"
	"sync"
	"time"

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

// maxSlots bounds how many Insights this task keeps per account and region
// — enough for a dashboard's handful of recurring queries (e.g. one
// SEVERITY overview plus one RESOURCE_TYPE breakdown per severity tab) to
// each get their own persistent slot, while staying a small, fixed
// allocation against the shared 100-per-region quota.
const maxSlots = 8

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
	// Resource ID (e.g. one ECR image or EC2 instance). AWS returns at most
	// the top 100 values for an Insight, so this can be truncated.
	//
	// TITLE is deliberately absent: AWS rejects "Title" as an Insight
	// GroupByAttribute (CreateInsight/UpdateInsight both fail with
	// InvalidInputException: Invalid Aggregations — confirmed live against
	// two real accounts), unlike every attribute above. To search or count
	// findings by title, use the filter's title_prefix (AWS's native
	// Title/PREFIX comparison, e.g. "CVE-2026") on this task, on
	// securityhub_get_findings, or on securityhub_get_findings_statistics
	// (whose TYPE/PRODUCT/RESOURCE_TYPE/TITLE/RESOURCE_ID group_by values are
	// a separate, client-side aggregation that AWS's Insight restriction does
	// not apply to).
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
// (possible for RESOURCE_ID): only the top values are listed and Total
// covers those only.
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
// lastUsed tracks, per slot ARN, when this process last read or wrote it —
// the LRU key for eviction once a region's pool is at maxSlots. Insights
// carry no last-read timestamp of their own, so this is process-local and
// does not survive a restart (acceptable: it only affects which slot gets
// reused first, never correctness).
var (
	regionLocksMu sync.Mutex
	regionLocks   = map[string]*sync.Mutex{}
	cleaned       = map[string]bool{}

	lastUsedMu sync.Mutex
	lastUsed   = map[string]time.Time{}
)

func touchLastUsed(arn string) {
	lastUsedMu.Lock()
	lastUsed[arn] = time.Now()
	lastUsedMu.Unlock()
}

func lastUsedAt(arn string) time.Time {
	lastUsedMu.Lock()
	defer lastUsedMu.Unlock()
	return lastUsed[arn] // zero value for an ARN never seen by this process
}

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
		return task.NewErrorResult(fmt.Sprintf("unsupported group_by %q (allowed: SEVERITY, TYPE, WORKFLOW_STATUS, PRODUCT, RESOURCE_TYPE, RESOURCE_ID; TITLE is not supported by AWS Insights — use filter.title_prefix instead, or securityhub_get_findings_statistics's group_by=TITLE)", groupByStr)), nil
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
			if (isNotFound(err) || isConflict(err)) && attempt < maxAttempts {
				// isNotFound: slot deleted under us (a duplicate cleaned up
				// elsewhere). isConflict: another replica's CreateInsight for
				// this exact query (same name) landed first — AWS enforces
				// unique Insight names per account/region, so our own
				// CreateInsight lost the race; re-listing on retry finds and
				// reuses the slot the winner just created, same outcome as
				// if we'd won.
				continue
			}
			return awshelper.WrapError("prepare insight", err)
		}

		out, err := client.GetInsightResults(ctx, &securityhub.GetInsightResultsInput{InsightArn: aws.String(arn)})
		if err != nil {
			if isNotFound(err) && attempt < maxAttempts {
				continue
			}
			return awshelper.WrapError("get insight results", err)
		}
		// The results are only ours if the slot still holds our query.
		current, err := insightNameOf(ctx, client, arn)
		if err != nil && !isNotFound(err) {
			return awshelper.WrapError("verify insight", err)
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

// useSlot returns a slot ARN set to answer name: an exact-match existing
// slot is reused as-is (no AWS write at all); otherwise a free slot is
// created, or — once the region's pool is at maxSlots — the
// least-recently-used slot is rewritten (UpdateInsight) to answer the new
// query. Once per process and region, it also deletes this task's other,
// leftover Insights (old naming scheme, or more than maxSlots own-region
// slots found at startup).
func useSlot(ctx context.Context, client api, region, name, attribute string, filters *types.AwsSecurityFindingFilters) (string, error) {
	var ours []types.Insight
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
			case strings.HasPrefix(n, slotPrefix(region)):
				ours = append(ours, in)
			case strings.HasPrefix(n, insightNamePrefix):
				leftovers = append(leftovers, in)
			}
		}
		if aws.ToString(out.NextToken) == "" {
			break
		}
		nextToken = out.NextToken
	}

	// More own-region slots than the current cap allows (e.g. left over
	// from a higher cap in a previous release): keep the first maxSlots
	// (stable order), the rest become leftovers for cleanup below.
	sort.Slice(ours, func(i, j int) bool { return aws.ToString(ours[i].InsightArn) < aws.ToString(ours[j].InsightArn) })
	if len(ours) > maxSlots {
		leftovers = append(leftovers, ours[maxSlots:]...)
		ours = ours[:maxSlots]
	}

	var arn string
	switch {
	case exactMatch(ours, name) != nil:
		arn = aws.ToString(exactMatch(ours, name).InsightArn)
	case len(ours) < maxSlots:
		created, err := client.CreateInsight(ctx, &securityhub.CreateInsightInput{
			Name: aws.String(name), GroupByAttribute: aws.String(attribute), Filters: filters,
		})
		if err != nil {
			return "", fmt.Errorf("create insight: %w", err)
		}
		arn = aws.ToString(created.InsightArn)
	default:
		victim := leastRecentlyUsed(ours)
		arn = aws.ToString(victim.InsightArn)
		if _, err := client.UpdateInsight(ctx, &securityhub.UpdateInsightInput{
			InsightArn: aws.String(arn), Name: aws.String(name), GroupByAttribute: aws.String(attribute), Filters: filters,
		}); err != nil {
			return "", fmt.Errorf("update insight: %w", err)
		}
	}

	touchLastUsed(arn)
	cleanupOnce(ctx, client, region, leftovers)
	return arn, nil
}

// exactMatch returns the slot already named name, or nil.
func exactMatch(slots []types.Insight, name string) *types.Insight {
	for i := range slots {
		if aws.ToString(slots[i].Name) == name {
			return &slots[i]
		}
	}
	return nil
}

// leastRecentlyUsed returns the slot this process least recently read or
// wrote (zero value — never seen by this process — sorts first).
func leastRecentlyUsed(slots []types.Insight) types.Insight {
	best := slots[0]
	bestAt := lastUsedAt(aws.ToString(best.InsightArn))
	for _, s := range slots[1:] {
		if at := lastUsedAt(aws.ToString(s.InsightArn)); at.Before(bestAt) {
			best, bestAt = s, at
		}
	}
	return best
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

// isConflict reports whether err is AWS rejecting CreateInsight because an
// Insight with that exact Name already exists — Security Hub enforces
// unique Insight names per account/region, so this is exactly the shape of
// error two concurrent satellite replicas (or two calls racing within the
// maxAttempts retry window) produce when both try to create the same
// brand-new query's slot at once.
func isConflict(err error) bool {
	var rc *types.ResourceConflictException
	if errors.As(err, &rc) {
		return true
	}
	var c *types.ConflictException
	return errors.As(err, &c)
}
