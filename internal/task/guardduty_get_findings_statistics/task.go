// Package guardduty_get_findings_statistics returns aggregated finding counts
// (by severity, type, date, resource, or account) for the dashboard summary
// widgets, using GuardDuty's non-deprecated GroupBy statistics API.
package guardduty_get_findings_statistics

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/guardduty"
	gdtypes "github.com/aws/aws-sdk-go-v2/service/guardduty/types"

	awshelper "github.com/loafoe/centcom-satellite/internal/aws"
	"github.com/loafoe/centcom-satellite/internal/task"
	gdc "github.com/loafoe/centcom-satellite/internal/task/guardduty_common"
)

const TaskName = "guardduty_get_findings_statistics"

// groupByValues maps the payload group_by string to the SDK enum.
var groupByValues = map[string]gdtypes.GroupByType{
	"SEVERITY":     gdtypes.GroupByTypeSeverity,
	"FINDING_TYPE": gdtypes.GroupByTypeFindingType,
	"DATE":         gdtypes.GroupByTypeDate,
	"RESOURCE":     gdtypes.GroupByTypeResource,
	"ACCOUNT":      gdtypes.GroupByTypeAccount,
}

type api interface {
	ListDetectors(context.Context, *guardduty.ListDetectorsInput, ...func(*guardduty.Options)) (*guardduty.ListDetectorsOutput, error)
	GetFindingsStatistics(context.Context, *guardduty.GetFindingsStatisticsInput, ...func(*guardduty.Options)) (*guardduty.GetFindingsStatisticsOutput, error)
}

// Payload for guardduty_get_findings_statistics.
type Payload struct {
	Region     string     `json:"region,omitempty"`
	DetectorID string     `json:"detector_id,omitempty"`
	Filter     gdc.Filter `json:"filter,omitempty"`
	GroupBy    string     `json:"group_by,omitempty"` // default SEVERITY
}

// Statistics is the task result payload: a normalized list of {key,count} buckets.
type Statistics struct {
	DetectorID string          `json:"detector_id"`
	GroupBy    string          `json:"group_by"`
	Total      int32           `json:"total"`
	Counts     []gdc.StatCount `json:"counts"`
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
		return guardduty.NewFromConfig(cfg), nil
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
	groupBy, ok := groupByValues[groupByStr]
	if !ok {
		return task.NewErrorResult(fmt.Sprintf("unsupported group_by %q (allowed: SEVERITY, FINDING_TYPE, DATE, RESOURCE, ACCOUNT)", groupByStr)), nil
	}

	client, err := t.clientFactory(ctx, payload.Region)
	if err != nil {
		return nil, fmt.Errorf("failed to build guardduty client: %w", err)
	}

	detectorID, err := gdc.ResolveDetectorID(ctx, client, payload.DetectorID)
	if err != nil {
		return task.NewErrorResult(err.Error()), nil
	}

	out, err := client.GetFindingsStatistics(ctx, &guardduty.GetFindingsStatisticsInput{
		DetectorId:      aws.String(detectorID),
		FindingCriteria: payload.Filter.BuildCriteria(),
		GroupBy:         groupBy,
	})
	if err != nil {
		return nil, fmt.Errorf("get findings statistics: %w", err)
	}

	result := Statistics{DetectorID: detectorID, GroupBy: groupByStr, Counts: []gdc.StatCount{}}
	if out.FindingStatistics != nil {
		result.Counts = normalizeStatistics(out.FindingStatistics)
	}
	for _, c := range result.Counts {
		result.Total += c.Count
	}

	return task.NewSuccessResultWithDetails(fmt.Sprintf("statistics grouped by %s: %d buckets", groupByStr, len(result.Counts)), result), nil
}

// normalizeStatistics flattens whichever GroupedBy* slice the API populated into
// a uniform list of {key,count} buckets.
func normalizeStatistics(s *gdtypes.FindingStatistics) []gdc.StatCount {
	counts := []gdc.StatCount{}
	for _, v := range s.GroupedBySeverity {
		counts = append(counts, gdc.StatCount{
			Key:   strconv.FormatFloat(aws.ToFloat64(v.Severity), 'f', -1, 64),
			Count: aws.ToInt32(v.TotalFindings),
		})
	}
	for _, v := range s.GroupedByFindingType {
		counts = append(counts, gdc.StatCount{Key: aws.ToString(v.FindingType), Count: aws.ToInt32(v.TotalFindings)})
	}
	for _, v := range s.GroupedByDate {
		key := ""
		if v.Date != nil {
			key = v.Date.UTC().Format("2006-01-02")
		}
		counts = append(counts, gdc.StatCount{Key: key, Count: aws.ToInt32(v.TotalFindings)})
	}
	for _, v := range s.GroupedByResource {
		counts = append(counts, gdc.StatCount{Key: aws.ToString(v.ResourceId), Count: aws.ToInt32(v.TotalFindings)})
	}
	for _, v := range s.GroupedByAccount {
		counts = append(counts, gdc.StatCount{Key: aws.ToString(v.AccountId), Count: aws.ToInt32(v.TotalFindings)})
	}
	return counts
}
