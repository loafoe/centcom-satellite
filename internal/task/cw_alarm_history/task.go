// Package cw_alarm_history retrieves CloudWatch alarm state-change history.
package cw_alarm_history

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cwtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"

	awshelper "github.com/loafoe/centcom-satellite/internal/aws"
	"github.com/loafoe/centcom-satellite/internal/task"
)

const TaskName = "cw_alarm_history"

const defaultLookbackDays = 14
const defaultMaxRecords = 50

type describeAlarmHistoryAPI interface {
	DescribeAlarmHistory(context.Context, *cloudwatch.DescribeAlarmHistoryInput, ...func(*cloudwatch.Options)) (*cloudwatch.DescribeAlarmHistoryOutput, error)
}

// Payload for cw_alarm_history.
type Payload struct {
	AlarmName  string `json:"alarm_name"`
	Start      string `json:"start,omitempty"` // RFC3339; default now-14d
	MaxRecords int32  `json:"max_records,omitempty"`
	Region     string `json:"region,omitempty"`
}

// HistoryItem is one parsed state transition.
type HistoryItem struct {
	Timestamp string `json:"timestamp"`
	OldState  string `json:"old_state,omitempty"`
	NewState  string `json:"new_state,omitempty"`
	Reason    string `json:"reason,omitempty"`
}

// HistoryList is the result payload.
type HistoryList struct {
	AlarmName string        `json:"alarm_name"`
	Total     int           `json:"total"`
	Items     []HistoryItem `json:"items"`
}

type Task struct {
	clientFactory func(ctx context.Context, region string) (describeAlarmHistoryAPI, error)
	now           func() time.Time
}

func New() *Task {
	return &Task{
		clientFactory: func(ctx context.Context, region string) (describeAlarmHistoryAPI, error) {
			cfg, err := awshelper.LoadConfig(ctx, awshelper.Options{Region: region})
			if err != nil {
				return nil, err
			}
			return cloudwatch.NewFromConfig(cfg), nil
		},
		now: time.Now,
	}
}

func NewWithClientFactory(f func(ctx context.Context, region string) (describeAlarmHistoryAPI, error)) *Task {
	return &Task{clientFactory: f, now: time.Now}
}

func (t *Task) Name() string { return TaskName }

func (t *Task) Execute(ctx context.Context, rawPayload json.RawMessage) (*task.Result, error) {
	var payload Payload
	if err := json.Unmarshal(rawPayload, &payload); err != nil {
		return task.NewErrorResult(fmt.Sprintf("invalid payload: %v", err)), nil
	}
	if payload.AlarmName == "" {
		return task.NewErrorResult("alarm_name is required"), nil
	}

	start := t.now().UTC().AddDate(0, 0, -defaultLookbackDays)
	if payload.Start != "" {
		parsed, err := time.Parse(time.RFC3339, payload.Start)
		if err != nil {
			return task.NewErrorResult(fmt.Sprintf("invalid start (want RFC3339): %v", err)), nil
		}
		start = parsed
	}
	maxRecords := payload.MaxRecords
	if maxRecords <= 0 {
		maxRecords = defaultMaxRecords
	}

	client, err := t.clientFactory(ctx, payload.Region)
	if err != nil {
		return nil, fmt.Errorf("failed to build cloudwatch client: %w", err)
	}

	out, err := client.DescribeAlarmHistory(ctx, &cloudwatch.DescribeAlarmHistoryInput{
		AlarmName:       aws.String(payload.AlarmName),
		HistoryItemType: cwtypes.HistoryItemTypeStateUpdate,
		StartDate:       aws.Time(start),
		EndDate:         aws.Time(t.now().UTC()),
		MaxRecords:      aws.Int32(maxRecords),
	})
	if err != nil {
		return nil, fmt.Errorf("describe alarm history: %w", err)
	}

	result := HistoryList{AlarmName: payload.AlarmName, Items: []HistoryItem{}}
	for _, h := range out.AlarmHistoryItems {
		item := HistoryItem{}
		if h.Timestamp != nil {
			item.Timestamp = h.Timestamp.UTC().Format(time.RFC3339)
		}
		var hd struct {
			OldState struct {
				StateValue string `json:"stateValue"`
			} `json:"oldState"`
			NewState struct {
				StateValue  string `json:"stateValue"`
				StateReason string `json:"stateReason"`
			} `json:"newState"`
		}
		if h.HistoryData != nil {
			if err := json.Unmarshal([]byte(*h.HistoryData), &hd); err != nil {
				// Skip items whose HistoryData can't be parsed rather than emitting
				// an ambiguous empty-state row.
				continue
			}
		}
		item.OldState = hd.OldState.StateValue
		item.NewState = hd.NewState.StateValue
		item.Reason = hd.NewState.StateReason
		result.Items = append(result.Items, item)
	}
	sort.Slice(result.Items, func(i, j int) bool {
		return result.Items[i].Timestamp < result.Items[j].Timestamp
	})
	result.Total = len(result.Items)

	return task.NewSuccessResultWithDetails(fmt.Sprintf("%d history items for %s", result.Total, payload.AlarmName), result), nil
}
