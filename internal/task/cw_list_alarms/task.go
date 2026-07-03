// Package cw_list_alarms lists CloudWatch alarms in the requested state(s).
package cw_list_alarms

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cwtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"

	awshelper "github.com/loafoe/centcom-satellite/internal/aws"
	"github.com/loafoe/centcom-satellite/internal/task"
)

const TaskName = "cw_list_alarms"

// describeAlarmsAPI is the narrow slice of the CloudWatch client used here.
type describeAlarmsAPI interface {
	DescribeAlarms(context.Context, *cloudwatch.DescribeAlarmsInput, ...func(*cloudwatch.Options)) (*cloudwatch.DescribeAlarmsOutput, error)
}

// Payload for cw_list_alarms.
type Payload struct {
	StateFilter     []string `json:"state_filter,omitempty"`
	AlarmNamePrefix string   `json:"alarm_name_prefix,omitempty"`
	Region          string   `json:"region,omitempty"`
}

// Alarm is the normalized alarm model (matches the RCA prototype).
type Alarm struct {
	Name       string            `json:"name"`
	ARN        string            `json:"arn"`
	Metric     string            `json:"metric"`
	Namespace  string            `json:"namespace"`
	State      string            `json:"state"`
	Reason     string            `json:"reason"`
	Dimensions map[string]string `json:"dimensions,omitempty"`
	Updated    string            `json:"updated,omitempty"`
}

// AlarmList is the task result payload.
type AlarmList struct {
	Total  int     `json:"total"`
	Alarms []Alarm `json:"alarms"`
}

// Task lists CloudWatch alarms.
type Task struct {
	clientFactory func(ctx context.Context, region string) (describeAlarmsAPI, error)
}

// New builds a production task using the shared AWS config helper.
func New() *Task {
	return &Task{clientFactory: func(ctx context.Context, region string) (describeAlarmsAPI, error) {
		cfg, err := awshelper.LoadConfig(ctx, awshelper.Options{Region: region})
		if err != nil {
			return nil, err
		}
		return cloudwatch.NewFromConfig(cfg), nil
	}}
}

// NewWithClientFactory builds a task with an injected client factory (tests).
func NewWithClientFactory(f func(ctx context.Context, region string) (describeAlarmsAPI, error)) *Task {
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

	states := payload.StateFilter
	if len(states) == 0 {
		states = []string{"ALARM", "INSUFFICIENT_DATA"}
	}

	client, err := t.clientFactory(ctx, payload.Region)
	if err != nil {
		return nil, fmt.Errorf("failed to build cloudwatch client: %w", err)
	}

	input := &cloudwatch.DescribeAlarmsInput{
		AlarmTypes: []cwtypes.AlarmType{cwtypes.AlarmTypeMetricAlarm, cwtypes.AlarmTypeCompositeAlarm},
	}
	if payload.AlarmNamePrefix != "" {
		input.AlarmNamePrefix = aws.String(payload.AlarmNamePrefix)
	}

	wanted := make(map[string]bool, len(states))
	for _, s := range states {
		wanted[s] = true
	}

	result := AlarmList{Alarms: []Alarm{}}
	paginator := cloudwatch.NewDescribeAlarmsPaginator(client, input)
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("describe alarms: %w", err)
		}
		for _, a := range page.MetricAlarms {
			if !wanted[string(a.StateValue)] {
				continue
			}
			result.Alarms = append(result.Alarms, normalizeMetricAlarm(a))
		}
		for _, a := range page.CompositeAlarms {
			if !wanted[string(a.StateValue)] {
				continue
			}
			result.Alarms = append(result.Alarms, normalizeCompositeAlarm(a))
		}
	}
	result.Total = len(result.Alarms)

	return task.NewSuccessResultWithDetails(fmt.Sprintf("found %d alarms", result.Total), result), nil
}

func normalizeMetricAlarm(a cwtypes.MetricAlarm) Alarm {
	dims := map[string]string{}
	for _, d := range a.Dimensions {
		dims[aws.ToString(d.Name)] = aws.ToString(d.Value)
	}
	updated := ""
	if a.StateUpdatedTimestamp != nil {
		updated = a.StateUpdatedTimestamp.UTC().Format("2006-01-02T15:04:05Z")
	}
	return Alarm{
		Name:       aws.ToString(a.AlarmName),
		ARN:        aws.ToString(a.AlarmArn),
		Metric:     aws.ToString(a.MetricName),
		Namespace:  aws.ToString(a.Namespace),
		State:      string(a.StateValue),
		Reason:     aws.ToString(a.StateReason),
		Dimensions: dims,
		Updated:    updated,
	}
}

func normalizeCompositeAlarm(a cwtypes.CompositeAlarm) Alarm {
	updated := ""
	if a.StateUpdatedTimestamp != nil {
		updated = a.StateUpdatedTimestamp.UTC().Format("2006-01-02T15:04:05Z")
	}
	return Alarm{
		Name:    aws.ToString(a.AlarmName),
		ARN:     aws.ToString(a.AlarmArn),
		State:   string(a.StateValue),
		Reason:  aws.ToString(a.StateReason),
		Updated: updated,
	}
}
