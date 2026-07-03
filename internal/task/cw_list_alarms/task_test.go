package cw_list_alarms

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cwtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
)

type fakeDescribeAlarms struct {
	out *cloudwatch.DescribeAlarmsOutput
	err error
}

func (f *fakeDescribeAlarms) DescribeAlarms(_ context.Context, _ *cloudwatch.DescribeAlarmsInput, _ ...func(*cloudwatch.Options)) (*cloudwatch.DescribeAlarmsOutput, error) {
	return f.out, f.err
}

func newTestTask(api describeAlarmsAPI) *Task {
	return NewWithClientFactory(func(_ context.Context, _ string) (describeAlarmsAPI, error) {
		return api, nil
	})
}

func TestExecute_NormalizesMetricAlarm(t *testing.T) {
	updated := time.Date(2026, 6, 30, 12, 0, 0, 0, time.UTC)
	api := &fakeDescribeAlarms{out: &cloudwatch.DescribeAlarmsOutput{
		MetricAlarms: []cwtypes.MetricAlarm{{
			AlarmName:             aws.String("cpu-high"),
			AlarmArn:              aws.String("arn:aws:cloudwatch:eu-west-1:1:alarm:cpu-high"),
			MetricName:            aws.String("CPUUtilization"),
			Namespace:             aws.String("AWS/EC2"),
			StateValue:            cwtypes.StateValueAlarm,
			StateReason:           aws.String("threshold breached"),
			StateUpdatedTimestamp: &updated,
			Dimensions:            []cwtypes.Dimension{{Name: aws.String("InstanceId"), Value: aws.String("i-123")}},
		}},
	}}

	res, err := newTestTask(api).Execute(context.Background(), json.RawMessage(`{}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.Success {
		t.Fatalf("expected success, got error: %s", res.Error)
	}
	list, ok := res.Details.(AlarmList)
	if !ok {
		t.Fatalf("details type = %T, want AlarmList", res.Details)
	}
	if list.Total != 1 || list.Alarms[0].Name != "cpu-high" {
		t.Fatalf("unexpected alarm list: %+v", list)
	}
	if list.Alarms[0].Dimensions["InstanceId"] != "i-123" {
		t.Fatalf("dimension not mapped: %+v", list.Alarms[0].Dimensions)
	}
}

func TestExecute_InvalidPayload(t *testing.T) {
	res, err := newTestTask(&fakeDescribeAlarms{}).Execute(context.Background(), json.RawMessage(`{`))
	if err != nil {
		t.Fatalf("expected nil error for bad payload, got %v", err)
	}
	if res.Success {
		t.Fatal("expected success=false for invalid payload")
	}
}

func TestExecute_NormalizesCompositeAlarm(t *testing.T) {
	updated := time.Date(2026, 7, 1, 10, 30, 0, 0, time.UTC)
	api := &fakeDescribeAlarms{out: &cloudwatch.DescribeAlarmsOutput{
		CompositeAlarms: []cwtypes.CompositeAlarm{{
			AlarmName:             aws.String("composite-alarm"),
			AlarmArn:              aws.String("arn:aws:cloudwatch:us-east-1:123456789012:alarm:composite-alarm"),
			StateValue:            cwtypes.StateValueAlarm,
			StateReason:           aws.String("composite rule triggered"),
			StateUpdatedTimestamp: &updated,
		}},
	}}

	res, err := newTestTask(api).Execute(context.Background(), json.RawMessage(`{}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.Success {
		t.Fatalf("expected success, got error: %s", res.Error)
	}
	list, ok := res.Details.(AlarmList)
	if !ok {
		t.Fatalf("details type = %T, want AlarmList", res.Details)
	}
	if list.Total != 1 {
		t.Fatalf("expected 1 alarm, got %d", list.Total)
	}
	alarm := list.Alarms[0]
	if alarm.Name != "composite-alarm" {
		t.Errorf("Name = %q, want %q", alarm.Name, "composite-alarm")
	}
	if alarm.ARN != "arn:aws:cloudwatch:us-east-1:123456789012:alarm:composite-alarm" {
		t.Errorf("ARN = %q, want expected ARN", alarm.ARN)
	}
	if alarm.State != "ALARM" {
		t.Errorf("State = %q, want ALARM", alarm.State)
	}
	if alarm.Reason != "composite rule triggered" {
		t.Errorf("Reason = %q, want expected reason", alarm.Reason)
	}
	if alarm.Updated != "2026-07-01T10:30:00Z" {
		t.Errorf("Updated = %q, want 2026-07-01T10:30:00Z", alarm.Updated)
	}
	if alarm.Metric != "" {
		t.Errorf("Metric = %q, want empty for composite alarm", alarm.Metric)
	}
	if alarm.Namespace != "" {
		t.Errorf("Namespace = %q, want empty for composite alarm", alarm.Namespace)
	}
}

func TestExecute_StateFiltering(t *testing.T) {
	updated := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
	api := &fakeDescribeAlarms{out: &cloudwatch.DescribeAlarmsOutput{
		MetricAlarms: []cwtypes.MetricAlarm{
			{
				AlarmName:             aws.String("alarm-ok"),
				StateValue:            cwtypes.StateValueOk,
				StateReason:           aws.String("back to normal"),
				StateUpdatedTimestamp: &updated,
			},
			{
				AlarmName:             aws.String("alarm-alarm"),
				StateValue:            cwtypes.StateValueAlarm,
				StateReason:           aws.String("threshold breached"),
				StateUpdatedTimestamp: &updated,
			},
			{
				AlarmName:             aws.String("alarm-insufficient"),
				StateValue:            cwtypes.StateValueInsufficientData,
				StateReason:           aws.String("not enough data"),
				StateUpdatedTimestamp: &updated,
			},
		},
	}}

	tests := []struct {
		name      string
		payload   string
		wantNames []string
	}{
		{
			name:      "default filter excludes OK",
			payload:   `{}`,
			wantNames: []string{"alarm-alarm", "alarm-insufficient"},
		},
		{
			name:      "custom filter only OK",
			payload:   `{"state_filter":["OK"]}`,
			wantNames: []string{"alarm-ok"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res, err := newTestTask(api).Execute(context.Background(), json.RawMessage(tt.payload))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !res.Success {
				t.Fatalf("expected success, got error: %s", res.Error)
			}
			list, ok := res.Details.(AlarmList)
			if !ok {
				t.Fatalf("details type = %T, want AlarmList", res.Details)
			}
			if list.Total != len(tt.wantNames) {
				t.Fatalf("Total = %d, want %d", list.Total, len(tt.wantNames))
			}
			gotNames := make([]string, len(list.Alarms))
			for i, a := range list.Alarms {
				gotNames[i] = a.Name
			}
			for i, want := range tt.wantNames {
				if i >= len(gotNames) || gotNames[i] != want {
					t.Errorf("alarm[%d].Name = %q, want %q", i, gotNames[i], want)
				}
			}
		})
	}
}

type fakePaginatingDescribeAlarms struct {
	callCount int
}

func (f *fakePaginatingDescribeAlarms) DescribeAlarms(_ context.Context, input *cloudwatch.DescribeAlarmsInput, _ ...func(*cloudwatch.Options)) (*cloudwatch.DescribeAlarmsOutput, error) {
	f.callCount++
	if f.callCount == 1 {
		return &cloudwatch.DescribeAlarmsOutput{
			MetricAlarms: []cwtypes.MetricAlarm{{
				AlarmName:  aws.String("alarm-page-1"),
				StateValue: cwtypes.StateValueAlarm,
			}},
			NextToken: aws.String("token-1"),
		}, nil
	}
	// Second call
	return &cloudwatch.DescribeAlarmsOutput{
		MetricAlarms: []cwtypes.MetricAlarm{{
			AlarmName:  aws.String("alarm-page-2"),
			StateValue: cwtypes.StateValueAlarm,
		}},
		NextToken: nil,
	}, nil
}

func TestExecute_Pagination(t *testing.T) {
	api := &fakePaginatingDescribeAlarms{}

	res, err := newTestTask(api).Execute(context.Background(), json.RawMessage(`{}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.Success {
		t.Fatalf("expected success, got error: %s", res.Error)
	}
	list, ok := res.Details.(AlarmList)
	if !ok {
		t.Fatalf("details type = %T, want AlarmList", res.Details)
	}
	if list.Total != 2 {
		t.Fatalf("Total = %d, want 2 (across both pages)", list.Total)
	}
	wantNames := []string{"alarm-page-1", "alarm-page-2"}
	for i, want := range wantNames {
		if i >= len(list.Alarms) || list.Alarms[i].Name != want {
			t.Errorf("alarm[%d].Name = %q, want %q", i, list.Alarms[i].Name, want)
		}
	}
	if api.callCount != 2 {
		t.Errorf("DescribeAlarms called %d times, want 2", api.callCount)
	}
}
