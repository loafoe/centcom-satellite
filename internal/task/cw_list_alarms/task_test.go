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
