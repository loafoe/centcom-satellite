package cw_get_metrics

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cwtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
)

type fakeGMD struct {
	in  *cloudwatch.GetMetricDataInput
	out *cloudwatch.GetMetricDataOutput
	err error
}

func (f *fakeGMD) GetMetricData(_ context.Context, in *cloudwatch.GetMetricDataInput, _ ...func(*cloudwatch.Options)) (*cloudwatch.GetMetricDataOutput, error) {
	f.in = in
	return f.out, f.err
}

func newTestTask(api *fakeGMD) *Task {
	return NewWithClientFactory(func(_ context.Context, _ string) (getMetricDataAPI, error) { return api, nil })
}

func TestExecute_MetricQuery(t *testing.T) {
	ts := time.Date(2026, 6, 30, 10, 0, 0, 0, time.UTC)
	api := &fakeGMD{out: &cloudwatch.GetMetricDataOutput{
		MetricDataResults: []cwtypes.MetricDataResult{{
			Id:         aws.String("m0"),
			Label:      aws.String("CPUUtilization"),
			Timestamps: []time.Time{ts},
			Values:     []float64{42.5},
		}},
	}}
	payload := `{"namespace":"AWS/EC2","metric_name":"CPUUtilization","dimensions":{"InstanceId":"i-1"},"period":300,"stat":"Average","start":"2026-06-30T09:00:00Z","end":"2026-06-30T11:00:00Z"}`
	res, err := newTestTask(api).Execute(context.Background(), json.RawMessage(payload))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	result, ok := res.Details.(MetricResult)
	if !ok {
		t.Fatalf("expected MetricResult, got %T", res.Details)
	}
	series := result.Series
	if len(series) != 1 || series[0].Values[0] != 42.5 {
		t.Fatalf("unexpected series: %+v", series)
	}
	q := api.in.MetricDataQueries[0]
	if q.MetricStat == nil || aws.ToString(q.MetricStat.Metric.MetricName) != "CPUUtilization" {
		t.Fatalf("expected MetricStat query, got %+v", q)
	}
	if aws.ToInt32(q.MetricStat.Period) != 300 {
		t.Fatalf("expected Period=300, got %d", aws.ToInt32(q.MetricStat.Period))
	}
	if aws.ToString(q.MetricStat.Stat) != "Average" {
		t.Fatalf("expected Stat=Average, got %s", aws.ToString(q.MetricStat.Stat))
	}
	foundInstanceId := false
	for _, dim := range q.MetricStat.Metric.Dimensions {
		if aws.ToString(dim.Name) == "InstanceId" && aws.ToString(dim.Value) == "i-1" {
			foundInstanceId = true
			break
		}
	}
	if !foundInstanceId {
		t.Fatalf("expected InstanceId dimension with value i-1")
	}
}

func TestExecute_MetricsInsightsExpression(t *testing.T) {
	api := &fakeGMD{out: &cloudwatch.GetMetricDataOutput{}}
	expectedExpr := `SELECT AVG(CPUUtilization) FROM "AWS/EC2"`
	payload := `{"expression":"SELECT AVG(CPUUtilization) FROM \"AWS/EC2\"","start":"2026-06-30T09:00:00Z","end":"2026-06-30T11:00:00Z"}`
	if _, err := newTestTask(api).Execute(context.Background(), json.RawMessage(payload)); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	q := api.in.MetricDataQueries[0]
	if q.Expression == nil {
		t.Fatal("expected Expression query for Metrics Insights")
	}
	if aws.ToString(q.Expression) != expectedExpr {
		t.Fatalf("expected Expression=%q, got %q", expectedExpr, aws.ToString(q.Expression))
	}
}

func TestExecute_MissingBoth(t *testing.T) {
	res, err := newTestTask(&fakeGMD{}).Execute(context.Background(), json.RawMessage(`{"start":"2026-06-30T09:00:00Z","end":"2026-06-30T11:00:00Z"}`))
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if res.Success {
		t.Fatal("expected success=false when neither metric_name nor expression provided")
	}
}

func TestExecute_BothProvided(t *testing.T) {
	payload := `{"metric_name":"CPUUtilization","expression":"SELECT AVG(CPUUtilization)","start":"2026-06-30T09:00:00Z","end":"2026-06-30T11:00:00Z"}`
	res, err := newTestTask(&fakeGMD{}).Execute(context.Background(), json.RawMessage(payload))
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if res.Success {
		t.Fatal("expected success=false when both metric_name and expression provided")
	}
}
