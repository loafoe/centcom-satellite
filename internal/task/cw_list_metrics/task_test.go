package cw_list_metrics

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cwtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
)

type fakeLM struct {
	in  *cloudwatch.ListMetricsInput
	out *cloudwatch.ListMetricsOutput
	err error
}

func (f *fakeLM) ListMetrics(_ context.Context, in *cloudwatch.ListMetricsInput, _ ...func(*cloudwatch.Options)) (*cloudwatch.ListMetricsOutput, error) {
	f.in = in
	return f.out, f.err
}

func newTestTask(api *fakeLM) *Task {
	return NewWithClientFactory(func(_ context.Context, _ string) (listMetricsAPI, error) { return api, nil })
}

func TestExecute_NormalizesMetrics(t *testing.T) {
	api := &fakeLM{out: &cloudwatch.ListMetricsOutput{
		Metrics: []cwtypes.Metric{{
			Namespace:  aws.String("AWS/EC2"),
			MetricName: aws.String("CPUUtilization"),
			Dimensions: []cwtypes.Dimension{{Name: aws.String("InstanceId"), Value: aws.String("i-1")}},
		}},
	}}
	res, err := newTestTask(api).Execute(context.Background(), json.RawMessage(`{"namespace":"AWS/EC2"}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	list := res.Details.(MetricList)
	if list.Total != 1 || list.Metrics[0].MetricName != "CPUUtilization" {
		t.Fatalf("unexpected list: %+v", list)
	}
	if aws.ToString(api.in.Namespace) != "AWS/EC2" {
		t.Fatalf("namespace not forwarded: %+v", api.in.Namespace)
	}
}

type fakePaginatingLM struct {
	callCount int
}

func (f *fakePaginatingLM) ListMetrics(_ context.Context, input *cloudwatch.ListMetricsInput, _ ...func(*cloudwatch.Options)) (*cloudwatch.ListMetricsOutput, error) {
	f.callCount++
	if f.callCount == 1 {
		return &cloudwatch.ListMetricsOutput{
			Metrics: []cwtypes.Metric{{
				Namespace:  aws.String("AWS/ECS"),
				MetricName: aws.String("CPUUtilization"),
				Dimensions: []cwtypes.Dimension{{Name: aws.String("ClusterName"), Value: aws.String("prod")}},
			}},
			NextToken: aws.String("token-1"),
		}, nil
	}
	// Second page
	return &cloudwatch.ListMetricsOutput{
		Metrics: []cwtypes.Metric{{
			Namespace:  aws.String("AWS/ECS"),
			MetricName: aws.String("MemoryUtilization"),
			Dimensions: []cwtypes.Dimension{{Name: aws.String("ClusterName"), Value: aws.String("prod")}},
		}},
		NextToken: nil,
	}, nil
}

func TestExecute_Pagination(t *testing.T) {
	api := &fakePaginatingLM{}
	task := NewWithClientFactory(func(_ context.Context, _ string) (listMetricsAPI, error) {
		return api, nil
	})

	res, err := task.Execute(context.Background(), json.RawMessage(`{"namespace":"AWS/ECS"}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.Success {
		t.Fatalf("expected success, got error: %s", res.Error)
	}
	list, ok := res.Details.(MetricList)
	if !ok {
		t.Fatalf("details type = %T, want MetricList", res.Details)
	}
	if list.Total != 2 {
		t.Fatalf("Total = %d, want 2 (across both pages)", list.Total)
	}

	wantMetrics := []struct {
		name      string
		namespace string
		dim       map[string]string
	}{
		{"CPUUtilization", "AWS/ECS", map[string]string{"ClusterName": "prod"}},
		{"MemoryUtilization", "AWS/ECS", map[string]string{"ClusterName": "prod"}},
	}

	for i, want := range wantMetrics {
		if i >= len(list.Metrics) {
			t.Fatalf("missing metric at index %d", i)
		}
		got := list.Metrics[i]
		if got.MetricName != want.name {
			t.Errorf("metric[%d].MetricName = %q, want %q", i, got.MetricName, want.name)
		}
		if got.Namespace != want.namespace {
			t.Errorf("metric[%d].Namespace = %q, want %q", i, got.Namespace, want.namespace)
		}
		if got.Dimensions["ClusterName"] != want.dim["ClusterName"] {
			t.Errorf("metric[%d].Dimensions[ClusterName] = %q, want %q", i, got.Dimensions["ClusterName"], want.dim["ClusterName"])
		}
	}

	if api.callCount != 2 {
		t.Errorf("ListMetrics called %d times, want 2", api.callCount)
	}
}
