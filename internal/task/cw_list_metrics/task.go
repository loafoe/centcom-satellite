// Package cw_list_metrics lists available CloudWatch metrics (discovery).
package cw_list_metrics

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

const TaskName = "cw_list_metrics"

type listMetricsAPI interface {
	ListMetrics(context.Context, *cloudwatch.ListMetricsInput, ...func(*cloudwatch.Options)) (*cloudwatch.ListMetricsOutput, error)
}

// Payload for cw_list_metrics. All fields optional.
type Payload struct {
	Namespace  string            `json:"namespace,omitempty"`
	MetricName string            `json:"metric_name,omitempty"`
	Dimensions map[string]string `json:"dimensions,omitempty"`
	Region     string            `json:"region,omitempty"`
}

// MetricInfo describes one discovered metric.
type MetricInfo struct {
	Namespace  string            `json:"namespace"`
	MetricName string            `json:"metric_name"`
	Dimensions map[string]string `json:"dimensions,omitempty"`
}

// MetricList is the result payload.
type MetricList struct {
	Total   int          `json:"total"`
	Metrics []MetricInfo `json:"metrics"`
}

type Task struct {
	clientFactory func(ctx context.Context, region string) (listMetricsAPI, error)
}

func New() *Task {
	return &Task{clientFactory: func(ctx context.Context, region string) (listMetricsAPI, error) {
		cfg, err := awshelper.LoadConfig(ctx, awshelper.Options{Region: region})
		if err != nil {
			return nil, err
		}
		return cloudwatch.NewFromConfig(cfg), nil
	}}
}

func NewWithClientFactory(f func(ctx context.Context, region string) (listMetricsAPI, error)) *Task {
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

	input := &cloudwatch.ListMetricsInput{}
	if payload.Namespace != "" {
		input.Namespace = aws.String(payload.Namespace)
	}
	if payload.MetricName != "" {
		input.MetricName = aws.String(payload.MetricName)
	}
	for k, v := range payload.Dimensions {
		input.Dimensions = append(input.Dimensions, cwtypes.DimensionFilter{
			Name:  aws.String(k),
			Value: aws.String(v),
		})
	}

	client, err := t.clientFactory(ctx, payload.Region)
	if err != nil {
		return nil, fmt.Errorf("failed to build cloudwatch client: %w", err)
	}

	result := MetricList{Metrics: []MetricInfo{}}
	paginator := cloudwatch.NewListMetricsPaginator(client, input)
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("list metrics: %w", err)
		}
		for _, m := range page.Metrics {
			dims := map[string]string{}
			for _, d := range m.Dimensions {
				dims[aws.ToString(d.Name)] = aws.ToString(d.Value)
			}
			result.Metrics = append(result.Metrics, MetricInfo{
				Namespace:  aws.ToString(m.Namespace),
				MetricName: aws.ToString(m.MetricName),
				Dimensions: dims,
			})
		}
	}
	result.Total = len(result.Metrics)

	return task.NewSuccessResultWithDetails(fmt.Sprintf("found %d metrics", result.Total), result), nil
}
