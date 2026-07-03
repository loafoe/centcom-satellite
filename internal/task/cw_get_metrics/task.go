// Package cw_get_metrics retrieves CloudWatch metric data via a metric query or
// a Metrics Insights SQL expression.
package cw_get_metrics

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cwtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"

	awshelper "github.com/loafoe/centcom-satellite/internal/aws"
	"github.com/loafoe/centcom-satellite/internal/task"
)

const TaskName = "cw_get_metrics"

const defaultPeriod = 300

type getMetricDataAPI interface {
	GetMetricData(context.Context, *cloudwatch.GetMetricDataInput, ...func(*cloudwatch.Options)) (*cloudwatch.GetMetricDataOutput, error)
}

// Payload for cw_get_metrics. Provide either a metric query (namespace +
// metric_name [+ dimensions, stat, period]) or a Metrics Insights expression.
// The two modes are mutually exclusive.
type Payload struct {
	Namespace  string            `json:"namespace,omitempty"`
	MetricName string            `json:"metric_name,omitempty"`
	Dimensions map[string]string `json:"dimensions,omitempty"`
	Stat       string            `json:"stat,omitempty"` // default Average
	Period     int32             `json:"period,omitempty"`
	Expression string            `json:"expression,omitempty"` // Metrics Insights SQL
	Start      string            `json:"start"`                // RFC3339, required
	End        string            `json:"end"`                  // RFC3339, required
	Region     string            `json:"region,omitempty"`
}

// Series is one metric time series.
type Series struct {
	ID         string    `json:"id"`
	Label      string    `json:"label,omitempty"`
	Timestamps []string  `json:"timestamps"`
	Values     []float64 `json:"values"`
}

// MetricResult is the result payload.
type MetricResult struct {
	Series []Series `json:"series"`
}

type Task struct {
	clientFactory func(ctx context.Context, region string) (getMetricDataAPI, error)
}

func New() *Task {
	return &Task{clientFactory: func(ctx context.Context, region string) (getMetricDataAPI, error) {
		cfg, err := awshelper.LoadConfig(ctx, awshelper.Options{Region: region})
		if err != nil {
			return nil, err
		}
		return cloudwatch.NewFromConfig(cfg), nil
	}}
}

func NewWithClientFactory(f func(ctx context.Context, region string) (getMetricDataAPI, error)) *Task {
	return &Task{clientFactory: f}
}

func (t *Task) Name() string { return TaskName }

func (t *Task) Execute(ctx context.Context, rawPayload json.RawMessage) (*task.Result, error) {
	var payload Payload
	if err := json.Unmarshal(rawPayload, &payload); err != nil {
		return task.NewErrorResult(fmt.Sprintf("invalid payload: %v", err)), nil
	}
	if payload.MetricName == "" && payload.Expression == "" {
		return task.NewErrorResult("either metric_name or expression is required"), nil
	}
	if payload.MetricName != "" && payload.Expression != "" {
		return task.NewErrorResult("provide either metric_name or expression, not both"), nil
	}
	start, err := time.Parse(time.RFC3339, payload.Start)
	if err != nil {
		return task.NewErrorResult(fmt.Sprintf("invalid start (want RFC3339): %v", err)), nil
	}
	end, err := time.Parse(time.RFC3339, payload.End)
	if err != nil {
		return task.NewErrorResult(fmt.Sprintf("invalid end (want RFC3339): %v", err)), nil
	}

	query := cwtypes.MetricDataQuery{Id: aws.String("m0"), ReturnData: aws.Bool(true)}
	if payload.Expression != "" {
		query.Expression = aws.String(payload.Expression)
		// CloudWatch requires Period on the query itself for a Metrics Insights
		// expression (there is no MetricStat to carry it). Default when unset.
		period := payload.Period
		if period <= 0 {
			period = defaultPeriod
		}
		query.Period = aws.Int32(period)
	} else {
		period := payload.Period
		if period <= 0 {
			period = defaultPeriod
		}
		stat := payload.Stat
		if stat == "" {
			stat = "Average"
		}
		dims := make([]cwtypes.Dimension, 0, len(payload.Dimensions))
		for k, v := range payload.Dimensions {
			dims = append(dims, cwtypes.Dimension{Name: aws.String(k), Value: aws.String(v)})
		}
		query.MetricStat = &cwtypes.MetricStat{
			Metric: &cwtypes.Metric{
				Namespace:  aws.String(payload.Namespace),
				MetricName: aws.String(payload.MetricName),
				Dimensions: dims,
			},
			Period: aws.Int32(period),
			Stat:   aws.String(stat),
		}
	}

	client, err := t.clientFactory(ctx, payload.Region)
	if err != nil {
		return nil, fmt.Errorf("failed to build cloudwatch client: %w", err)
	}

	out, err := client.GetMetricData(ctx, &cloudwatch.GetMetricDataInput{
		StartTime:         aws.Time(start),
		EndTime:           aws.Time(end),
		MetricDataQueries: []cwtypes.MetricDataQuery{query},
	})
	if err != nil {
		return nil, fmt.Errorf("get metric data: %w", err)
	}

	result := MetricResult{Series: []Series{}}
	for _, r := range out.MetricDataResults {
		s := Series{
			ID:         aws.ToString(r.Id),
			Label:      aws.ToString(r.Label),
			Timestamps: make([]string, 0, len(r.Timestamps)),
			Values:     r.Values,
		}
		for _, ts := range r.Timestamps {
			s.Timestamps = append(s.Timestamps, ts.UTC().Format(time.RFC3339))
		}
		result.Series = append(result.Series, s)
	}

	return task.NewSuccessResultWithDetails(fmt.Sprintf("%d series", len(result.Series)), result), nil
}
