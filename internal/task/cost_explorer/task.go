// Package cost_explorer retrieves AWS cost and usage data, optionally filtered
// to the service backing a CloudWatch namespace.
package cost_explorer

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/costexplorer"
	cetypes "github.com/aws/aws-sdk-go-v2/service/costexplorer/types"

	awshelper "github.com/loafoe/centcom-satellite/internal/aws"
	"github.com/loafoe/centcom-satellite/internal/task"
)

const TaskName = "cost_explorer"

// ceRegion is fixed: Cost Explorer is a global service reachable via us-east-1.
const ceRegion = "us-east-1"

// namespaceToService maps CloudWatch namespaces to Cost Explorer SERVICE values.
var namespaceToService = map[string]string{
	"AWS/EC2":            "Amazon Elastic Compute Cloud - Compute",
	"AWS/RDS":            "Amazon Relational Database Service",
	"AWS/Lambda":         "AWS Lambda",
	"AWS/StorageGateway": "AWS Storage Gateway",
	"AWS/ECS":            "Amazon Elastic Container Service",
}

type getCostAndUsageAPI interface {
	GetCostAndUsage(context.Context, *costexplorer.GetCostAndUsageInput, ...func(*costexplorer.Options)) (*costexplorer.GetCostAndUsageOutput, error)
}

// Payload for cost_explorer.
type Payload struct {
	Namespace   string `json:"namespace,omitempty"`
	Start       string `json:"start,omitempty"`       // YYYY-MM-DD; default now-30d
	End         string `json:"end,omitempty"`         // YYYY-MM-DD; default today
	Granularity string `json:"granularity,omitempty"` // default MONTHLY
}

// PeriodCost is cost for one time period.
type PeriodCost struct {
	Start  string `json:"start"`
	End    string `json:"end"`
	Amount string `json:"amount"`
	Unit   string `json:"unit"`
}

// CostReport is the result payload.
type CostReport struct {
	Service string       `json:"service,omitempty"`
	Periods []PeriodCost `json:"periods"`
}

type Task struct {
	clientFactory func(ctx context.Context) (getCostAndUsageAPI, error)
	now           func() time.Time
}

func New() *Task {
	return &Task{
		clientFactory: func(ctx context.Context) (getCostAndUsageAPI, error) {
			cfg, err := awshelper.LoadConfig(ctx, awshelper.Options{Region: ceRegion})
			if err != nil {
				return nil, err
			}
			return costexplorer.NewFromConfig(cfg), nil
		},
		now: time.Now,
	}
}

func NewWithClientFactory(f func(ctx context.Context) (getCostAndUsageAPI, error)) *Task {
	return &Task{clientFactory: f, now: time.Now}
}

func (t *Task) Name() string { return TaskName }

func (t *Task) Execute(ctx context.Context, rawPayload json.RawMessage) (*task.Result, error) {
	var payload Payload
	if len(rawPayload) > 0 {
		if err := json.Unmarshal(rawPayload, &payload); err != nil {
			return task.NewErrorResult(fmt.Sprintf("invalid payload: %v", err)), nil
		}
	}

	end := t.now().UTC().Format("2006-01-02")
	if payload.End != "" {
		end = payload.End
	}
	start := t.now().UTC().AddDate(0, 0, -30).Format("2006-01-02")
	if payload.Start != "" {
		start = payload.Start
	}
	granularity := cetypes.GranularityMonthly
	if payload.Granularity != "" {
		granularity = cetypes.Granularity(payload.Granularity)
	}

	input := &costexplorer.GetCostAndUsageInput{
		TimePeriod:  &cetypes.DateInterval{Start: aws.String(start), End: aws.String(end)},
		Granularity: granularity,
		Metrics:     []string{"UnblendedCost", "UsageQuantity"},
	}

	report := CostReport{Periods: []PeriodCost{}}
	if payload.Namespace != "" {
		service, ok := namespaceToService[payload.Namespace]
		if !ok {
			return task.NewErrorResult(fmt.Sprintf("unknown namespace %q (no service mapping)", payload.Namespace)), nil
		}
		report.Service = service
		input.Filter = &cetypes.Expression{
			Dimensions: &cetypes.DimensionValues{
				Key:    cetypes.DimensionService,
				Values: []string{service},
			},
		}
	}

	client, err := t.clientFactory(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to build cost explorer client: %w", err)
	}

	out, err := client.GetCostAndUsage(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("get cost and usage: %w", err)
	}

	for _, r := range out.ResultsByTime {
		p := PeriodCost{}
		if r.TimePeriod != nil {
			p.Start = aws.ToString(r.TimePeriod.Start)
			p.End = aws.ToString(r.TimePeriod.End)
		}
		if mv, ok := r.Total["UnblendedCost"]; ok {
			p.Amount = aws.ToString(mv.Amount)
			p.Unit = aws.ToString(mv.Unit)
		}
		report.Periods = append(report.Periods, p)
	}

	return task.NewSuccessResultWithDetails(fmt.Sprintf("cost report: %d periods", len(report.Periods)), report), nil
}
