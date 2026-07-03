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

// allowedGroupDimensions are the Cost Explorer DIMENSION keys we accept for
// group_by. Cost Explorer permits at most two GroupBy entries per request.
var allowedGroupDimensions = map[string]cetypes.Dimension{
	"SERVICE":        cetypes.DimensionService,
	"REGION":         cetypes.DimensionRegion,
	"LINKED_ACCOUNT": cetypes.DimensionLinkedAccount,
	"INSTANCE_TYPE":  cetypes.DimensionInstanceType,
	"USAGE_TYPE":     cetypes.DimensionUsageType,
	"AZ":             cetypes.DimensionAz,
}

const maxGroupBy = 2

type getCostAndUsageAPI interface {
	GetCostAndUsage(context.Context, *costexplorer.GetCostAndUsageInput, ...func(*costexplorer.Options)) (*costexplorer.GetCostAndUsageOutput, error)
}

// Payload for cost_explorer.
type Payload struct {
	Namespace   string `json:"namespace,omitempty"`
	Start       string `json:"start,omitempty"`       // YYYY-MM-DD; default now-30d
	End         string `json:"end,omitempty"`         // YYYY-MM-DD; default today
	Granularity string `json:"granularity,omitempty"` // default MONTHLY
	// GroupBy holds up to two Cost Explorer DIMENSION keys (e.g. "SERVICE",
	// "REGION"). When set, each period's cost is broken down by these dimensions.
	GroupBy []string `json:"group_by,omitempty"`
}

// GroupCost is cost for one group (dimension-value combination) within a period.
type GroupCost struct {
	// Keys are the dimension values in the same order as the request's group_by,
	// e.g. ["Amazon Elastic Compute Cloud - Compute", "eu-west-2"].
	Keys   []string `json:"keys"`
	Amount string   `json:"amount"`
	Unit   string   `json:"unit"`
}

// PeriodCost is cost for one time period. When group_by is set, Groups holds the
// per-group breakdown and Amount/Unit are empty (Cost Explorer returns no period
// total for grouped queries).
type PeriodCost struct {
	Start  string      `json:"start"`
	End    string      `json:"end"`
	Amount string      `json:"amount,omitempty"`
	Unit   string      `json:"unit,omitempty"`
	Groups []GroupCost `json:"groups,omitempty"`
}

// CostReport is the result payload.
type CostReport struct {
	Service string       `json:"service,omitempty"`
	GroupBy []string     `json:"group_by,omitempty"`
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

	// GroupBy: validate against allowed dimensions (Cost Explorer permits ≤2).
	if len(payload.GroupBy) > 0 {
		if len(payload.GroupBy) > maxGroupBy {
			return task.NewErrorResult(fmt.Sprintf("group_by supports at most %d dimensions, got %d", maxGroupBy, len(payload.GroupBy))), nil
		}
		groups := make([]cetypes.GroupDefinition, 0, len(payload.GroupBy))
		normalized := make([]string, 0, len(payload.GroupBy))
		for _, g := range payload.GroupBy {
			dim, ok := allowedGroupDimensions[g]
			if !ok {
				return task.NewErrorResult(fmt.Sprintf("unsupported group_by dimension %q (allowed: SERVICE, REGION, LINKED_ACCOUNT, INSTANCE_TYPE, USAGE_TYPE, AZ)", g)), nil
			}
			groups = append(groups, cetypes.GroupDefinition{
				Type: cetypes.GroupDefinitionTypeDimension,
				Key:  aws.String(string(dim)),
			})
			normalized = append(normalized, g)
		}
		input.GroupBy = groups
		report.GroupBy = normalized
	}
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
		// Grouped queries return per-group amounts in Groups (Total is empty);
		// ungrouped queries return the period aggregate in Total.
		if len(r.Groups) > 0 {
			for _, g := range r.Groups {
				gc := GroupCost{Keys: g.Keys}
				if mv, ok := g.Metrics["UnblendedCost"]; ok {
					gc.Amount = aws.ToString(mv.Amount)
					gc.Unit = aws.ToString(mv.Unit)
				}
				p.Groups = append(p.Groups, gc)
			}
		} else if mv, ok := r.Total["UnblendedCost"]; ok {
			p.Amount = aws.ToString(mv.Amount)
			p.Unit = aws.ToString(mv.Unit)
		}
		report.Periods = append(report.Periods, p)
	}

	summary := fmt.Sprintf("cost report: %d periods", len(report.Periods))
	if len(report.GroupBy) > 0 {
		summary = fmt.Sprintf("cost report: %d periods grouped by %v", len(report.Periods), report.GroupBy)
	}
	return task.NewSuccessResultWithDetails(summary, report), nil
}
