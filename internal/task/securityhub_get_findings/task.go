// Package securityhub_get_findings retrieves Security Hub findings matching a
// filter, fully hydrated and normalized in one call — unlike GuardDuty,
// Security Hub's GetFindings returns full records directly, no separate
// list-then-hydrate step is needed.
package securityhub_get_findings

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/securityhub"

	awshelper "github.com/loafoe/centcom-satellite/internal/aws"
	"github.com/loafoe/centcom-satellite/internal/task"
	shc "github.com/loafoe/centcom-satellite/internal/task/securityhub_common"
)

const TaskName = "securityhub_get_findings"

// defaultMaxResults / maxAllowedResults reflect Security Hub's GetFindings
// MaxResults valid range (1-100).
const (
	defaultMaxResults int32 = 100
	maxAllowedResults int32 = 100
)

type api interface {
	GetFindings(context.Context, *securityhub.GetFindingsInput, ...func(*securityhub.Options)) (*securityhub.GetFindingsOutput, error)
}

// Payload for securityhub_get_findings.
type Payload struct {
	Region     string     `json:"region,omitempty"`
	Filter     shc.Filter `json:"filter,omitempty"`
	SortField  string     `json:"sort_field,omitempty"` // default "SeverityNormalized"
	SortAsc    bool       `json:"sort_asc,omitempty"`   // default false (descending)
	MaxResults int32      `json:"max_results,omitempty"`
	NextToken  string     `json:"next_token,omitempty"`
}

// FindingList is the task result payload.
type FindingList struct {
	Total     int           `json:"total"`
	Findings  []shc.Finding `json:"findings"`
	NextToken string        `json:"next_token,omitempty"`
}

type Task struct {
	// clientFactory returns the securityhub client plus the AWS region it
	// actually resolved to (payload.Region if non-empty, otherwise whatever
	// the default credential chain / AWS_REGION resolved) — Execute uses
	// that resolved region to constrain results via Filter.Region, so a
	// Security Hub cross-region finding aggregator can't silently leak
	// other regions' findings into this satellite's results (see
	// securityhub_common.Filter.Region's doc comment).
	clientFactory func(ctx context.Context, region string) (api, string, error)
}

func New() *Task {
	return &Task{clientFactory: func(ctx context.Context, region string) (api, string, error) {
		cfg, err := awshelper.LoadConfig(ctx, awshelper.Options{Region: region})
		if err != nil {
			return nil, "", err
		}
		return securityhub.NewFromConfig(cfg), cfg.Region, nil
	}}
}

func NewWithClientFactory(f func(ctx context.Context, region string) (api, string, error)) *Task {
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

	client, resolvedRegion, err := t.clientFactory(ctx, payload.Region)
	if err != nil {
		return nil, fmt.Errorf("failed to build securityhub client: %w", err)
	}

	maxResults := payload.MaxResults
	if maxResults <= 0 || maxResults > maxAllowedResults {
		maxResults = defaultMaxResults
	}

	input := &securityhub.GetFindingsInput{
		Filters:      payload.Filter.WithResolvedRegion(resolvedRegion).BuildFilters(),
		SortCriteria: shc.SortCriteria(payload.SortField, !payload.SortAsc),
		MaxResults:   aws.Int32(maxResults),
	}
	if payload.NextToken != "" {
		input.NextToken = aws.String(payload.NextToken)
	}

	out, err := client.GetFindings(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("get findings: %w", err)
	}

	result := FindingList{Findings: []shc.Finding{}, NextToken: aws.ToString(out.NextToken)}
	for _, f := range out.Findings {
		result.Findings = append(result.Findings, shc.NormalizeFinding(f))
	}
	result.Total = len(result.Findings)

	return task.NewSuccessResultWithDetails(fmt.Sprintf("retrieved %d findings", result.Total), result), nil
}
