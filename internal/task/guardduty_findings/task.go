// Package guardduty_findings is a convenience composite: it lists finding IDs
// matching a filter and hydrates them in one call, returning fully-normalized
// findings ready for a dashboard table. Prefer the thin guardduty_list_findings
// + guardduty_get_findings tasks when you need finer control (e.g. paging IDs
// separately from hydration).
package guardduty_findings

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/guardduty"

	awshelper "github.com/loafoe/centcom-satellite/internal/aws"
	"github.com/loafoe/centcom-satellite/internal/task"
	gdc "github.com/loafoe/centcom-satellite/internal/task/guardduty_common"
)

const TaskName = "guardduty_findings"

// defaultLimit caps how many findings the composite hydrates (GetFindings max).
const defaultLimit int32 = 50

type api interface {
	ListDetectors(context.Context, *guardduty.ListDetectorsInput, ...func(*guardduty.Options)) (*guardduty.ListDetectorsOutput, error)
	ListFindings(context.Context, *guardduty.ListFindingsInput, ...func(*guardduty.Options)) (*guardduty.ListFindingsOutput, error)
	GetFindings(context.Context, *guardduty.GetFindingsInput, ...func(*guardduty.Options)) (*guardduty.GetFindingsOutput, error)
}

// Payload for guardduty_findings.
type Payload struct {
	Region     string     `json:"region,omitempty"`
	DetectorID string     `json:"detector_id,omitempty"`
	Filter     gdc.Filter `json:"filter,omitempty"`
	SortField  string     `json:"sort_field,omitempty"` // default "severity"
	SortAsc    bool       `json:"sort_asc,omitempty"`   // default false (descending)
	// Limit caps how many findings to hydrate (1-50). NextToken continues paging.
	Limit     int32  `json:"limit,omitempty"`
	NextToken string `json:"next_token,omitempty"`
}

// FindingList is the task result payload.
type FindingList struct {
	DetectorID string        `json:"detector_id"`
	Total      int           `json:"total"`
	Findings   []gdc.Finding `json:"findings"`
	NextToken  string        `json:"next_token,omitempty"`
}

type Task struct {
	clientFactory func(ctx context.Context, region string) (api, error)
}

func New() *Task {
	return &Task{clientFactory: func(ctx context.Context, region string) (api, error) {
		cfg, err := awshelper.LoadConfig(ctx, awshelper.Options{Region: region})
		if err != nil {
			return nil, err
		}
		return guardduty.NewFromConfig(cfg), nil
	}}
}

func NewWithClientFactory(f func(ctx context.Context, region string) (api, error)) *Task {
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

	client, err := t.clientFactory(ctx, payload.Region)
	if err != nil {
		return nil, fmt.Errorf("failed to build guardduty client: %w", err)
	}

	detectorID, err := gdc.ResolveDetectorID(ctx, client, payload.DetectorID)
	if err != nil {
		return task.NewErrorResult(err.Error()), nil
	}

	limit := payload.Limit
	if limit <= 0 || limit > defaultLimit {
		limit = defaultLimit
	}

	listInput := &guardduty.ListFindingsInput{
		DetectorId:      aws.String(detectorID),
		FindingCriteria: payload.Filter.BuildCriteria(),
		SortCriteria:    gdc.SortCriteria(payload.SortField, !payload.SortAsc),
		MaxResults:      aws.Int32(limit),
	}
	if payload.NextToken != "" {
		listInput.NextToken = aws.String(payload.NextToken)
	}

	listOut, err := client.ListFindings(ctx, listInput)
	if err != nil {
		return nil, fmt.Errorf("list findings: %w", err)
	}

	result := FindingList{
		DetectorID: detectorID,
		Findings:   []gdc.Finding{},
		NextToken:  aws.ToString(listOut.NextToken),
	}
	if len(listOut.FindingIds) == 0 {
		return task.NewSuccessResultWithDetails("found 0 findings", result), nil
	}

	getOut, err := client.GetFindings(ctx, &guardduty.GetFindingsInput{
		DetectorId: aws.String(detectorID),
		FindingIds: listOut.FindingIds,
	})
	if err != nil {
		return nil, fmt.Errorf("get findings: %w", err)
	}
	for _, f := range getOut.Findings {
		result.Findings = append(result.Findings, gdc.NormalizeFinding(f))
	}
	result.Total = len(result.Findings)

	return task.NewSuccessResultWithDetails(fmt.Sprintf("retrieved %d findings", result.Total), result), nil
}
