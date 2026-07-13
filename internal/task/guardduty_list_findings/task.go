// Package guardduty_list_findings lists GuardDuty finding IDs matching a filter,
// sorted for dashboard display. The list API returns IDs only; use
// guardduty_get_findings (or the guardduty_findings composite) to hydrate them.
package guardduty_list_findings

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

const TaskName = "guardduty_list_findings"

// defaultMaxResults caps IDs returned per page (GuardDuty allows up to 50).
const defaultMaxResults int32 = 50

type api interface {
	ListDetectors(context.Context, *guardduty.ListDetectorsInput, ...func(*guardduty.Options)) (*guardduty.ListDetectorsOutput, error)
	ListFindings(context.Context, *guardduty.ListFindingsInput, ...func(*guardduty.Options)) (*guardduty.ListFindingsOutput, error)
}

// Payload for guardduty_list_findings.
type Payload struct {
	Region     string     `json:"region,omitempty"`
	DetectorID string     `json:"detector_id,omitempty"`
	Filter     gdc.Filter `json:"filter,omitempty"`
	SortField  string     `json:"sort_field,omitempty"` // default "severity"
	SortAsc    bool       `json:"sort_asc,omitempty"`   // default false (descending)
	// MaxResults caps IDs per page (1-50). NextToken continues a prior page.
	MaxResults int32  `json:"max_results,omitempty"`
	NextToken  string `json:"next_token,omitempty"`
}

// FindingIDList is the task result payload.
type FindingIDList struct {
	DetectorID string   `json:"detector_id"`
	Total      int      `json:"total"`
	FindingIDs []string `json:"finding_ids"`
	NextToken  string   `json:"next_token,omitempty"`
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

	maxResults := payload.MaxResults
	if maxResults <= 0 || maxResults > defaultMaxResults {
		maxResults = defaultMaxResults
	}

	input := &guardduty.ListFindingsInput{
		DetectorId:      aws.String(detectorID),
		FindingCriteria: payload.Filter.BuildCriteria(),
		SortCriteria:    gdc.SortCriteria(payload.SortField, !payload.SortAsc),
		MaxResults:      aws.Int32(maxResults),
	}
	if payload.NextToken != "" {
		input.NextToken = aws.String(payload.NextToken)
	}

	out, err := client.ListFindings(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("list findings: %w", err)
	}

	result := FindingIDList{
		DetectorID: detectorID,
		FindingIDs: out.FindingIds,
		Total:      len(out.FindingIds),
		NextToken:  aws.ToString(out.NextToken),
	}
	if result.FindingIDs == nil {
		result.FindingIDs = []string{}
	}

	return task.NewSuccessResultWithDetails(fmt.Sprintf("found %d findings", result.Total), result), nil
}
