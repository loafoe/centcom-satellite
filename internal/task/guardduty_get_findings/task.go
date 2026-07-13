// Package guardduty_get_findings retrieves full detail for a batch of GuardDuty
// finding IDs (obtained from guardduty_list_findings).
package guardduty_get_findings

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

const TaskName = "guardduty_get_findings"

// maxFindingIDs is the GuardDuty GetFindings per-call limit.
const maxFindingIDs = 50

type api interface {
	ListDetectors(context.Context, *guardduty.ListDetectorsInput, ...func(*guardduty.Options)) (*guardduty.ListDetectorsOutput, error)
	GetFindings(context.Context, *guardduty.GetFindingsInput, ...func(*guardduty.Options)) (*guardduty.GetFindingsOutput, error)
}

// Payload for guardduty_get_findings.
type Payload struct {
	Region     string   `json:"region,omitempty"`
	DetectorID string   `json:"detector_id,omitempty"`
	FindingIDs []string `json:"finding_ids"`
}

// FindingList is the task result payload.
type FindingList struct {
	DetectorID string        `json:"detector_id"`
	Total      int           `json:"total"`
	Findings   []gdc.Finding `json:"findings"`
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
	if len(payload.FindingIDs) == 0 {
		return task.NewErrorResult("finding_ids is required"), nil
	}
	if len(payload.FindingIDs) > maxFindingIDs {
		return task.NewErrorResult(fmt.Sprintf("finding_ids supports at most %d IDs per call, got %d", maxFindingIDs, len(payload.FindingIDs))), nil
	}

	client, err := t.clientFactory(ctx, payload.Region)
	if err != nil {
		return nil, fmt.Errorf("failed to build guardduty client: %w", err)
	}

	detectorID, err := gdc.ResolveDetectorID(ctx, client, payload.DetectorID)
	if err != nil {
		return task.NewErrorResult(err.Error()), nil
	}

	out, err := client.GetFindings(ctx, &guardduty.GetFindingsInput{
		DetectorId: aws.String(detectorID),
		FindingIds: payload.FindingIDs,
	})
	if err != nil {
		return nil, fmt.Errorf("get findings: %w", err)
	}

	result := FindingList{DetectorID: detectorID, Findings: []gdc.Finding{}}
	for _, f := range out.Findings {
		result.Findings = append(result.Findings, gdc.NormalizeFinding(f))
	}
	result.Total = len(result.Findings)

	return task.NewSuccessResultWithDetails(fmt.Sprintf("retrieved %d findings", result.Total), result), nil
}
