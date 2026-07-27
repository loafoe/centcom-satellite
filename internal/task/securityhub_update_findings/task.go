// Package securityhub_update_findings sets a Security Hub finding's
// investigation Workflow.Status and/or attaches a Note via BatchUpdateFindings
// — the triage/remediation capability GuardDuty's API does not offer.
package securityhub_update_findings

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/securityhub"
	"github.com/aws/aws-sdk-go-v2/service/securityhub/types"

	awshelper "github.com/loafoe/centcom-satellite/internal/aws"
	"github.com/loafoe/centcom-satellite/internal/task"
)

const TaskName = "securityhub_update_findings"

// maxFindings is BatchUpdateFindings' per-call limit.
const maxFindings = 100

// defaultUpdatedBy is used when the caller omits note_updated_by.
const defaultUpdatedBy = "centcom-satellite"

type api interface {
	BatchUpdateFindings(context.Context, *securityhub.BatchUpdateFindingsInput, ...func(*securityhub.Options)) (*securityhub.BatchUpdateFindingsOutput, error)
}

// FindingRef identifies one finding to update.
type FindingRef struct {
	ID         string `json:"id"`
	ProductArn string `json:"product_arn"`
}

// Payload for securityhub_update_findings.
type Payload struct {
	Region         string       `json:"region,omitempty"`
	Findings       []FindingRef `json:"findings"`
	WorkflowStatus string       `json:"workflow_status,omitempty"`
	Note           string       `json:"note,omitempty"`
	NoteUpdatedBy  string       `json:"note_updated_by,omitempty"`
}

// UnprocessedFinding is one finding AWS could not update.
type UnprocessedFinding struct {
	ID           string `json:"id"`
	ProductArn   string `json:"product_arn"`
	ErrorCode    string `json:"error_code,omitempty"`
	ErrorMessage string `json:"error_message,omitempty"`
}

// UpdateResult is the task result payload.
type UpdateResult struct {
	Processed   []FindingRef         `json:"processed"`
	Unprocessed []UnprocessedFinding `json:"unprocessed"`
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
		return securityhub.NewFromConfig(cfg), nil
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

	if len(payload.Findings) == 0 {
		return task.NewErrorResult("findings is required and must be non-empty"), nil
	}
	if len(payload.Findings) > maxFindings {
		return task.NewErrorResult(fmt.Sprintf("findings supports at most %d entries per call, got %d", maxFindings, len(payload.Findings))), nil
	}
	if payload.WorkflowStatus == "" && payload.Note == "" {
		return task.NewErrorResult("at least one of workflow_status or note is required"), nil
	}

	client, err := t.clientFactory(ctx, payload.Region)
	if err != nil {
		return nil, fmt.Errorf("failed to build securityhub client: %w", err)
	}

	input := &securityhub.BatchUpdateFindingsInput{}
	for _, f := range payload.Findings {
		input.FindingIdentifiers = append(input.FindingIdentifiers, types.AwsSecurityFindingIdentifier{
			Id:         aws.String(f.ID),
			ProductArn: aws.String(f.ProductArn),
		})
	}
	if payload.WorkflowStatus != "" {
		input.Workflow = &types.WorkflowUpdate{Status: types.WorkflowStatus(payload.WorkflowStatus)}
	}
	if payload.Note != "" {
		updatedBy := payload.NoteUpdatedBy
		if updatedBy == "" {
			updatedBy = defaultUpdatedBy
		}
		input.Note = &types.NoteUpdate{Text: aws.String(payload.Note), UpdatedBy: aws.String(updatedBy)}
	}

	out, err := client.BatchUpdateFindings(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("batch update findings: %w", err)
	}

	result := UpdateResult{Processed: []FindingRef{}, Unprocessed: []UnprocessedFinding{}}
	for _, p := range out.ProcessedFindings {
		result.Processed = append(result.Processed, FindingRef{ID: aws.ToString(p.Id), ProductArn: aws.ToString(p.ProductArn)})
	}
	for _, u := range out.UnprocessedFindings {
		uf := UnprocessedFinding{ErrorCode: aws.ToString(u.ErrorCode), ErrorMessage: aws.ToString(u.ErrorMessage)}
		if u.FindingIdentifier != nil {
			uf.ID = aws.ToString(u.FindingIdentifier.Id)
			uf.ProductArn = aws.ToString(u.FindingIdentifier.ProductArn)
		}
		result.Unprocessed = append(result.Unprocessed, uf)
	}

	return task.NewSuccessResultWithDetails(
		fmt.Sprintf("updated %d findings (%d unprocessed)", len(result.Processed), len(result.Unprocessed)),
		result,
	), nil
}
