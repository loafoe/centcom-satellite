// Package securityhub_update_findings sets a Security Hub finding's
// investigation Workflow.Status, attaches a Note and/or sets or removes
// UserDefinedFields keys via BatchUpdateFindings — the triage/remediation
// capability GuardDuty's and Inspector's own APIs do not offer.
//
// Findings are given explicitly ({id, product_arn}) or selected by
// vulnerability (optionally narrowed to resources), resolved through
// Inspector: an Inspector finding's ARN is its Security Hub finding ID.
//
// BatchUpdateFindings replaces a finding's whole UserDefinedFields map
// (verified live: writing one key dropped every other key), and one call
// sets the same map on every finding in it. Key changes are therefore
// read-modify-write: each finding's current map is read, only the named
// keys change, and findings are written in groups that end up with an
// identical map. Other tools' keys (e.g. an enrichment automation's) stay.
package securityhub_update_findings

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/inspector2"
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
	GetFindings(context.Context, *securityhub.GetFindingsInput, ...func(*securityhub.Options)) (*securityhub.GetFindingsOutput, error)
}

type inspectorAPI interface {
	ListFindings(context.Context, *inspector2.ListFindingsInput, ...func(*inspector2.Options)) (*inspector2.ListFindingsOutput, error)
}

// FindingRef identifies one finding to update.
type FindingRef struct {
	ID         string `json:"id"`
	ProductArn string `json:"product_arn"`
}

// Payload for securityhub_update_findings.
type Payload struct {
	Region   string       `json:"region,omitempty"`
	Findings []FindingRef `json:"findings,omitempty"`
	// VulnerabilityID selects every active Inspector finding for this
	// vulnerability (CVE/GHSA ID) instead of explicit Findings; ResourceIDs
	// narrows it to those resources (instance IDs, Lambda function ARNs,
	// ECR image ARNs).
	VulnerabilityID string   `json:"vulnerability_id,omitempty"`
	ResourceIDs     []string `json:"resource_ids,omitempty"`
	WorkflowStatus  string   `json:"workflow_status,omitempty"`
	Note            string   `json:"note,omitempty"`
	NoteUpdatedBy   string   `json:"note_updated_by,omitempty"`
	// SetUserDefinedFields / RemoveUserDefinedFields change only these keys
	// on each finding, keeping every other key.
	SetUserDefinedFields    map[string]string `json:"set_user_defined_fields,omitempty"`
	RemoveUserDefinedFields []string          `json:"remove_user_defined_fields,omitempty"`
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
	// Selected is how many findings the request addressed.
	Selected int `json:"selected"`
}

type Task struct {
	clientFactory    func(ctx context.Context, region string) (api, error)
	inspectorFactory func(ctx context.Context, region string) (inspectorAPI, error)
}

func New() *Task {
	return &Task{
		clientFactory: func(ctx context.Context, region string) (api, error) {
			cfg, err := awshelper.LoadConfig(ctx, awshelper.Options{Region: region})
			if err != nil {
				return nil, err
			}
			return securityhub.NewFromConfig(cfg), nil
		},
		inspectorFactory: func(ctx context.Context, region string) (inspectorAPI, error) {
			cfg, err := awshelper.LoadConfig(ctx, awshelper.Options{Region: region})
			if err != nil {
				return nil, err
			}
			return inspector2.NewFromConfig(cfg), nil
		},
	}
}

func NewWithClientFactory(f func(ctx context.Context, region string) (api, error)) *Task {
	return &Task{clientFactory: f}
}

func newWithClients(f func(ctx context.Context, region string) (api, error), i func(ctx context.Context, region string) (inspectorAPI, error)) *Task {
	return &Task{clientFactory: f, inspectorFactory: i}
}

func (t *Task) Name() string { return TaskName }

func (t *Task) Execute(ctx context.Context, rawPayload json.RawMessage) (*task.Result, error) {
	var payload Payload
	if len(rawPayload) > 0 {
		if err := json.Unmarshal(rawPayload, &payload); err != nil {
			return task.NewErrorResult(fmt.Sprintf("invalid payload: %v", err)), nil
		}
	}
	if msg := validate(&payload); msg != "" {
		return task.NewErrorResult(msg), nil
	}

	client, err := t.clientFactory(ctx, payload.Region)
	if err != nil {
		return nil, fmt.Errorf("failed to build securityhub client: %w", err)
	}

	refs := payload.Findings
	if payload.VulnerabilityID != "" {
		if t.inspectorFactory == nil {
			return task.NewErrorResult("vulnerability_id selection is not supported by this satellite build"), nil
		}
		insp, err := t.inspectorFactory(ctx, payload.Region)
		if err != nil {
			return nil, fmt.Errorf("failed to build inspector client: %w", err)
		}
		if refs, err = resolveVulnerability(ctx, insp, payload.VulnerabilityID, payload.ResourceIDs); err != nil {
			return awshelper.WrapError("resolve inspector findings", err)
		}
	}

	result := UpdateResult{Processed: []FindingRef{}, Unprocessed: []UnprocessedFinding{}, Selected: len(refs)}
	if len(refs) == 0 {
		return task.NewSuccessResultWithDetails("no matching active findings", result), nil
	}
	base := baseInput(&payload)
	if len(payload.SetUserDefinedFields) == 0 && len(payload.RemoveUserDefinedFields) == 0 {
		err = batchUpdate(ctx, client, base, refs, &result)
	} else {
		err = updateUserDefinedFields(ctx, client, base, &payload, refs, &result)
	}
	if err != nil {
		return awshelper.WrapError("batch update findings", err)
	}
	return task.NewSuccessResultWithDetails(
		fmt.Sprintf("updated %d of %d findings (%d unprocessed)", len(result.Processed), result.Selected, len(result.Unprocessed)),
		result,
	), nil
}

func validate(p *Payload) string {
	if len(p.Findings) == 0 && p.VulnerabilityID == "" {
		return "findings or vulnerability_id is required"
	}
	if len(p.Findings) > 0 && p.VulnerabilityID != "" {
		return "use either findings or vulnerability_id, not both"
	}
	if len(p.ResourceIDs) > 0 && p.VulnerabilityID == "" {
		return "resource_ids narrows vulnerability_id and needs it"
	}
	if len(p.Findings) > maxFindings {
		return fmt.Sprintf("findings supports at most %d entries per call, got %d", maxFindings, len(p.Findings))
	}
	if len(p.ResourceIDs) > maxResourceIDs {
		return fmt.Sprintf("resource_ids supports at most %d entries, got %d", maxResourceIDs, len(p.ResourceIDs))
	}
	if p.WorkflowStatus == "" && p.Note == "" && len(p.SetUserDefinedFields) == 0 && len(p.RemoveUserDefinedFields) == 0 {
		return "at least one of workflow_status, note, set_user_defined_fields or remove_user_defined_fields is required"
	}
	for k, v := range p.SetUserDefinedFields {
		if strings.TrimSpace(k) == "" || strings.TrimSpace(v) == "" {
			return "set_user_defined_fields keys and values must be non-empty (use remove_user_defined_fields to delete a key)"
		}
		if len(k) > maxUDFKey || len(v) > maxUDFValue {
			return fmt.Sprintf("user-defined field %q: keys are limited to %d and values to %d characters", k, maxUDFKey, maxUDFValue)
		}
	}
	return ""
}

// baseInput holds the parts of BatchUpdateFindingsInput shared by every call.
func baseInput(p *Payload) securityhub.BatchUpdateFindingsInput {
	var in securityhub.BatchUpdateFindingsInput
	if p.WorkflowStatus != "" {
		in.Workflow = &types.WorkflowUpdate{Status: types.WorkflowStatus(p.WorkflowStatus)}
	}
	if p.Note != "" {
		updatedBy := p.NoteUpdatedBy
		if updatedBy == "" {
			updatedBy = defaultUpdatedBy
		}
		in.Note = &types.NoteUpdate{Text: aws.String(p.Note), UpdatedBy: aws.String(updatedBy)}
	}
	return in
}

// batchUpdate writes base to refs, maxFindings per call, appending to result.
func batchUpdate(ctx context.Context, client api, base securityhub.BatchUpdateFindingsInput, refs []FindingRef, result *UpdateResult) error {
	for start := 0; start < len(refs); start += maxFindings {
		in := base
		in.FindingIdentifiers = nil
		for _, f := range refs[start:min(start+maxFindings, len(refs))] {
			in.FindingIdentifiers = append(in.FindingIdentifiers, types.AwsSecurityFindingIdentifier{Id: aws.String(f.ID), ProductArn: aws.String(f.ProductArn)})
		}
		out, err := client.BatchUpdateFindings(ctx, &in)
		if err != nil {
			return err
		}
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
	}
	return nil
}
