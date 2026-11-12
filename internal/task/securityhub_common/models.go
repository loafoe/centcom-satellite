// Package securityhub_common holds shared payload fields, filter construction,
// and normalized output models for the Security Hub tasks.
package securityhub_common

import (
	"encoding/json"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/securityhub/types"
)

// Finding is the normalized finding model. The full SDK finding is preserved in
// Detail so a dashboard can render everything without the satellite having to
// model every nested Security Hub structure.
type Finding struct {
	ID                 string   `json:"id"`
	ProductArn         string   `json:"product_arn"`
	ProductName        string   `json:"product_name,omitempty"`
	Title              string   `json:"title,omitempty"`
	Description        string   `json:"description,omitempty"`
	Types              []string `json:"types,omitempty"`
	SeverityLabel      string   `json:"severity_label,omitempty"`
	SeverityNormalized int32    `json:"severity_normalized,omitempty"`
	WorkflowStatus     string   `json:"workflow_status,omitempty"`
	RecordState        string   `json:"record_state,omitempty"`
	ComplianceStatus   string   `json:"compliance_status,omitempty"`
	ResourceType       string   `json:"resource_type,omitempty"`
	ResourceID         string   `json:"resource_id,omitempty"`
	AWSAccountID       string   `json:"aws_account_id,omitempty"`
	Region             string   `json:"region,omitempty"`
	CreatedAt          string   `json:"created_at,omitempty"`
	UpdatedAt          string   `json:"updated_at,omitempty"`
	// VulnerabilityID, CVSS, EPSS, FixAvailable and ExploitAvailable are
	// extracted from the ASFF Vulnerabilities field (present on
	// Inspector-generated findings, including EC2 instance OS/package
	// findings — these are a separate field from PackageVulnerabilityDetails,
	// which only Inspector2's own native API uses, see
	// running_image_vulnerabilities' maxCvssBaseScore). CVSS/EPSS are the max
	// across every entry/source a finding carries, same convention as
	// running_image_vulnerabilities. Empty/zero when a finding carries no
	// Vulnerabilities entries (e.g. a non-Inspector Security Hub finding).
	VulnerabilityID  string  `json:"vulnerability_id,omitempty"`
	CVSS             float64 `json:"cvss,omitempty"`
	EPSS             float64 `json:"epss,omitempty"`
	FixAvailable     string  `json:"fix_available,omitempty"`
	ExploitAvailable string  `json:"exploit_available,omitempty"`
	// NoteText / NoteUpdatedBy / NoteUpdatedAt are the finding's
	// investigation note, if any.
	NoteText      string          `json:"note_text,omitempty"`
	NoteUpdatedBy string          `json:"note_updated_by,omitempty"`
	NoteUpdatedAt string          `json:"note_updated_at,omitempty"`
	Detail        json.RawMessage `json:"detail,omitempty"`
}

// NormalizeFinding maps an SDK finding to the normalized model. The full finding
// is marshaled into Detail; marshal failures leave Detail nil rather than erroring.
func NormalizeFinding(f types.AwsSecurityFinding) Finding {
	out := Finding{
		ID:           aws.ToString(f.Id),
		ProductArn:   aws.ToString(f.ProductArn),
		ProductName:  aws.ToString(f.ProductName),
		Title:        aws.ToString(f.Title),
		Description:  aws.ToString(f.Description),
		Types:        f.Types,
		RecordState:  string(f.RecordState),
		AWSAccountID: aws.ToString(f.AwsAccountId),
		Region:       aws.ToString(f.Region),
		CreatedAt:    aws.ToString(f.CreatedAt),
		UpdatedAt:    aws.ToString(f.UpdatedAt),
	}
	if f.Severity != nil {
		out.SeverityLabel = string(f.Severity.Label)
		out.SeverityNormalized = aws.ToInt32(f.Severity.Normalized)
	}
	if f.Workflow != nil {
		out.WorkflowStatus = string(f.Workflow.Status)
	}
	if f.Note != nil {
		out.NoteText = aws.ToString(f.Note.Text)
		out.NoteUpdatedBy = aws.ToString(f.Note.UpdatedBy)
		out.NoteUpdatedAt = aws.ToString(f.Note.UpdatedAt)
	}
	if f.Compliance != nil {
		out.ComplianceStatus = string(f.Compliance.Status)
	}
	if len(f.Resources) > 0 {
		out.ResourceType = aws.ToString(f.Resources[0].Type)
		out.ResourceID = aws.ToString(f.Resources[0].Id)
	}
	for _, v := range f.Vulnerabilities {
		if out.VulnerabilityID == "" {
			out.VulnerabilityID = aws.ToString(v.Id)
		}
		for _, c := range v.Cvss {
			if c.BaseScore != nil && *c.BaseScore > out.CVSS {
				out.CVSS = *c.BaseScore
			}
		}
		if v.EpssScore != nil && *v.EpssScore > out.EPSS {
			out.EPSS = *v.EpssScore
		}
		if fa := string(v.FixAvailable); fa != "" && (out.FixAvailable == "" || fa == "YES") {
			out.FixAvailable = fa
		}
		if string(v.ExploitAvailable) == "YES" {
			out.ExploitAvailable = "YES"
		} else if out.ExploitAvailable == "" && v.ExploitAvailable != "" {
			out.ExploitAvailable = string(v.ExploitAvailable)
		}
	}
	if raw, err := json.Marshal(f); err == nil {
		out.Detail = raw
	}
	return out
}

// Standard is the normalized compliance standard model, combining
// DescribeStandards metadata with the account's subscription status.
type Standard struct {
	StandardsArn     string `json:"standards_arn"`
	Name             string `json:"name,omitempty"`
	Description      string `json:"description,omitempty"`
	EnabledByDefault bool   `json:"enabled_by_default"`
	Status           string `json:"status,omitempty"`
}

// HubStatus is the normalized DescribeHub result.
type HubStatus struct {
	HubArn                  string `json:"hub_arn"`
	SubscribedAt            string `json:"subscribed_at,omitempty"`
	AutoEnableControls      bool   `json:"auto_enable_controls"`
	ControlFindingGenerator string `json:"control_finding_generator,omitempty"`
}

// StatCount is one bucket in a findings-statistics breakdown. Capped is true
// when Count was capped at a per-bucket query limit rather than an exhaustive
// scan — in that case Count is a lower bound, not an exact total.
type StatCount struct {
	Key    string `json:"key"`
	Count  int32  `json:"count"`
	Capped bool   `json:"capped,omitempty"`
}
