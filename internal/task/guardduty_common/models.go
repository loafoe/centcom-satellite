package guardduty_common

import (
	"encoding/json"

	"github.com/aws/aws-sdk-go-v2/aws"
	gdtypes "github.com/aws/aws-sdk-go-v2/service/guardduty/types"
)

// Detector is the normalized detector model.
type Detector struct {
	ID                         string            `json:"id"`
	Status                     string            `json:"status"`
	ServiceRole                string            `json:"service_role,omitempty"`
	FindingPublishingFrequency string            `json:"finding_publishing_frequency,omitempty"`
	CreatedAt                  string            `json:"created_at,omitempty"`
	UpdatedAt                  string            `json:"updated_at,omitempty"`
	Features                   []DetectorFeature `json:"features,omitempty"`
}

// DetectorFeature is one enabled/disabled GuardDuty feature on a detector.
type DetectorFeature struct {
	Name   string `json:"name"`
	Status string `json:"status"`
}

// Finding is the normalized finding model. The full SDK finding is preserved in
// Detail so a dashboard can render everything without the satellite having to
// model every nested GuardDuty structure.
type Finding struct {
	ID            string          `json:"id"`
	ARN           string          `json:"arn,omitempty"`
	Type          string          `json:"type"`
	Title         string          `json:"title,omitempty"`
	Description   string          `json:"description,omitempty"`
	Severity      float64         `json:"severity"`
	SeverityLabel string          `json:"severity_label"`
	Confidence    float64         `json:"confidence,omitempty"`
	AccountID     string          `json:"account_id,omitempty"`
	Region        string          `json:"region,omitempty"`
	ResourceType  string          `json:"resource_type,omitempty"`
	CreatedAt     string          `json:"created_at,omitempty"`
	UpdatedAt     string          `json:"updated_at,omitempty"`
	Count         int32           `json:"count,omitempty"`
	Detail        json.RawMessage `json:"detail,omitempty"`
}

// NormalizeFinding maps an SDK finding to the normalized model. The full finding
// is marshaled into Detail; marshal failures leave Detail nil rather than erroring.
func NormalizeFinding(f gdtypes.Finding) Finding {
	out := Finding{
		ID:          aws.ToString(f.Id),
		ARN:         aws.ToString(f.Arn),
		Type:        aws.ToString(f.Type),
		Title:       aws.ToString(f.Title),
		Description: aws.ToString(f.Description),
		Severity:    aws.ToFloat64(f.Severity),
		Confidence:  aws.ToFloat64(f.Confidence),
		AccountID:   aws.ToString(f.AccountId),
		Region:      aws.ToString(f.Region),
		CreatedAt:   aws.ToString(f.CreatedAt),
		UpdatedAt:   aws.ToString(f.UpdatedAt),
	}
	out.SeverityLabel = SeverityLabel(out.Severity)
	if f.Resource != nil {
		out.ResourceType = aws.ToString(f.Resource.ResourceType)
	}
	if f.Service != nil {
		out.Count = aws.ToInt32(f.Service.Count)
	}
	if raw, err := json.Marshal(f); err == nil {
		out.Detail = raw
	}
	return out
}

// StatCount is one bucket in a findings-statistics breakdown.
type StatCount struct {
	Key   string `json:"key"`
	Count int32  `json:"count"`
}
