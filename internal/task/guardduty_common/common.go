// Package guardduty_common holds shared payload fields, filter construction,
// detector resolution, and normalized output models for the GuardDuty tasks.
//
// GuardDuty is a regional service: every task takes an optional region (falling
// back to the SDK default chain) and an optional detector_id. When the detector
// ID is omitted, tasks resolve it by listing detectors in the region and using
// the first one — the single-detector-per-region case that is by far the norm.
package guardduty_common

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/guardduty"
	gdtypes "github.com/aws/aws-sdk-go-v2/service/guardduty/types"
)

// DetectorLister is the slice of the GuardDuty API used to resolve a detector ID.
type DetectorLister interface {
	ListDetectors(context.Context, *guardduty.ListDetectorsInput, ...func(*guardduty.Options)) (*guardduty.ListDetectorsOutput, error)
}

// ResolveDetectorID returns the provided detector ID unchanged, or discovers one
// by listing detectors in the current region. It returns a descriptive error
// when no detector exists so callers can surface it as a task error result.
func ResolveDetectorID(ctx context.Context, api DetectorLister, provided string) (string, error) {
	if provided != "" {
		return provided, nil
	}
	out, err := api.ListDetectors(ctx, &guardduty.ListDetectorsInput{})
	if err != nil {
		return "", fmt.Errorf("list detectors: %w", err)
	}
	if len(out.DetectorIds) == 0 {
		return "", fmt.Errorf("no GuardDuty detector found in this region; GuardDuty may not be enabled")
	}
	return out.DetectorIds[0], nil
}

// Filter is the pragmatic subset of GuardDuty FindingCriteria we expose. It is
// embedded in the list/statistics/composite payloads. Every field is optional.
type Filter struct {
	// MinSeverity keeps findings with severity >= this value (e.g. 7 for High).
	MinSeverity *float64 `json:"min_severity,omitempty"`
	// Types keeps findings whose type is in this list (exact match).
	Types []string `json:"types,omitempty"`
	// ResourceType keeps findings for this resource.resourceType (e.g. "Instance").
	ResourceType string `json:"resource_type,omitempty"`
	// Archived selects archived vs. unarchived findings. When nil, only
	// unarchived findings are returned, matching the GuardDuty console default.
	Archived *bool `json:"archived,omitempty"`
	// UpdatedAfter / UpdatedBefore bound updatedAt in epoch milliseconds.
	UpdatedAfter  *int64 `json:"updated_after,omitempty"`
	UpdatedBefore *int64 `json:"updated_before,omitempty"`
}

// BuildCriteria translates the Filter into a GuardDuty FindingCriteria. It always
// constrains service.archived (defaulting to false) so results match the console.
func (f Filter) BuildCriteria() *gdtypes.FindingCriteria {
	criterion := map[string]gdtypes.Condition{}

	if f.MinSeverity != nil {
		v := int64(*f.MinSeverity)
		criterion["severity"] = gdtypes.Condition{GreaterThanOrEqual: aws.Int64(v)}
	}
	if len(f.Types) > 0 {
		criterion["type"] = gdtypes.Condition{Equals: f.Types}
	}
	if f.ResourceType != "" {
		criterion["resource.resourceType"] = gdtypes.Condition{Equals: []string{f.ResourceType}}
	}

	archived := false
	if f.Archived != nil {
		archived = *f.Archived
	}
	criterion["service.archived"] = gdtypes.Condition{Equals: []string{fmt.Sprintf("%t", archived)}}

	if f.UpdatedAfter != nil || f.UpdatedBefore != nil {
		c := gdtypes.Condition{}
		if f.UpdatedAfter != nil {
			c.GreaterThanOrEqual = aws.Int64(*f.UpdatedAfter)
		}
		if f.UpdatedBefore != nil {
			c.LessThanOrEqual = aws.Int64(*f.UpdatedBefore)
		}
		criterion["updatedAt"] = c
	}

	return &gdtypes.FindingCriteria{Criterion: criterion}
}

// SortCriteria builds a GuardDuty SortCriteria from a field + order, defaulting
// to severity descending (the most-severe-first ordering a dashboard wants).
func SortCriteria(field string, desc bool) *gdtypes.SortCriteria {
	if field == "" {
		field = "severity"
	}
	order := gdtypes.OrderByDesc
	if !desc {
		order = gdtypes.OrderByAsc
	}
	return &gdtypes.SortCriteria{AttributeName: aws.String(field), OrderBy: order}
}

// SeverityLabel maps a numeric GuardDuty severity to its console label.
// GuardDuty severity bands: Low 1.0–3.9, Medium 4.0–6.9, High 7.0–8.9.
func SeverityLabel(sev float64) string {
	switch {
	case sev >= 7.0:
		return "High"
	case sev >= 4.0:
		return "Medium"
	case sev >= 1.0:
		return "Low"
	default:
		return "Informational"
	}
}
