package securityhub_common

import (
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/securityhub/types"
)

// Filter is the pragmatic subset of AwsSecurityFindingFilters we expose.
// Every field is optional except RecordState, which defaults to "ACTIVE"
// when empty (matching the Security Hub console default).
type Filter struct {
	// SeverityLabels keeps findings whose SeverityLabel is in this list
	// (INFORMATIONAL, LOW, MEDIUM, HIGH, CRITICAL).
	SeverityLabels []string `json:"severity_labels,omitempty"`
	// Types keeps findings whose Type is in this list (exact match).
	Types []string `json:"types,omitempty"`
	// ProductName keeps findings from this product (e.g. "GuardDuty", "Macie").
	ProductName string `json:"product_name,omitempty"`
	// WorkflowStatus keeps findings whose workflow status is in this list
	// (NEW, NOTIFIED, RESOLVED, SUPPRESSED).
	WorkflowStatus []string `json:"workflow_status,omitempty"`
	// RecordState selects ACTIVE vs. ARCHIVED findings. Defaults to ACTIVE
	// when empty, matching the Security Hub console default.
	RecordState string `json:"record_state,omitempty"`
	// ResourceType keeps findings for this resource type (e.g. "AwsEc2Instance").
	ResourceType string `json:"resource_type,omitempty"`
	// AWSAccountID keeps findings for this account ID.
	AWSAccountID string `json:"aws_account_id,omitempty"`
	// UpdatedAfter / UpdatedBefore bound UpdatedAt as RFC3339 timestamps.
	UpdatedAfter  string `json:"updated_after,omitempty"`
	UpdatedBefore string `json:"updated_before,omitempty"`
	// Region constrains findings to Security Hub's Region field (the region a
	// finding was generated in), NOT exposed on the task payload — callers
	// set it from the AWS client's own resolved region after LoadConfig, via
	// WithResolvedRegion. Security Hub's cross-region finding aggregation
	// (finding aggregators) means a GetFindings/CreateInsight call against
	// one region's API endpoint can silently return findings merged in from
	// every linked region if this filter is omitted; every task in this
	// package must set it so results reflect only the satellite's own region.
	Region string `json:"-"`
}

// WithResolvedRegion returns a copy of f with Region set, for constraining
// results to the AWS region a task actually resolved and dialed — see the
// Region field's doc comment for why this is required, not optional.
func (f Filter) WithResolvedRegion(region string) Filter {
	f.Region = region
	return f
}

// BuildFilters translates the Filter into Security Hub's AwsSecurityFindingFilters.
func (f Filter) BuildFilters() *types.AwsSecurityFindingFilters {
	out := &types.AwsSecurityFindingFilters{}

	recordState := f.RecordState
	if recordState == "" {
		recordState = "ACTIVE"
	}
	out.RecordState = []types.StringFilter{equalsFilter(recordState)}

	for _, s := range f.SeverityLabels {
		out.SeverityLabel = append(out.SeverityLabel, equalsFilter(s))
	}
	for _, t := range f.Types {
		out.Type = append(out.Type, equalsFilter(t))
	}
	if f.ProductName != "" {
		out.ProductName = []types.StringFilter{equalsFilter(f.ProductName)}
	}
	for _, w := range f.WorkflowStatus {
		out.WorkflowStatus = append(out.WorkflowStatus, equalsFilter(w))
	}
	if f.ResourceType != "" {
		out.ResourceType = []types.StringFilter{equalsFilter(f.ResourceType)}
	}
	if f.AWSAccountID != "" {
		out.AwsAccountId = []types.StringFilter{equalsFilter(f.AWSAccountID)}
	}
	if f.UpdatedAfter != "" || f.UpdatedBefore != "" {
		df := types.DateFilter{}
		if f.UpdatedAfter != "" {
			df.Start = aws.String(f.UpdatedAfter)
		}
		if f.UpdatedBefore != "" {
			df.End = aws.String(f.UpdatedBefore)
		}
		out.UpdatedAt = []types.DateFilter{df}
	}
	if f.Region != "" {
		out.Region = []types.StringFilter{equalsFilter(f.Region)}
	}

	return out
}

func equalsFilter(value string) types.StringFilter {
	return types.StringFilter{
		Value:      aws.String(value),
		Comparison: types.StringFilterComparisonEquals,
	}
}

// SortCriteria builds Security Hub SortCriterion list from a field + order,
// defaulting to SeverityNormalized descending (the most-severe-first ordering
// a dashboard wants).
func SortCriteria(field string, desc bool) []types.SortCriterion {
	if field == "" {
		field = "SeverityNormalized"
	}
	order := types.SortOrderDescending
	if !desc {
		order = types.SortOrderAscending
	}
	return []types.SortCriterion{{Field: aws.String(field), SortOrder: order}}
}
