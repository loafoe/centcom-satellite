package securityhub_common

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/securityhub/types"
)

func TestBuildFilters_DefaultsToActiveRecordState(t *testing.T) {
	f := Filter{}.BuildFilters()
	if len(f.RecordState) != 1 || f.RecordState[0].Value == nil || *f.RecordState[0].Value != "ACTIVE" {
		t.Fatalf("RecordState = %+v, want [ACTIVE]", f.RecordState)
	}
	if f.RecordState[0].Comparison != types.StringFilterComparisonEquals {
		t.Errorf("comparison = %v, want EQUALS", f.RecordState[0].Comparison)
	}
}

func TestBuildFilters_ExplicitRecordStateOverridesDefault(t *testing.T) {
	f := Filter{RecordState: "ARCHIVED"}.BuildFilters()
	if len(f.RecordState) != 1 || *f.RecordState[0].Value != "ARCHIVED" {
		t.Fatalf("RecordState = %+v, want [ARCHIVED]", f.RecordState)
	}
}

func TestBuildFilters_FullFilter(t *testing.T) {
	filter := Filter{
		SeverityLabels: []string{"HIGH", "CRITICAL"},
		Types:          []string{"TTPs/Command and Control"},
		ProductName:    "GuardDuty",
		WorkflowStatus: []string{"NEW", "NOTIFIED"},
		RecordState:    "ACTIVE",
		ResourceType:   "AwsEc2Instance",
		AWSAccountID:   "123456789012",
		UpdatedAfter:   "2026-07-01T00:00:00Z",
		UpdatedBefore:  "2026-07-27T00:00:00Z",
	}
	f := filter.BuildFilters()

	if len(f.SeverityLabel) != 2 {
		t.Errorf("SeverityLabel len = %d, want 2", len(f.SeverityLabel))
	}
	if len(f.Type) != 1 || *f.Type[0].Value != "TTPs/Command and Control" {
		t.Errorf("Type = %+v", f.Type)
	}
	if len(f.ProductName) != 1 || *f.ProductName[0].Value != "GuardDuty" {
		t.Errorf("ProductName = %+v", f.ProductName)
	}
	if len(f.WorkflowStatus) != 2 {
		t.Errorf("WorkflowStatus len = %d, want 2", len(f.WorkflowStatus))
	}
	if len(f.ResourceType) != 1 || *f.ResourceType[0].Value != "AwsEc2Instance" {
		t.Errorf("ResourceType = %+v", f.ResourceType)
	}
	if len(f.AwsAccountId) != 1 || *f.AwsAccountId[0].Value != "123456789012" {
		t.Errorf("AwsAccountId = %+v", f.AwsAccountId)
	}
	if len(f.UpdatedAt) != 1 || f.UpdatedAt[0].DateRange != nil {
		t.Fatalf("UpdatedAt = %+v, want a single DateFilter with Start/End set", f.UpdatedAt)
	}
	if *f.UpdatedAt[0].Start != "2026-07-01T00:00:00Z" || *f.UpdatedAt[0].End != "2026-07-27T00:00:00Z" {
		t.Errorf("UpdatedAt range = [%s,%s]", *f.UpdatedAt[0].Start, *f.UpdatedAt[0].End)
	}
}

func TestBuildFilters_EmptyFiltersOmitted(t *testing.T) {
	f := Filter{}.BuildFilters()
	if len(f.Type) != 0 || len(f.ProductName) != 0 || len(f.WorkflowStatus) != 0 || len(f.ResourceType) != 0 || len(f.AwsAccountId) != 0 || len(f.UpdatedAt) != 0 || len(f.Region) != 0 {
		t.Errorf("expected all unset filters to be empty, got %+v", f)
	}
}

// TestBuildFilters_RegionOmittedUnlessSet verifies BuildFilters never emits a
// Region filter unless WithResolvedRegion set one — Region is not a
// caller-supplied payload field (it has no json tag), only ever populated by
// a task's own resolved AWS region.
func TestBuildFilters_RegionOmittedUnlessSet(t *testing.T) {
	f := Filter{}.BuildFilters()
	if len(f.Region) != 0 {
		t.Errorf("Region = %+v, want empty when WithResolvedRegion was never called", f.Region)
	}
}

// TestWithResolvedRegion_SetsRegionFilter verifies WithResolvedRegion is the
// only way Filter.Region gets populated, and BuildFilters translates it into
// an equals StringFilter — this is the mechanism every securityhub_* task
// uses to keep Security Hub's cross-region finding aggregation from leaking
// other regions' findings into results scoped to one satellite's region.
func TestWithResolvedRegion_SetsRegionFilter(t *testing.T) {
	f := Filter{}.WithResolvedRegion("eu-west-1").BuildFilters()
	if len(f.Region) != 1 {
		t.Fatalf("Region = %+v, want exactly one filter", f.Region)
	}
	if *f.Region[0].Value != "eu-west-1" {
		t.Errorf("Region value = %q, want eu-west-1", *f.Region[0].Value)
	}
	if f.Region[0].Comparison != types.StringFilterComparisonEquals {
		t.Errorf("Region comparison = %v, want EQUALS", f.Region[0].Comparison)
	}
}

// TestWithResolvedRegion_DoesNotMutateReceiver verifies WithResolvedRegion
// returns a modified copy rather than mutating the original Filter value —
// callers build a Filter once from a JSON payload and must be able to reuse
// it (e.g. across cappedBucketStats' per-bucket loop) without one call's
// WithResolvedRegion leaking into another's base filter.
func TestWithResolvedRegion_DoesNotMutateReceiver(t *testing.T) {
	base := Filter{SeverityLabels: []string{"HIGH"}}
	_ = base.WithResolvedRegion("eu-west-1")
	if base.Region != "" {
		t.Errorf("base.Region = %q, want unchanged empty string", base.Region)
	}
}

func TestSortCriteria_Defaults(t *testing.T) {
	sc := SortCriteria("", true)
	if len(sc) != 1 || *sc[0].Field != "SeverityNormalized" {
		t.Fatalf("default field = %+v, want SeverityNormalized", sc)
	}
	if sc[0].SortOrder != types.SortOrderDescending {
		t.Errorf("order = %q, want desc", sc[0].SortOrder)
	}
}

func TestSortCriteria_AscendingCustomField(t *testing.T) {
	sc := SortCriteria("UpdatedAt", false)
	if *sc[0].Field != "UpdatedAt" {
		t.Errorf("field = %q, want UpdatedAt", *sc[0].Field)
	}
	if sc[0].SortOrder != types.SortOrderAscending {
		t.Errorf("order = %q, want asc", sc[0].SortOrder)
	}
}
