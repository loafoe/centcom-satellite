package guardduty_common

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/guardduty"
)

type fakeDetectorLister struct {
	out *guardduty.ListDetectorsOutput
	err error
}

func (f *fakeDetectorLister) ListDetectors(_ context.Context, _ *guardduty.ListDetectorsInput, _ ...func(*guardduty.Options)) (*guardduty.ListDetectorsOutput, error) {
	return f.out, f.err
}

func TestResolveDetectorID_Provided(t *testing.T) {
	// A provided ID short-circuits and never calls the API.
	id, err := ResolveDetectorID(context.Background(), &fakeDetectorLister{err: errors.New("should not be called")}, "det-123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id != "det-123" {
		t.Fatalf("id = %q, want det-123", id)
	}
}

func TestResolveDetectorID_Discovered(t *testing.T) {
	api := &fakeDetectorLister{out: &guardduty.ListDetectorsOutput{DetectorIds: []string{"det-abc", "det-def"}}}
	id, err := ResolveDetectorID(context.Background(), api, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id != "det-abc" {
		t.Fatalf("id = %q, want det-abc (first detector)", id)
	}
}

func TestResolveDetectorID_None(t *testing.T) {
	api := &fakeDetectorLister{out: &guardduty.ListDetectorsOutput{DetectorIds: nil}}
	if _, err := ResolveDetectorID(context.Background(), api, ""); err == nil {
		t.Fatal("expected error when no detector exists")
	}
}

func TestBuildCriteria_DefaultsToUnarchived(t *testing.T) {
	crit := Filter{}.BuildCriteria()
	cond, ok := crit.Criterion["service.archived"]
	if !ok {
		t.Fatal("expected service.archived condition")
	}
	if len(cond.Equals) != 1 || cond.Equals[0] != "false" {
		t.Fatalf("service.archived = %v, want [false]", cond.Equals)
	}
}

func TestBuildCriteria_FullFilter(t *testing.T) {
	sev := 7.0
	archived := true
	after := int64(1000)
	before := int64(2000)
	crit := Filter{
		MinSeverity:   &sev,
		Types:         []string{"Recon:EC2/PortProbeUnprotectedPort"},
		ResourceType:  "Instance",
		Archived:      &archived,
		UpdatedAfter:  &after,
		UpdatedBefore: &before,
	}.BuildCriteria()

	if c := crit.Criterion["severity"]; c.GreaterThanOrEqual == nil || *c.GreaterThanOrEqual != 7 {
		t.Errorf("severity GTE = %v, want 7", c.GreaterThanOrEqual)
	}
	if c := crit.Criterion["type"]; len(c.Equals) != 1 || c.Equals[0] != "Recon:EC2/PortProbeUnprotectedPort" {
		t.Errorf("type = %v", c.Equals)
	}
	if c := crit.Criterion["resource.resourceType"]; len(c.Equals) != 1 || c.Equals[0] != "Instance" {
		t.Errorf("resourceType = %v", c.Equals)
	}
	if c := crit.Criterion["service.archived"]; len(c.Equals) != 1 || c.Equals[0] != "true" {
		t.Errorf("archived = %v, want [true]", c.Equals)
	}
	c := crit.Criterion["updatedAt"]
	if c.GreaterThanOrEqual == nil || *c.GreaterThanOrEqual != 1000 || c.LessThanOrEqual == nil || *c.LessThanOrEqual != 2000 {
		t.Errorf("updatedAt range = [%v,%v], want [1000,2000]", c.GreaterThanOrEqual, c.LessThanOrEqual)
	}
}

func TestSortCriteria_Defaults(t *testing.T) {
	sc := SortCriteria("", true)
	if aws.ToString(sc.AttributeName) != "severity" {
		t.Errorf("default field = %q, want severity", aws.ToString(sc.AttributeName))
	}
	if string(sc.OrderBy) != "DESC" {
		t.Errorf("order = %q, want DESC", sc.OrderBy)
	}
	if string(SortCriteria("updatedAt", false).OrderBy) != "ASC" {
		t.Error("expected ASC when desc=false")
	}
}

func TestSeverityLabel(t *testing.T) {
	cases := map[float64]string{
		0.5: "Informational",
		1.0: "Low",
		3.9: "Low",
		4.0: "Medium",
		6.9: "Medium",
		7.0: "High",
		8.9: "High",
	}
	for sev, want := range cases {
		if got := SeverityLabel(sev); got != want {
			t.Errorf("SeverityLabel(%v) = %q, want %q", sev, got, want)
		}
	}
}
