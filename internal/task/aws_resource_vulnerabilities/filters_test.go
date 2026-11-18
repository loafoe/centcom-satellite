package aws_resource_vulnerabilities

import (
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	itypes "github.com/aws/aws-sdk-go-v2/service/inspector2/types"
)

func filterFake() *fakeInspector {
	return &fakeInspector{
		covered: []itypes.CoveredResource{ec2Coverage("i-1", "web-1", "ACTIVE"), ec2Coverage("i-2", "db-1", "ACTIVE"), ec2Coverage("i-3", "batch", "ACTIVE")},
		findings: []itypes.Finding{
			pkgFinding("i-1", "CVE-A", itypes.SeverityCritical, 9.8, itypes.FixAvailableYes),
			pkgFinding("i-2", "CVE-A", itypes.SeverityCritical, 9.8, itypes.FixAvailableYes),
			pkgFinding("i-1", "CVE-B", itypes.SeverityCritical, 9.1, itypes.FixAvailableNo),
			pkgFinding("i-3", "CVE-C", itypes.SeverityCritical, 7.0, itypes.FixAvailableYes),
		},
	}
}

// resource_ids: only those instances are queried (no account-wide scan),
// with every one of their vulnerabilities.
func TestExecute_ResourceIDsFilter(t *testing.T) {
	fake := filterFake()
	r := run(t, fake, `{"resource_type":"ec2","resource_ids":[" i-1 ","i-1"]}`, time.Minute)
	if r.ResourcesTotal != 1 || r.Resources[0].ID != "i-1" || r.VulnerabilitiesTotal != 2 || r.Coverage.Resources != 1 {
		t.Fatalf("resources %+v, vulnerabilities %d, coverage %+v", r.Resources, r.VulnerabilitiesTotal, r.Coverage)
	}
	for _, fc := range fake.filters {
		for _, id := range fc.ResourceId {
			if v := aws.ToString(id.Value); v != "i-1" {
				t.Errorf("queried %s: the filter must keep other instances out of every call", v)
			}
		}
	}
	if strings.Join(r.AppliedFilters, ",") != "resource_ids" {
		t.Errorf("applied_filters = %v", r.AppliedFilters)
	}
}

// vulnerability_ids: one CVE across the account, sent to Inspector as a
// filter rather than filtered afterwards.
func TestExecute_VulnerabilityIDsFilter(t *testing.T) {
	fake := filterFake()
	r := run(t, fake, `{"resource_type":"ec2","vulnerability_ids":["cve-a"]}`, time.Minute)
	if r.VulnerabilitiesTotal != 1 || r.Vulnerabilities[0].ID != "CVE-A" || r.Vulnerabilities[0].Resources != 2 || r.ResourcesTotal != 2 {
		t.Fatalf("vulnerabilities %+v, resources %d", r.Vulnerabilities, r.ResourcesTotal)
	}
	sent := false
	for _, fc := range fake.filters {
		if len(fc.VulnerabilityId) == 1 && aws.ToString(fc.VulnerabilityId[0].Value) == "CVE-A" {
			sent = true
		}
	}
	if !sent || strings.Join(r.AppliedFilters, ",") != "vulnerability_ids" {
		t.Errorf("filter sent to Inspector: %v, applied_filters %v", sent, r.AppliedFilters)
	}
}

func TestResourceWanted_LambdaNameOrARN(t *testing.T) {
	arn := "arn:aws:lambda:us-east-1:111111111111:function:resize-images:$LATEST"
	for _, c := range []struct {
		filter string
		want   bool
	}{
		{arn, true},
		{"resize-images", true},
		{"arn:aws:lambda:us-east-1:111111111111:function:resize-images", true},
		{"resize", false},
		{"arn:aws:lambda:us-east-1:111111111111:function:resize", false},
	} {
		s := &scan{payload: Payload{ResourceIDs: []string{c.filter}}}
		if got := s.resourceWanted(arn); got != c.want {
			t.Errorf("filter %q: wanted = %v, want %v", c.filter, got, c.want)
		}
	}
}

func TestNormalize_FilterLimits(t *testing.T) {
	ids := make([]string, 11)
	for i := range ids {
		ids[i] = "CVE-" + strings.Repeat("1", i+1)
	}
	if msg := normalize(&Payload{ResourceType: "ec2", VulnerabilityIDs: ids}); !strings.Contains(msg, "at most 10") {
		t.Errorf("11 vulnerability_ids: %q", msg)
	}
}
