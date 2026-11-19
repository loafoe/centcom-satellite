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

// account_ids: narrows ListCoverage and ListFindings to specific member
// accounts (meaningful only when this satellite's identity is an Inspector
// delegated administrator — a no-op filter value on every other satellite,
// since ListCoverage/ListFindings already only ever see the calling
// account's own resources).
func TestExecute_AccountIDsFilter(t *testing.T) {
	fake := filterFake()
	r := run(t, fake, `{"resource_type":"ec2","account_ids":[" 111111111111 ","111111111111"]}`, time.Minute)
	if strings.Join(r.AppliedFilters, ",") != "account_ids" {
		t.Errorf("applied_filters = %v, want [account_ids]", r.AppliedFilters)
	}
	sentToFindings := false
	for _, fc := range fake.filters {
		for _, id := range fc.AwsAccountId {
			if aws.ToString(id.Value) != "111111111111" {
				t.Errorf("ListFindings AwsAccountId filter = %s, want 111111111111", aws.ToString(id.Value))
			}
			sentToFindings = true
		}
	}
	if !sentToFindings {
		t.Error("account_ids never reached ListFindings' FilterCriteria.AwsAccountId")
	}
	sentToCoverage := false
	for _, fc := range fake.coverageFilters {
		for _, id := range fc.AccountId {
			if aws.ToString(id.Value) != "111111111111" {
				t.Errorf("ListCoverage AccountId filter = %s, want 111111111111", aws.ToString(id.Value))
			}
			sentToCoverage = true
		}
	}
	if !sentToCoverage {
		t.Error("account_ids never reached ListCoverage's CoverageFilterCriteria.AccountId")
	}
	// Deduped (the payload passed the same ID twice, trimmed/untrimmed).
	for _, fc := range fake.filters {
		if len(fc.AwsAccountId) > 1 {
			t.Errorf("AwsAccountId not deduped: %d entries", len(fc.AwsAccountId))
		}
	}
}

// Resource.AccountID is populated from ListCoverage's own CoveredResource.AccountId
// — present for every covered resource, independent of the account_ids filter.
func TestExecute_ResourceAccountIDFromCoverage(t *testing.T) {
	covered := ec2Coverage("i-1", "web-1", "ACTIVE")
	covered.AccountId = aws.String("222222222222")
	fake := &fakeInspector{
		covered:  []itypes.CoveredResource{covered},
		findings: []itypes.Finding{pkgFinding("i-1", "CVE-A", itypes.SeverityCritical, 9.8, itypes.FixAvailableYes)},
	}
	r := run(t, fake, `{"resource_type":"ec2"}`, time.Minute)
	if len(r.Resources) != 1 || r.Resources[0].AccountID != "222222222222" {
		t.Fatalf("resources = %+v, want one resource with account_id 222222222222", r.Resources)
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
