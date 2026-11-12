package aws_resource_vulnerabilities

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/inspector2"
	itypes "github.com/aws/aws-sdk-go-v2/service/inspector2/types"
)

// fakeInspector serves coverage from a fixed list and findings filtered by
// the request's resourceId values, paging findings pageSize at a time.
type fakeInspector struct {
	covered  []itypes.CoveredResource
	findings []itypes.Finding
	pageSize int
	delay    time.Duration

	mu      sync.Mutex
	filters []*itypes.FilterCriteria
}

func (f *fakeInspector) ListCoverage(_ context.Context, _ *inspector2.ListCoverageInput, _ ...func(*inspector2.Options)) (*inspector2.ListCoverageOutput, error) {
	return &inspector2.ListCoverageOutput{CoveredResources: f.covered}, nil
}

func (f *fakeInspector) ListFindings(ctx context.Context, in *inspector2.ListFindingsInput, _ ...func(*inspector2.Options)) (*inspector2.ListFindingsOutput, error) {
	f.mu.Lock()
	f.filters = append(f.filters, in.FilterCriteria)
	f.mu.Unlock()
	if f.delay > 0 {
		select {
		case <-time.After(f.delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	want := map[string]bool{}
	for _, id := range in.FilterCriteria.ResourceId {
		want[aws.ToString(id.Value)] = true
	}
	sevs := map[string]bool{}
	for _, s := range in.FilterCriteria.Severity {
		sevs[aws.ToString(s.Value)] = true
	}
	var match []itypes.Finding
	for _, fd := range f.findings {
		if want[aws.ToString(fd.Resources[0].Id)] && sevs[string(fd.Severity)] {
			match = append(match, fd)
		}
	}
	start := 0
	if in.NextToken != nil {
		start = len(aws.ToString(in.NextToken))
	}
	size := f.pageSize
	if size == 0 {
		size = 100
	}
	end := min(start+size, len(match))
	out := &inspector2.ListFindingsOutput{Findings: match[start:end]}
	if end < len(match) {
		out.NextToken = aws.String(strings.Repeat("x", end))
	}
	return out, nil
}

func ec2Coverage(id, name, status string) itypes.CoveredResource {
	return itypes.CoveredResource{
		ResourceId: aws.String(id), ResourceType: itypes.CoverageResourceTypeAwsEc2Instance,
		ScanStatus:       &itypes.ScanStatus{StatusCode: itypes.ScanStatusCode(status), Reason: itypes.ScanStatusReasonSuccessful},
		ResourceMetadata: &itypes.ResourceScanMetadata{Ec2: &itypes.Ec2Metadata{AmiId: aws.String("ami-1"), Platform: itypes.Ec2PlatformLinux, Tags: map[string]string{"Name": name}}},
	}
}

func pkgFinding(resID, cve string, sev itypes.Severity, cvss float64, fix itypes.FixAvailable) itypes.Finding {
	return itypes.Finding{
		Title: aws.String(cve + " - openssl"), Type: itypes.FindingTypePackageVulnerability, Severity: sev,
		FixAvailable: fix, ExploitAvailable: itypes.ExploitAvailableNo,
		Description: aws.String("a description"),
		Epss:        &itypes.EpssDetails{Score: 0.5},
		Resources: []itypes.Resource{{
			Id: aws.String(resID), Type: itypes.ResourceTypeAwsEc2Instance,
			Details: &itypes.ResourceDetails{AwsEc2Instance: &itypes.AwsEc2InstanceDetails{Type: aws.String("t3.small"), IpV4Addresses: []string{"10.0.0.1"}}},
		}},
		PackageVulnerabilityDetails: &itypes.PackageVulnerabilityDetails{
			VulnerabilityId: aws.String(cve), SourceUrl: aws.String("https://nvd.nist.gov/vuln/detail/" + cve),
			Cvss:               []itypes.CvssScore{{BaseScore: aws.Float64(cvss - 1)}, {BaseScore: aws.Float64(cvss)}},
			VulnerablePackages: []itypes.VulnerablePackage{{Name: aws.String("openssl"), Version: aws.String("3.0.1"), Release: aws.String("1.el9"), FixedInVersion: aws.String("3.0.2")}},
		},
	}
}

func run(t *testing.T, fake *fakeInspector, payload string, budget time.Duration) Report {
	t.Helper()
	tk := &Task{
		clients: func(context.Context, string) (inspectorAPI, string, string, error) {
			return fake, "us-east-1", "111111111111", nil
		},
		budget: budget,
	}
	res, err := tk.Execute(context.Background(), json.RawMessage(payload))
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !res.Success {
		t.Fatalf("not successful: %s", res.Error)
	}
	var r Report
	b, _ := json.Marshal(res.Details)
	if err := json.Unmarshal(b, &r); err != nil {
		t.Fatal(err)
	}
	return r
}

func TestExecute_GroupsByVulnerabilityAndResource(t *testing.T) {
	fake := &fakeInspector{
		covered: []itypes.CoveredResource{
			ec2Coverage("i-1", "web-1", "ACTIVE"), ec2Coverage("i-2", "db-1", "ACTIVE"), ec2Coverage("i-3", "idle", "INACTIVE"),
		},
		findings: []itypes.Finding{
			pkgFinding("i-1", "CVE-A", itypes.SeverityCritical, 9.8, itypes.FixAvailableYes),
			pkgFinding("i-2", "CVE-A", itypes.SeverityCritical, 9.8, itypes.FixAvailableYes),
			pkgFinding("i-1", "CVE-B", itypes.SeverityCritical, 9.1, itypes.FixAvailableNo),
		},
	}
	r := run(t, fake, `{"resource_type":"AwsEc2Instance"}`, time.Minute)

	if r.ResourceType != ResourceEC2 || !r.Complete || r.TotalFindings != 3 {
		t.Fatalf("report header = %+v", r)
	}
	if r.Coverage.Resources != 3 || r.Coverage.Scanned != 2 || r.Coverage.NotScanned != 1 || r.Coverage.WithFindings != 2 {
		t.Errorf("coverage = %+v", r.Coverage)
	}
	if r.VulnerabilitiesTotal != 2 || r.Vulnerabilities[0].ID != "CVE-A" {
		t.Fatalf("vulnerabilities = %+v", r.Vulnerabilities)
	}
	a := r.Vulnerabilities[0]
	if a.Resources != 2 || len(a.ResourceIDs) != 2 || a.CVSS != 9.8 || a.EPSS != 0.5 || a.FixAvailable != "YES" {
		t.Errorf("CVE-A = %+v", a)
	}
	if len(a.Packages) != 1 || a.Packages[0].Version != "3.0.1-1.el9" || a.Packages[0].FixedInVersion != "3.0.2" {
		t.Errorf("CVE-A packages = %+v", a.Packages)
	}
	if a.SourceURL == "" || a.Description == "" {
		t.Errorf("CVE-A missing description/source: %+v", a)
	}
	if r.ResourcesTotal != 2 {
		t.Fatalf("resources = %+v", r.Resources)
	}
	web := r.Resources[0]
	if web.ID != "i-1" || web.Name != "web-1" || web.Findings != 2 || web.Vulnerabilities != 2 || web.Fixable != 1 {
		t.Errorf("first resource = %+v", web)
	}
	if web.EC2 == nil || web.EC2.InstanceType != "t3.small" || web.EC2.ImageID != "ami-1" || len(web.EC2.IPv4Addresses) != 1 {
		t.Errorf("ec2 details = %+v", web.EC2)
	}
	if len(web.VulnerabilityIDs) != 2 || web.VulnerabilityIDs[0] != "CVE-A" {
		t.Errorf("vulnerability ids = %v, want highest CVSS first", web.VulnerabilityIDs)
	}
}

func TestExecute_BatchesResourceIDsTenPerCall(t *testing.T) {
	fake := &fakeInspector{}
	for i := 0; i < 25; i++ {
		fake.covered = append(fake.covered, ec2Coverage("i-"+string(rune('a'+i)), "", "ACTIVE"))
	}
	run(t, fake, `{"resource_type":"EC2"}`, time.Minute)
	if len(fake.filters) != 3 {
		t.Fatalf("ListFindings calls = %d, want 3 (25 resources / 10)", len(fake.filters))
	}
	for _, f := range fake.filters {
		if len(f.ResourceId) > idsPerCall {
			t.Errorf("filter has %d resource IDs, max %d", len(f.ResourceId), idsPerCall)
		}
		if len(f.FindingType) != 2 {
			t.Errorf("finding types = %v, want package + code vulnerabilities only", f.FindingType)
		}
	}
}

func TestExecute_PaginatesFindings(t *testing.T) {
	fake := &fakeInspector{covered: []itypes.CoveredResource{ec2Coverage("i-1", "", "ACTIVE")}, pageSize: 2}
	for _, cve := range []string{"CVE-1", "CVE-2", "CVE-3", "CVE-4", "CVE-5"} {
		fake.findings = append(fake.findings, pkgFinding("i-1", cve, itypes.SeverityCritical, 9, itypes.FixAvailableYes))
	}
	r := run(t, fake, `{"resource_type":"AWS_EC2_INSTANCE"}`, time.Minute)
	if r.TotalFindings != 5 || r.VulnerabilitiesTotal != 5 || len(fake.filters) != 3 {
		t.Errorf("findings=%d vulns=%d calls=%d, want 5/5/3", r.TotalFindings, r.VulnerabilitiesTotal, len(fake.filters))
	}
}

func TestExecute_BudgetReturnsPartial(t *testing.T) {
	fake := &fakeInspector{covered: []itypes.CoveredResource{ec2Coverage("i-1", "", "ACTIVE")}, delay: 200 * time.Millisecond}
	r := run(t, fake, `{"resource_type":"AWS_EC2_INSTANCE"}`, 50*time.Millisecond)
	if r.Complete || r.StopReason != "time_budget" {
		t.Errorf("complete=%v stop=%q, want a partial time_budget result", r.Complete, r.StopReason)
	}
}

func TestExecute_LambdaDetails(t *testing.T) {
	arn := "arn:aws:lambda:us-east-1:111111111111:function:reports:$LATEST"
	fake := &fakeInspector{
		covered: []itypes.CoveredResource{{
			ResourceId: aws.String(arn), ResourceType: itypes.CoverageResourceTypeAwsLambdaFunction,
			ScanStatus:       &itypes.ScanStatus{StatusCode: itypes.ScanStatusCodeActive, Reason: itypes.ScanStatusReasonSuccessful},
			ResourceMetadata: &itypes.ResourceScanMetadata{LambdaFunction: &itypes.LambdaFunctionMetadata{FunctionName: aws.String("reports"), Runtime: itypes.RuntimePython313, Layers: []string{"arn:layer:1"}}},
		}},
	}
	f := pkgFinding(arn, "CVE-L", itypes.SeverityHigh, 8.1, itypes.FixAvailableYes)
	f.Resources[0].Details = &itypes.ResourceDetails{AwsLambdaFunction: &itypes.AwsLambdaFunctionDetails{FunctionName: aws.String("reports"), Version: aws.String("$LATEST")}}
	fake.findings = []itypes.Finding{f}

	r := run(t, fake, `{"resource_type":"lambda","severities":["HIGH"]}`, time.Minute)
	if r.ResourceType != ResourceLambda || r.ResourcesTotal != 1 {
		t.Fatalf("report = %+v", r)
	}
	res := r.Resources[0]
	if res.Name != "reports" || res.Lambda == nil || res.Lambda.Runtime != "PYTHON_3_13" || res.Lambda.Version != "$LATEST" || len(res.Lambda.Layers) != 1 {
		t.Errorf("lambda resource = %+v / %+v", res, res.Lambda)
	}
}

func TestExecute_RejectsInvalidPayload(t *testing.T) {
	tk := &Task{clients: func(context.Context, string) (inspectorAPI, string, string, error) {
		t.Fatal("no AWS call expected for an invalid payload")
		return nil, "", "", nil
	}}
	for _, p := range []string{`{}`, `{"resource_type":"S3"}`, `{"resource_type":"EC2","severities":["BAD"]}`, `{"resource_type":"EC2","fix_available":"MAYBE"}`} {
		res, err := tk.Execute(context.Background(), json.RawMessage(p))
		if err != nil || res.Success {
			t.Errorf("payload %s: success=%v err=%v, want a self-describing error result", p, res.Success, err)
		}
	}
}

func TestTruncate(t *testing.T) {
	if got := truncate("héllo wörld", 2); got != "h…" {
		t.Errorf("truncate on a rune boundary = %q", got)
	}
	if got := truncate("short", 10); got != "short" {
		t.Errorf("truncate(short) = %q", got)
	}
}
