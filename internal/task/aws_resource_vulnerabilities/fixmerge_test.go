package aws_resource_vulnerabilities

import (
	"testing"
	"time"

	itypes "github.com/aws/aws-sdk-go-v2/service/inspector2/types"
)

// TestExecute_ResourceFixableCountsOwnFindingsOnly: a CVE fixable on i-1 but
// not on i-2 is fixable for the vulnerability, yet i-2 must not count it as
// fixable (it used to whenever i-1's finding was processed first), in
// either order.
func TestExecute_ResourceFixableCountsOwnFindingsOnly(t *testing.T) {
	for _, fixFirst := range []bool{true, false} {
		yes := pkgFinding("i-1", "CVE-MIX", itypes.SeverityHigh, 8.1, itypes.FixAvailableYes)
		no := pkgFinding("i-2", "CVE-MIX", itypes.SeverityHigh, 8.1, itypes.FixAvailableNo)
		findings := []itypes.Finding{yes, no}
		if !fixFirst {
			findings = []itypes.Finding{no, yes}
		}
		fake := &fakeInspector{
			covered:  []itypes.CoveredResource{ec2Coverage("i-1", "web-1", "ACTIVE"), ec2Coverage("i-2", "web-2", "ACTIVE")},
			findings: findings,
		}
		r := run(t, fake, `{"resource_type":"AwsEc2Instance","severities":["HIGH"]}`, time.Minute)
		if len(r.Vulnerabilities) != 1 || r.Vulnerabilities[0].FixAvailable != "YES" {
			t.Fatalf("fixFirst=%v: vulnerability fix = %+v, want YES", fixFirst, r.Vulnerabilities)
		}
		got := map[string]int{}
		for _, res := range r.Resources {
			got[res.ID] = res.Fixable
		}
		if got["i-1"] != 1 || got["i-2"] != 0 {
			t.Fatalf("fixFirst=%v: fixable per resource = %v, want i-1:1 i-2:0", fixFirst, got)
		}
	}
}
