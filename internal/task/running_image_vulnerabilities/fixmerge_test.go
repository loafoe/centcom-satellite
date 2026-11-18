package running_image_vulnerabilities

import (
	"strings"
	"testing"

	itypes "github.com/aws/aws-sdk-go-v2/service/inspector2/types"
)

// TestExecute_FixAvailableIsOrderIndependent: a CVE fixable on one image but
// not on another must report fix YES (whatever order the findings arrive in;
// it used to be whichever finding came last) and name only the workload
// whose own image has the fix.
func TestExecute_FixAvailableIsOrderIndependent(t *testing.T) {
	const (
		dA = "sha256:a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1"
		dB = "sha256:b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2"
	)
	withFix := func(f itypes.Finding, fix itypes.FixAvailable, exploit itypes.ExploitAvailable) itypes.Finding {
		f.FixAvailable, f.ExploitAvailable = fix, exploit
		return f
	}
	active := itypes.ScanStatus{StatusCode: itypes.ScanStatusCodeActive, Reason: itypes.ScanStatusReasonSuccessful}
	for _, order := range []string{"fix-first", "fix-last"} {
		yes := withFix(finding("app/a", dA, "CVE-MIX", "HIGH", "openssl", "3.0.1", "3.0.2"), itypes.FixAvailableYes, itypes.ExploitAvailableNo)
		no := withFix(finding("app/b", dB, "CVE-MIX", "HIGH", "openssl", "3.0.1", ""), itypes.FixAvailableNo, itypes.ExploitAvailableYes)
		findings := map[string][]itypes.Finding{dA: {yes}, dB: {no}}
		if order == "fix-last" { // swap which image carries the fix
			yes = withFix(finding("app/b", dB, "CVE-MIX", "HIGH", "openssl", "3.0.1", "3.0.2"), itypes.FixAvailableYes, itypes.ExploitAvailableNo)
			no = withFix(finding("app/a", dA, "CVE-MIX", "HIGH", "openssl", "3.0.1", ""), itypes.FixAvailableNo, itypes.ExploitAvailableYes)
			findings = map[string][]itypes.Finding{dA: {no}, dB: {yes}}
		}
		e := &fakeECR{manifests: map[string]string{dA: "", dB: ""}}
		i := &fakeInspector{coverage: map[string]itypes.ScanStatus{dA: active, dB: active}, findings: findings}
		tk := newTestTask(e, i,
			pod("shop", "a-abc12-x", "a", "app/a:1", testHost+"/app/a@"+dA),
			pod("shop", "b-abc12-x", "b", "app/b:1", testHost+"/app/b@"+dB))
		r := run(t, tk, `{"severities":["HIGH"]}`)
		if len(r.Groups) != 1 {
			t.Fatalf("%s: groups = %+v", order, r.Groups)
		}
		g := r.Groups[0]
		if g.FixAvailable != "YES" || g.ExploitAvailable != "YES" {
			t.Fatalf("%s: fix=%q exploit=%q, want YES/YES (most actionable wins)", order, g.FixAvailable, g.ExploitAvailable)
		}
		wantFixable := "/a"
		if order == "fix-last" {
			wantFixable = "/b"
		}
		if g.WorkloadsTotal != 2 || g.FixableWorkloadsTotal != 1 || len(g.FixableWorkloads) != 1 || !strings.HasSuffix(g.FixableWorkloads[0], wantFixable) {
			t.Fatalf("%s: workloads=%v fixable=%v (total %d), want only the workload ending %q", order, g.Workloads, g.FixableWorkloads, g.FixableWorkloadsTotal, wantFixable)
		}
	}
}
