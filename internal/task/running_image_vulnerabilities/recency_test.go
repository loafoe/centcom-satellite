package running_image_vulnerabilities

import (
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	itypes "github.com/aws/aws-sdk-go-v2/service/inspector2/types"
)

// TestExecute_PreferRecentDaysKeepsNewCVEAheadOfLimit: a brand-new CVE (HIGH,
// no known exploit) sorts last in the default order, so a plain limit drops
// it; prefer_recent_days keeps it, and first_observed_at is reported.
func TestExecute_PreferRecentDaysKeepsNewCVEAheadOfLimit(t *testing.T) {
	fixed := time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)
	defer func(orig func() time.Time) { now = orig }(now)
	now = func() time.Time { return fixed }

	at := func(f itypes.Finding, ts time.Time, exploit itypes.ExploitAvailable) itypes.Finding {
		f.FirstObservedAt = aws.Time(ts)
		f.ExploitAvailable = exploit
		return f
	}
	old := fixed.Add(-60 * 24 * time.Hour)
	newTask := func() *Task {
		e := &fakeECR{manifests: map[string]string{indexDigest: indexManifest}}
		i := &fakeInspector{
			coverage: map[string]itypes.ScanStatus{amdDigest: {StatusCode: itypes.ScanStatusCodeActive, Reason: itypes.ScanStatusReasonSuccessful}},
			findings: map[string][]itypes.Finding{amdDigest: {
				at(finding("app/web", amdDigest, "CVE-OLD-1", "CRITICAL", "a", "1", "2"), old, itypes.ExploitAvailableYes),
				at(finding("app/web", amdDigest, "CVE-OLD-2", "CRITICAL", "b", "1", "2"), old, itypes.ExploitAvailableYes),
				at(finding("app/web", amdDigest, "CVE-NEW", "HIGH", "c", "1", ""), fixed.Add(-3*time.Hour), itypes.ExploitAvailableNo),
			}},
		}
		return newTestTask(e, i, pod("shop", "web-abc12-x", "web", "app/web:1.0", testHost+"/app/web@"+indexDigest))
	}
	keys := func(r Report) []string {
		var out []string
		for _, g := range r.Groups {
			out = append(out, g.Key)
		}
		return out
	}

	plain := run(t, newTask(), `{"severities":["CRITICAL","HIGH"],"limit":2}`)
	if got := keys(plain); len(got) != 2 || got[0] != "CVE-OLD-1" || got[1] != "CVE-OLD-2" {
		t.Fatalf("without prefer_recent_days: got %v, want the two old CRITICALs", got)
	}

	r := run(t, newTask(), `{"severities":["CRITICAL","HIGH"],"limit":2,"prefer_recent_days":7}`)
	got := keys(r)
	if len(got) != 2 || got[0] != "CVE-OLD-1" || got[1] != "CVE-NEW" {
		t.Fatalf("with prefer_recent_days: got %v, want [CVE-OLD-1 CVE-NEW] (default order kept)", got)
	}
	if r.GroupsTotal != 3 {
		t.Fatalf("groups_total = %d, want 3", r.GroupsTotal)
	}
	if want := fixed.Add(-3 * time.Hour).Format(time.RFC3339); r.Groups[1].FirstObservedAt != want {
		t.Fatalf("first_observed_at = %q, want %q", r.Groups[1].FirstObservedAt, want)
	}
}
