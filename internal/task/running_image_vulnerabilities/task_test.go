package running_image_vulnerabilities

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	itypes "github.com/aws/aws-sdk-go-v2/service/inspector2/types"
	corev1 "k8s.io/api/core/v1"
)

const (
	indexDigest = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	amdDigest   = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	armDigest   = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	attDigest   = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
)

var indexManifest = fmt.Sprintf(`{"manifests":[
 {"digest":%q,"platform":{"architecture":"amd64","os":"linux"}},
 {"digest":%q,"platform":{"architecture":"arm64","os":"linux"}},
 {"digest":%q,"platform":{"architecture":"unknown","os":"unknown"}}]}`, amdDigest, armDigest, attDigest)

func run(t *testing.T, tk *Task, payload string) Report {
	t.Helper()
	res, err := tk.Execute(context.Background(), json.RawMessage(payload))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.Success {
		t.Fatalf("expected success, got %s", res.Error)
	}
	return res.Details.(Report)
}

// TestExecute_ResolvesIndexAndJoinsWorkloads covers the whole path: a pod
// reports an image index digest, findings live on the platform manifests,
// one platform is no longer scanned, and other registries are not assessed.
func TestExecute_ResolvesIndexAndJoinsWorkloads(t *testing.T) {
	e := &fakeECR{manifests: map[string]string{indexDigest: indexManifest}}
	i := &fakeInspector{
		coverage: map[string]itypes.ScanStatus{
			amdDigest: {StatusCode: itypes.ScanStatusCodeActive, Reason: itypes.ScanStatusReasonSuccessful},
			armDigest: {StatusCode: itypes.ScanStatusCodeInactive, Reason: itypes.ScanStatusReasonScanEligibilityExpired},
		},
		findings: map[string][]itypes.Finding{amdDigest: {
			finding("app/web", amdDigest, "CVE-1", "CRITICAL", "tomcat", "9.0.62", "11.0.2"),
			finding("app/web", amdDigest, "CVE-2", "HIGH", "snakeyaml", "1.28", "2.0"),
		}},
	}
	img := testHost + "/app/web@" + indexDigest
	tk := newTestTask(e, i,
		pod("shop", "web-abc12-x", "web", "app/web:1.0", "docker-pullable://"+img),
		pod("shop", "web-abc12-y", "web", "app/web:1.0", img),
		pod("kube-system", "cni-abc12-z", "cni", "eks/cni", "602401143452.dkr.ecr.us-east-1.amazonaws.com/amazon-k8s-cni@"+armDigest),
		pod("tools", "dbg-abc12-q", "dbg", "cgr.dev/x", "cgr.dev/chainguard/x@"+attDigest),
	)
	r := run(t, tk, `{}`)

	c := r.Coverage
	if c.RunningContainers != 4 || c.RunningImages != 3 || c.ECRImages != 1 || c.OtherRegistryImages != 2 {
		t.Errorf("coverage counts = %+v", c)
	}
	if c.PlatformImages != 2 {
		t.Errorf("PlatformImages = %d, want 2 (attestation manifest skipped)", c.PlatformImages)
	}
	if c.ScanStatus["ACTIVE"] != 1 || c.ScanStatus["INACTIVE/SCAN_ELIGIBILITY_EXPIRED"] != 1 {
		t.Errorf("ScanStatus = %v", c.ScanStatus)
	}
	if c.AssessedImages != 1 || c.UnscannedImages != 0 || c.ImagesWithFindings != 1 {
		t.Errorf("assessed/unscanned/with findings = %d/%d/%d, want 1/0/1", c.AssessedImages, c.UnscannedImages, c.ImagesWithFindings)
	}
	if r.TotalFindings != 1 || r.SeverityCounts["CRITICAL"] != 1 {
		t.Errorf("default severity CRITICAL only: total=%d counts=%v", r.TotalFindings, r.SeverityCounts)
	}
	if len(r.Groups) != 1 {
		t.Fatalf("groups = %+v", r.Groups)
	}
	g := r.Groups[0]
	if g.Key != "CVE-1" || g.Images != 1 || g.FixAvailable != "YES" || g.ExploitAvailable != "YES" {
		t.Errorf("group = %+v", g)
	}
	if len(g.Packages) != 1 || g.Packages[0].FixedInVersion != "11.0.2" {
		t.Errorf("packages = %+v", g.Packages)
	}
	if g.WorkloadsTotal != 1 || g.Workloads[0] != "shop/Deployment/web" {
		t.Errorf("workloads = %v (total %d), want [shop/Deployment/web]", g.Workloads, g.WorkloadsTotal)
	}
	if !r.Complete || r.AccountID != testAccount {
		t.Errorf("complete=%v account=%q", r.Complete, r.AccountID)
	}
}

// TestExecute_UnscannedImageIsAGap: an image whose only platform is
// expired must count as unscanned, not as clean.
func TestExecute_UnscannedImageIsAGap(t *testing.T) {
	e := &fakeECR{manifests: map[string]string{amdDigest: ""}}
	i := &fakeInspector{coverage: map[string]itypes.ScanStatus{
		amdDigest: {StatusCode: itypes.ScanStatusCodeInactive, Reason: itypes.ScanStatusReasonScanEligibilityExpired},
	}}
	tk := newTestTask(e, i, pod("ns", "a-abc12-1", "a", "app/a", testHost+"/app/a@"+amdDigest))
	c := run(t, tk, `{}`).Coverage
	if c.AssessedImages != 0 || c.UnscannedImages != 1 {
		t.Errorf("assessed=%d unscanned=%d, want 0/1", c.AssessedImages, c.UnscannedImages)
	}
}

// TestExecute_HashFilterBatchesOfTen guards Inspector's 10-value filter
// limit, and that severity/fix/exploit filters reach the API.
func TestExecute_HashFilterBatchesOfTen(t *testing.T) {
	e := &fakeECR{manifests: map[string]string{}}
	var pods []*corev1.Pod
	for n := 0; n < 25; n++ {
		d := fmt.Sprintf("sha256:%064d", n)
		e.manifests[d] = ""
		pods = append(pods, pod("ns", fmt.Sprintf("p%d-abc12-1", n), fmt.Sprintf("p%d", n), "app/x", testHost+"/app/x@"+d))
	}
	i := &fakeInspector{}
	run(t, newTestTask(e, i, pods...), `{"severities":["critical","HIGH"],"fix_available":"yes","exploit_available":"YES"}`)
	if len(i.filters) != 3 {
		t.Fatalf("ListFindings calls = %d, want 3 (25 hashes / 10)", len(i.filters))
	}
	for _, f := range i.filters {
		if len(f.EcrImageHash) > hashesPerCall {
			t.Errorf("filter has %d hashes, limit is %d", len(f.EcrImageHash), hashesPerCall)
		}
		if len(f.Severity) != 2 || len(f.FixAvailable) != 1 || len(f.ExploitAvailable) != 1 {
			t.Errorf("filters not passed through: %+v", f)
		}
	}
}

func TestExecute_BudgetGivesPartialResult(t *testing.T) {
	e := &fakeECR{manifests: map[string]string{amdDigest: ""}}
	tk := newTestTask(e, &fakeInspector{}, pod("ns", "a-abc12-1", "a", "app/a", testHost+"/app/a@"+amdDigest))
	tk.budget = time.Nanosecond
	r := run(t, tk, `{}`)
	if r.Complete || r.StopReason != "time_budget" {
		t.Errorf("complete=%v stop=%q, want partial time_budget", r.Complete, r.StopReason)
	}
}

func TestExecute_GroupByPackageAndImage(t *testing.T) {
	e := &fakeECR{manifests: map[string]string{amdDigest: ""}}
	i := &fakeInspector{
		coverage: map[string]itypes.ScanStatus{amdDigest: {StatusCode: itypes.ScanStatusCodeActive}},
		findings: map[string][]itypes.Finding{amdDigest: {
			finding("app/a", amdDigest, "CVE-1", "CRITICAL", "tomcat", "9", "11"),
			finding("app/a", amdDigest, "CVE-2", "CRITICAL", "tomcat", "9", "11"),
		}},
	}
	p := pod("ns", "a-abc12-1", "a", "app/a:1", testHost+"/app/a@"+amdDigest)
	r := run(t, newTestTask(e, i, p), `{"group_by":"PACKAGE"}`)
	if len(r.Groups) != 1 || r.Groups[0].Key != "tomcat" || r.Groups[0].Vulnerabilities != 2 || r.Groups[0].Findings != 2 {
		t.Errorf("PACKAGE groups = %+v", r.Groups)
	}
	r = run(t, newTestTask(e, i, p), `{"group_by":"IMAGE"}`)
	if len(r.Groups) != 1 || r.Groups[0].Title != "app/a:1" || r.Groups[0].Vulnerabilities != 2 {
		t.Errorf("IMAGE groups = %+v", r.Groups)
	}
}

func TestExecute_InvalidPayload(t *testing.T) {
	for _, p := range []string{`{`, `{"severities":["BAD"]}`, `{"fix_available":"MAYBE"}`, `{"exploit_available":"PARTIAL"}`, `{"group_by":"X"}`} {
		res, err := newTestTask(&fakeECR{}, &fakeInspector{}).Execute(context.Background(), json.RawMessage(p))
		if err != nil || res.Success {
			t.Errorf("%s: err=%v success=%v, want an error result", p, err, res != nil && res.Success)
		}
	}
}

func TestParseImageIDAndWorkload(t *testing.T) {
	host, repo, d, ok := parseImageID("docker-pullable://" + testHost + "/a/b/c@" + amdDigest)
	if !ok || host != testHost || repo != "a/b/c" || d != amdDigest {
		t.Errorf("parse = %q %q %q %v", host, repo, d, ok)
	}
	if _, _, _, ok := parseImageID("sha256:abc"); ok {
		t.Error("bare digest parsed")
	}
	if w := workloadOf(pod("ns", "p", "web", "", "")); w != "ns/Deployment/web" {
		t.Errorf("workload = %q", w)
	}
}
