package running_image_vulnerabilities

import (
	"encoding/json"
	"testing"

	itypes "github.com/aws/aws-sdk-go-v2/service/inspector2/types"
)

// TestExecute_WorkloadsFilter: only the named workloads' pods are scanned,
// in any of the three forms, and the report says what matched.
func TestExecute_WorkloadsFilter(t *testing.T) {
	const (
		dWeb   = "sha256:c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3"
		dAdmin = "sha256:d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4"
	)
	active := itypes.ScanStatus{StatusCode: itypes.ScanStatusCodeActive, Reason: itypes.ScanStatusReasonSuccessful}
	newTask := func() *Task {
		e := &fakeECR{manifests: map[string]string{dWeb: "", dAdmin: ""}}
		i := &fakeInspector{coverage: map[string]itypes.ScanStatus{dWeb: active, dAdmin: active}, findings: map[string][]itypes.Finding{
			dWeb:   {finding("app/web", dWeb, "CVE-WEB", "HIGH", "openssl", "3.0.1", "3.0.7")},
			dAdmin: {finding("app/admin", dAdmin, "CVE-ADMIN", "HIGH", "glibc", "2.35", "2.36")},
		}}
		return newTestTask(e, i,
			pod("shop", "web-abc12-x", "web", "app/web:1", testHost+"/app/web@"+dWeb),
			pod("ops", "admin-abc12-x", "admin", "app/admin:1", testHost+"/app/admin@"+dAdmin))
	}
	for _, c := range []struct {
		filter   []string
		wantCVEs []string
	}{
		{[]string{"shop/Deployment/web"}, []string{"CVE-WEB"}},
		{[]string{"shop/deployment/web"}, []string{"CVE-WEB"}}, // kind is case-insensitive
		{[]string{"shop/web"}, []string{"CVE-WEB"}},
		{[]string{"admin"}, []string{"CVE-ADMIN"}},
		{[]string{"shop/web", "ops/Deployment/admin"}, []string{"CVE-ADMIN", "CVE-WEB"}},
		{[]string{"shop/Deployment/nope"}, nil},
	} {
		b, _ := json.Marshal(map[string]any{"severities": []string{"HIGH"}, "workloads": c.filter})
		r := run(t, newTask(), string(b))
		var got []string
		for _, g := range r.Groups {
			got = append(got, g.Key)
		}
		sortStrings(got)
		if len(got) != len(c.wantCVEs) || (len(got) > 0 && got[0] != c.wantCVEs[0]) {
			t.Errorf("filter %v: CVEs %v, want %v", c.filter, got, c.wantCVEs)
		}
		if len(c.wantCVEs) == 0 && len(r.MatchedWorkloads) != 0 || len(c.wantCVEs) > 0 && len(r.MatchedWorkloads) == 0 {
			t.Errorf("filter %v: matched_workloads %v", c.filter, r.MatchedWorkloads)
		}
		if r.Coverage.RunningImages != len(c.wantCVEs) {
			t.Errorf("filter %v: scanned %d images, want only the matching workloads' (%d)", c.filter, r.Coverage.RunningImages, len(c.wantCVEs))
		}
	}
}

func TestNormalize_WorkloadsNarrowNamespaces(t *testing.T) {
	p := Payload{Workloads: []string{" shop/Deployment/web ", "ops/admin"}}
	if msg := normalize(&p); msg != "" {
		t.Fatal(msg)
	}
	if len(p.Namespaces) != 2 || p.Namespaces[0] != "shop" || p.Namespaces[1] != "ops" {
		t.Fatalf("namespaces = %v, want [shop ops]", p.Namespaces)
	}
	p = Payload{Workloads: []string{"shop/web", "admin"}} // one entry without a namespace: list all
	normalize(&p)
	if len(p.Namespaces) != 0 {
		t.Fatalf("namespaces = %v, want all (an entry without namespace)", p.Namespaces)
	}
}
