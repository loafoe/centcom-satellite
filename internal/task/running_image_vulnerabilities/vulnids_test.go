package running_image_vulnerabilities

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	itypes "github.com/aws/aws-sdk-go-v2/service/inspector2/types"
)

// vulnerability_ids reaches Inspector's filter, and the report says which
// optional filters it applied.
func TestExecute_VulnerabilityIDsFilterSentToInspector(t *testing.T) {
	const d = "sha256:e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5"
	active := itypes.ScanStatus{StatusCode: itypes.ScanStatusCodeActive, Reason: itypes.ScanStatusReasonSuccessful}
	i := &fakeInspector{coverage: map[string]itypes.ScanStatus{d: active}, findings: map[string][]itypes.Finding{
		d: {finding("app/web", d, "CVE-WEB", "HIGH", "openssl", "3.0.1", "3.0.7")},
	}}
	tk := newTestTask(&fakeECR{manifests: map[string]string{d: ""}}, i, pod("shop", "web-abc12-x", "web", "app/web:1", testHost+"/app/web@"+d))
	b, _ := json.Marshal(map[string]any{"severities": []string{"HIGH"}, "vulnerability_ids": []string{"cve-web"}, "workloads": []string{"shop/web"}})
	r := run(t, tk, string(b))
	if strings.Join(r.AppliedFilters, ",") != "workloads,vulnerability_ids" {
		t.Errorf("applied_filters = %v", r.AppliedFilters)
	}
	sent := false
	for _, fc := range i.filters {
		if len(fc.VulnerabilityId) == 1 && aws.ToString(fc.VulnerabilityId[0].Value) == "CVE-WEB" {
			sent = true
		}
	}
	if !sent {
		t.Error("vulnerability_ids was not sent to Inspector")
	}
}
