package securityhub_update_findings

import (
	"context"
	"encoding/json"
	"sync"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/inspector2"
	itypes "github.com/aws/aws-sdk-go-v2/service/inspector2/types"
	"github.com/aws/aws-sdk-go-v2/service/securityhub"
	"github.com/aws/aws-sdk-go-v2/service/securityhub/types"
)

// statefulHub mimics Security Hub as observed live: BatchUpdateFindings
// REPLACES a finding's whole UserDefinedFields map.
type statefulHub struct {
	mu       sync.Mutex
	udf      map[string]map[string]string // finding ID -> map
	writes   int
	getCalls int
}

func (h *statefulHub) GetFindings(_ context.Context, in *securityhub.GetFindingsInput, _ ...func(*securityhub.Options)) (*securityhub.GetFindingsOutput, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.getCalls++
	out := &securityhub.GetFindingsOutput{}
	for _, f := range in.Filters.Id {
		id := aws.ToString(f.Value)
		if m, ok := h.udf[id]; ok {
			out.Findings = append(out.Findings, types.AwsSecurityFinding{Id: aws.String(id), UserDefinedFields: m})
		}
	}
	return out, nil
}

func (h *statefulHub) BatchUpdateFindings(_ context.Context, in *securityhub.BatchUpdateFindingsInput, _ ...func(*securityhub.Options)) (*securityhub.BatchUpdateFindingsOutput, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.writes++
	out := &securityhub.BatchUpdateFindingsOutput{}
	for _, f := range in.FindingIdentifiers {
		if in.UserDefinedFields != nil {
			m := map[string]string{}
			for k, v := range in.UserDefinedFields {
				m[k] = v
			}
			h.udf[aws.ToString(f.Id)] = m
		}
		out.ProcessedFindings = append(out.ProcessedFindings, f)
	}
	return out, nil
}

type fakeInspector struct {
	findings map[string][]string // resource ID -> finding ARNs for the vulnerability
	filters  []*itypes.FilterCriteria
}

func (f *fakeInspector) ListFindings(_ context.Context, in *inspector2.ListFindingsInput, _ ...func(*inspector2.Options)) (*inspector2.ListFindingsOutput, error) {
	f.filters = append(f.filters, in.FilterCriteria)
	out := &inspector2.ListFindingsOutput{}
	want := map[string]bool{}
	for _, r := range in.FilterCriteria.ResourceId {
		want[aws.ToString(r.Value)] = true
	}
	for res, arns := range f.findings {
		if len(want) > 0 && !want[res] {
			continue
		}
		for _, a := range arns {
			out.Findings = append(out.Findings, itypes.Finding{FindingArn: aws.String(a)})
		}
	}
	return out, nil
}

func enrichment(owner string) map[string]string {
	return map[string]string{"owner": owner, "findingEnriched": "True", "CostCenter": "NL9"}
}

func runUDF(t *testing.T, hub *statefulHub, insp *fakeInspector, payload string) UpdateResult {
	t.Helper()
	tk := newWithClients(
		func(context.Context, string) (api, error) { return hub, nil },
		func(context.Context, string) (inspectorAPI, error) { return insp, nil },
	)
	res, err := tk.Execute(context.Background(), json.RawMessage(payload))
	if err != nil || !res.Success {
		t.Fatalf("Execute: err=%v result=%+v", err, res)
	}
	var r UpdateResult
	b, _ := json.Marshal(res.Details)
	json.Unmarshal(b, &r)
	return r
}

const (
	arnA = "arn:aws:inspector2:eu-west-1:111111111111:finding/a"
	arnB = "arn:aws:inspector2:eu-west-1:111111111111:finding/b"
	arnC = "arn:aws:inspector2:eu-west-1:111111111111:finding/c"
)

func TestSetUserDefinedFields_KeepsOtherKeysPerFinding(t *testing.T) {
	hub := &statefulHub{udf: map[string]map[string]string{arnA: enrichment("alice"), arnB: enrichment("bob")}}
	r := runUDF(t, hub, &fakeInspector{}, `{"findings":[
		{"id":"`+arnA+`","product_arn":"arn:aws:securityhub:eu-west-1::product/aws/inspector"},
		{"id":"`+arnB+`","product_arn":"arn:aws:securityhub:eu-west-1::product/aws/inspector"}],
		"set_user_defined_fields":{"ticket":"PROJ-1"}}`)
	if len(r.Processed) != 2 {
		t.Fatalf("processed = %+v", r)
	}
	for id, owner := range map[string]string{arnA: "alice", arnB: "bob"} {
		m := hub.udf[id]
		if m["ticket"] != "PROJ-1" || m["owner"] != owner || m["findingEnriched"] != "True" || len(m) != 4 {
			t.Errorf("%s map = %v, want enrichment keys kept (owner %s) plus ticket", id, m, owner)
		}
	}
	if hub.writes != 2 {
		t.Errorf("writes = %d, want 2 (different resulting maps cannot share a call)", hub.writes)
	}
}

func TestSetUserDefinedFields_GroupsIdenticalResultingMaps(t *testing.T) {
	hub := &statefulHub{udf: map[string]map[string]string{arnA: enrichment("alice"), arnB: enrichment("alice"), arnC: enrichment("alice")}}
	runUDF(t, hub, &fakeInspector{}, `{"findings":[{"id":"`+arnA+`","product_arn":"p"},{"id":"`+arnB+`","product_arn":"p"},{"id":"`+arnC+`","product_arn":"p"}],
		"set_user_defined_fields":{"ticket":"PROJ-1"}}`)
	if hub.writes != 1 {
		t.Errorf("writes = %d, want 1 for three findings with the same resulting map", hub.writes)
	}
}

func TestRemoveUserDefinedFields_DeletesOnlyNamedKeys(t *testing.T) {
	m := enrichment("alice")
	m["ticket"] = "PROJ-1"
	m["ticketUrl"] = "https://x/browse/PROJ-1"
	hub := &statefulHub{udf: map[string]map[string]string{arnA: m}}
	runUDF(t, hub, &fakeInspector{}, `{"findings":[{"id":"`+arnA+`","product_arn":"p"}],"remove_user_defined_fields":["ticket","ticketUrl"]}`)
	got := hub.udf[arnA]
	if _, ok := got["ticket"]; ok || len(got) != 3 || got["owner"] != "alice" {
		t.Errorf("map = %v, want only the enrichment keys", got)
	}
}

// Security Hub applies writes asynchronously, so a map that reads back
// already-correct must still be written: the read may predate a pending
// write (a remove right after a set read no ticket key and skipped it, live).
func TestSetUserDefinedFields_WritesEvenWhenReadLooksCurrent(t *testing.T) {
	hub := &statefulHub{udf: map[string]map[string]string{arnA: enrichment("alice")}}
	r := runUDF(t, hub, &fakeInspector{}, `{"findings":[{"id":"`+arnA+`","product_arn":"p"},{"id":"`+arnB+`","product_arn":"p"}],"remove_user_defined_fields":["ticket"]}`)
	if hub.writes != 1 || len(r.Processed) != 1 {
		t.Errorf("writes=%d processed=%d, want the found finding written anyway", hub.writes, len(r.Processed))
	}
	if len(r.Unprocessed) != 1 || r.Unprocessed[0].ErrorCode != "NotFound" {
		t.Errorf("unprocessed = %+v, want the unknown finding reported, not written blind", r.Unprocessed)
	}
}

func TestVulnerabilitySelector_ResolvesThroughInspector(t *testing.T) {
	hub := &statefulHub{udf: map[string]map[string]string{arnA: enrichment("a"), arnB: enrichment("a"), arnC: enrichment("a")}}
	insp := &fakeInspector{findings: map[string][]string{"i-1": {arnA}, "i-2": {arnB}, "i-3": {arnC}}}
	r := runUDF(t, hub, insp, `{"vulnerability_id":"CVE-1","resource_ids":["i-1","i-2"],"set_user_defined_fields":{"ticket":"PROJ-9"}}`)
	if r.Selected != 2 || len(r.Processed) != 2 {
		t.Fatalf("result = %+v, want the two selected resources' findings", r)
	}
	if hub.udf[arnC]["ticket"] != "" {
		t.Error("finding on an unselected resource was updated")
	}
	f := insp.filters[0]
	if aws.ToString(f.VulnerabilityId[0].Value) != "CVE-1" || aws.ToString(f.FindingStatus[0].Value) != "ACTIVE" {
		t.Errorf("inspector filter = %+v", f)
	}
	if r.Processed[0].ProductArn != "arn:aws:securityhub:eu-west-1::product/aws/inspector" {
		t.Errorf("product arn = %s", r.Processed[0].ProductArn)
	}
}

func TestValidate_RejectsBadSelectorsAndFields(t *testing.T) {
	for _, p := range []string{
		`{"set_user_defined_fields":{"a":"b"}}`,
		`{"findings":[{"id":"x","product_arn":"p"}],"vulnerability_id":"CVE-1","note":"n"}`,
		`{"resource_ids":["i-1"],"note":"n"}`,
		`{"vulnerability_id":"CVE-1"}`,
		`{"vulnerability_id":"CVE-1","set_user_defined_fields":{"ticket":" "}}`,
	} {
		res, err := newTestTask(&fakeAPI{}).Execute(context.Background(), json.RawMessage(p))
		if err != nil || res.Success {
			t.Errorf("payload %s: want a validation error result", p)
		}
	}
}
