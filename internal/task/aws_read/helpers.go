package aws_read

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/aws/aws-sdk-go-v2/service/iam"
	"golang.org/x/time/rate"
)

// paramsError marks a caller mistake in params (unknown field, wrong type),
// reported as a task error result rather than an AWS call failure.
type paramsError struct{ err error }

func (e *paramsError) Error() string { return e.err.Error() }

// decodeParams rejects unknown fields so a misnamed filter (e.g. "User" for
// ListGroupsForUser's "UserName") fails loudly instead of silently running
// an unfiltered call. Matching is case-insensitive, as in encoding/json.
func decodeParams(params json.RawMessage, in any) error {
	if len(bytes.TrimSpace(params)) == 0 || string(bytes.TrimSpace(params)) == "null" {
		return nil
	}
	dec := json.NewDecoder(bytes.NewReader(params))
	dec.DisallowUnknownFields()
	if err := dec.Decode(in); err != nil {
		return &paramsError{err: err}
	}
	return nil
}

func normalize(s string) string {
	return strings.ToLower(strings.NewReplacer("-", "", "_", "", " ", "").Replace(s))
}

var serviceAliases = map[string]string{
	"iam":           "iam",
	"ssoadmin":      "sso-admin",
	"identitystore": "identitystore",
}

// opIndex maps service -> normalized operation -> canonical API name.
var opIndex = func() map[string]map[string]string {
	idx := map[string]map[string]string{}
	for svc, ops := range allowlist {
		idx[svc] = map[string]string{}
		for name := range ops {
			idx[svc][normalize(name)] = name
		}
	}
	return idx
}()

// resolve maps a caller's service/operation spelling to an allowlisted
// opFunc; on failure fn is nil and msg says what is allowed.
func resolve(service, operation string) (string, string, opFunc, string) {
	svc, ok := serviceAliases[normalize(service)]
	if !ok {
		return "", "", nil, fmt.Sprintf("service %q is not supported; one of: %s", service, strings.Join(Services(), ", "))
	}
	name, ok := opIndex[svc][normalize(operation)]
	if !ok {
		return svc, "", nil, fmt.Sprintf("operation %q is not allowlisted for %s (read-only allowlist); allowed: %s", operation, svc, strings.Join(Operations(svc), ", "))
	}
	return svc, name, allowlist[svc][name], ""
}

// Services returns the supported service names, sorted.
func Services() []string {
	out := make([]string, 0, len(allowlist))
	for svc := range allowlist {
		out = append(out, svc)
	}
	sort.Strings(out)
	return out
}

// Operations returns a service's allowlisted operations, sorted.
func Operations(service string) []string {
	out := make([]string, 0, len(allowlist[service]))
	for name := range allowlist[service] {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

var (
	limitersMu sync.Mutex
	limiters   = map[string]*rate.Limiter{}
	// IAM and Identity Center control-plane APIs throttle per account at low
	// rates; one process-wide budget per service keeps a bulk script from
	// tripping it for every other caller.
	ratePerSecond rate.Limit = 5
)

func limiterFor(service string) *rate.Limiter {
	limitersMu.Lock()
	defer limitersMu.Unlock()
	l, ok := limiters[service]
	if !ok {
		l = rate.NewLimiter(ratePerSecond, 5)
		limiters[service] = l
	}
	return l
}

// maxResponseBytes bounds a single page's marshaled JSON size. A var, not a
// const, so tests can shrink it instead of needing a multi-MB fixture.
//
// Real incident, ops-sandbox, 2026-10-27: this account has 369 IAM roles and
// 169+ customer-managed policies, and one GetAccountAuthorizationDetails
// page landed a role/policy whose attached documents alone marshaled to
// 23.75MB. toResponse's second copy - unmarshaling that into map[string]any
// - amplified it to a ~183MB single-request spike (RSS 34MB -> 217MB, one
// call), which OOM-killed the satellite's 384Mi container outright: not
// just that one request, but every other concurrent caller on that replica
// too, and a retry hit the second replica and OOM-killed it the same way.
// Checking the size of the FIRST marshal (the SDK struct, before the
// map[string]any amplification) and bailing before the second copy catches
// this at ~23MB instead of ~183MB, with no fixture needed - see
// TestToResponse_OversizedResponseIsRejectedNotAmplified.
var maxResponseBytes = 5 * 1024 * 1024

// errResponseTooLarge marks a response this task refuses to amplify into
// map[string]any and return, rather than a transport/AWS failure - Execute
// turns it into a self-describing task.Result (not a 500) so a bulk-reading
// script gets something it can act on instead of taking down the satellite.
type errResponseTooLarge struct{ size int }

func (e *errResponseTooLarge) Error() string {
	return fmt.Sprintf("response too large: %.1fMB exceeds the %.0fMB per-call cap", float64(e.size)/1e6, float64(maxResponseBytes)/1e6)
}

// toResponse converts an SDK output struct into plain JSON fields, dropping
// the SDK's ResultMetadata and decoding the credential report from bytes to
// CSV text so the caller doesn't have to base64-decode it. Refuses (via
// errResponseTooLarge) before the map[string]any copy if the first marshal
// already exceeds maxResponseBytes - see its doc comment.
func toResponse(out any) (map[string]any, error) {
	b, err := json.Marshal(out)
	if err != nil {
		return nil, err
	}
	if len(b) > maxResponseBytes {
		return nil, &errResponseTooLarge{size: len(b)}
	}
	resp := map[string]any{}
	if err := json.Unmarshal(b, &resp); err != nil {
		return nil, err
	}
	delete(resp, "ResultMetadata")
	if cr, ok := out.(*iam.GetCredentialReportOutput); ok {
		delete(resp, "Content")
		resp["ContentCSV"] = string(cr.Content)
	}
	return resp, nil
}
