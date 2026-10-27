package aws_read

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"golang.org/x/time/rate"

	"github.com/loafoe/centcom-satellite/internal/task"
)

type fakeIAM struct {
	t        *testing.T
	status   int
	body     string
	gotForm  map[string]string
	requests int
}

func (f *fakeIAM) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.requests++
	if err := r.ParseForm(); err != nil {
		f.t.Fatalf("parse form: %v", err)
	}
	f.gotForm = map[string]string{}
	for k, v := range r.PostForm {
		f.gotForm[k] = v[0]
	}
	w.Header().Set("Content-Type", "text/xml")
	if f.status != 0 {
		w.WriteHeader(f.status)
	}
	_, _ = w.Write([]byte(f.body))
}

func newTestTask(t *testing.T, f *fakeIAM) *Task {
	t.Helper()
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	ratePerSecond = rate.Inf
	limiters = map[string]*rate.Limiter{}
	return NewWithConfigFactory(func(ctx context.Context, region string) (aws.Config, error) {
		return aws.Config{
			Region:           "us-east-1",
			Credentials:      credentials.NewStaticCredentialsProvider("AKID", "SECRET", ""),
			BaseEndpoint:     aws.String(srv.URL),
			RetryMaxAttempts: 1,
		}, nil
	})
}

func run(t *testing.T, tk *Task, payload string) *task.Result {
	t.Helper()
	res, err := tk.Execute(context.Background(), json.RawMessage(payload))
	if err != nil {
		t.Fatalf("Execute returned Go error: %v", err)
	}
	return res
}

const listGroupsForUserXML = `<ListGroupsForUserResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/">
  <ListGroupsForUserResult>
    <Groups><member><GroupName>admins</GroupName><GroupId>AGPA1</GroupId><Path>/</Path><Arn>arn:aws:iam::123456789012:group/admins</Arn><CreateDate>2026-01-01T00:00:00Z</CreateDate></member></Groups>
    <IsTruncated>false</IsTruncated>
  </ListGroupsForUserResult>
  <ResponseMetadata><RequestId>r1</RequestId></ResponseMetadata>
</ListGroupsForUserResponse>`

func TestExecute_RealSDKCallWithParams(t *testing.T) {
	f := &fakeIAM{t: t, body: listGroupsForUserXML}
	tk := newTestTask(t, f)

	// CLI spelling for service and operation must resolve to the API names.
	res := run(t, tk, `{"service":"IAM","operation":"list-groups-for-user","params":{"UserName":"alice"}}`)
	if !res.Success {
		t.Fatalf("expected success, got %+v", res)
	}
	if f.gotForm["Action"] != "ListGroupsForUser" || f.gotForm["UserName"] != "alice" {
		t.Fatalf("request not forwarded as expected: %v", f.gotForm)
	}
	out := res.Details.(Output)
	if out.Service != "iam" || out.Operation != "ListGroupsForUser" {
		t.Fatalf("unexpected canonical names: %+v", out)
	}
	if _, ok := out.Response["ResultMetadata"]; ok {
		t.Fatalf("ResultMetadata should be dropped: %v", out.Response)
	}
	groups := out.Response["Groups"].([]any)
	if len(groups) != 1 || groups[0].(map[string]any)["GroupName"] != "admins" {
		t.Fatalf("unexpected groups: %v", out.Response)
	}
}

func TestExecute_RejectsNonAllowlistedOperation(t *testing.T) {
	f := &fakeIAM{t: t}
	tk := newTestTask(t, f)
	for _, payload := range []string{
		`{"service":"iam","operation":"CreateUser","params":{"UserName":"x"}}`,
		`{"service":"iam","operation":"DeleteRole"}`,
		`{"service":"iam","operation":"AttachRolePolicy"}`,
		`{"service":"iam","operation":"CreateAccessKey"}`,
		`{"service":"sso-admin","operation":"CreateAccountAssignment"}`,
		`{"service":"identitystore","operation":"DeleteUser"}`,
		`{"service":"s3","operation":"ListBuckets"}`,
		`{"service":"secretsmanager","operation":"GetSecretValue"}`,
	} {
		res := run(t, tk, payload)
		if res.Success || res.Error == "" {
			t.Errorf("%s: expected error result, got %+v", payload, res)
		}
	}
	if f.requests != 0 {
		t.Fatalf("a refused operation reached AWS (%d requests)", f.requests)
	}
}

func TestExecute_UnknownParamFieldIsRejected(t *testing.T) {
	f := &fakeIAM{t: t, body: listGroupsForUserXML}
	tk := newTestTask(t, f)
	// encoding/json matches field names case-insensitively, so "Username"
	// binds to UserName; a different word must still be refused.
	res := run(t, tk, `{"service":"iam","operation":"ListGroupsForUser","params":{"User":"alice"}}`)
	if res.Success || !strings.Contains(res.Error, "invalid params") {
		t.Fatalf("expected invalid params error, got %+v", res)
	}
	if f.requests != 0 {
		t.Fatalf("misspelt params must not reach AWS")
	}
}

func TestExecute_AccessDeniedIsAResultNotA500(t *testing.T) {
	f := &fakeIAM{t: t, status: http.StatusForbidden, body: `<ErrorResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/"><Error><Type>Sender</Type><Code>AccessDenied</Code><Message>not authorized to perform: iam:ListUsers</Message></Error><RequestId>r2</RequestId></ErrorResponse>`}
	tk := newTestTask(t, f)
	res := run(t, tk, `{"service":"iam","operation":"ListUsers"}`)
	if res.Success || !strings.Contains(res.Error, "AccessDenied") {
		t.Fatalf("expected AccessDenied error result, got %+v", res)
	}
}

func TestExecute_CredentialReportIsDecodedToCSV(t *testing.T) {
	csv := "user,arn,password_enabled\nalice,arn:aws:iam::123456789012:user/alice,true\n"
	body := `<GetCredentialReportResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/"><GetCredentialReportResult>` +
		`<Content>dXNlcixhcm4scGFzc3dvcmRfZW5hYmxlZAphbGljZSxhcm46YXdzOmlhbTo6MTIzNDU2Nzg5MDEyOnVzZXIvYWxpY2UsdHJ1ZQo=</Content>` +
		`<ReportFormat>text/csv</ReportFormat><GeneratedTime>2026-10-27T10:00:00Z</GeneratedTime>` +
		`</GetCredentialReportResult><ResponseMetadata><RequestId>r3</RequestId></ResponseMetadata></GetCredentialReportResponse>`
	f := &fakeIAM{t: t, body: body}
	tk := newTestTask(t, f)
	res := run(t, tk, `{"service":"iam","operation":"GetCredentialReport"}`)
	if !res.Success {
		t.Fatalf("expected success, got %+v", res)
	}
	resp := res.Details.(Output).Response
	if resp["ContentCSV"] != csv {
		t.Fatalf("ContentCSV = %q, want %q", resp["ContentCSV"], csv)
	}
	if _, ok := resp["Content"]; ok {
		t.Fatalf("raw base64 Content should be replaced")
	}
}

// Every allowlisted operation must be a read: a List/Get/Describe call or one
// of IAM's two read-level report generators. Guards against a write sneaking
// into the table in a later edit.
func TestAllowlist_OnlyReadOperations(t *testing.T) {
	generators := map[string]bool{"GenerateCredentialReport": true, "GenerateServiceLastAccessedDetails": true}
	for svc, ops := range allowlist {
		for name := range ops {
			if generators[name] && svc == "iam" {
				continue
			}
			if !strings.HasPrefix(name, "List") && !strings.HasPrefix(name, "Get") && !strings.HasPrefix(name, "Describe") {
				t.Errorf("%s %s is not a read operation", svc, name)
			}
		}
	}
}

// Regression test for the 2026-10-27 ops-sandbox incident: one
// GetAccountAuthorizationDetails page there marshaled to 23.75MB, and
// toResponse's old unconditional map[string]any copy amplified that into a
// ~183MB single-request spike that OOM-killed the satellite's 384Mi
// container (taking down every other concurrent caller on that replica,
// not just this one call) - see helpers.go's maxResponseBytes doc comment.
// Shrinks the cap instead of needing a multi-MB fixture.
func TestExecute_OversizedResponseIsRefusedNotAmplified(t *testing.T) {
	// A ListGroupsForUser response with one large group name, well under
	// Go's own string/slice limits but over a shrunk-for-test cap.
	big := strings.Repeat("x", 2000)
	body := `<ListGroupsForUserResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/">
  <ListGroupsForUserResult>
    <Groups><member><GroupName>` + big + `</GroupName><GroupId>AGPA1</GroupId><Path>/</Path><Arn>arn:aws:iam::123456789012:group/x</Arn><CreateDate>2026-01-01T00:00:00Z</CreateDate></member></Groups>
    <IsTruncated>false</IsTruncated>
  </ListGroupsForUserResult>
  <ResponseMetadata><RequestId>r1</RequestId></ResponseMetadata>
</ListGroupsForUserResponse>`
	f := &fakeIAM{t: t, body: body}
	tk := newTestTask(t, f)

	restore := func(v int) func() { return func() { maxResponseBytes = v } }(maxResponseBytes)
	maxResponseBytes = 500 // smaller than the fixture's ~2KB group name
	defer restore()

	res := run(t, tk, `{"service":"iam","operation":"ListGroupsForUser","params":{"UserName":"alice"}}`)
	if res.Success {
		t.Fatalf("expected a refusal, got success: %+v", res)
	}
	for _, want := range []string{"too large", "ListGroupsForUser", "MaxItems", "narrow"} {
		if !strings.Contains(res.Error, want) {
			t.Errorf("error message missing %q guidance: %s", want, res.Error)
		}
	}
	// The call to AWS itself must have happened (this isn't a pre-call
	// refusal) - the refusal is about the response, not the request.
	if f.requests != 1 {
		t.Fatalf("expected exactly 1 AWS call, got %d", f.requests)
	}
}

// A response at or under the cap must still succeed normally - the cap is
// a safety ceiling, not a general-purpose size reduction.
func TestExecute_ResponseUnderCapStillSucceeds(t *testing.T) {
	f := &fakeIAM{t: t, body: listGroupsForUserXML}
	tk := newTestTask(t, f)
	res := run(t, tk, `{"service":"iam","operation":"ListGroupsForUser","params":{"UserName":"alice"}}`)
	if !res.Success {
		t.Fatalf("expected success for a small response, got %+v", res)
	}
}
