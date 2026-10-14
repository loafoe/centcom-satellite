package cloudtrail_logins

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"

	ctc "github.com/loafoe/centcom-satellite/internal/task/cloudtrail_common"
	"github.com/loafoe/centcom-satellite/internal/task/cloudtrail_common/cttest"
)

var now = time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)

func samlSession(t time.Time, email, role string) types.Event {
	return cttest.MakeEvent(t, "AssumeRoleWithSAML",
		map[string]any{"type": "SAMLUser", "userName": email, "principalId": "p:" + email},
		map[string]any{"requestParameters": map[string]any{"roleArn": "arn:aws:iam::123456789012:role/aws-reserved/sso.amazonaws.com/" + role}})
}

// account mimics the measured hsp-ops-tools shape: a handful of console
// logins over months, a high volume of SSO sessions, and thousands of other
// API calls by the same user that a Username lookup would wade through.
func account() *cttest.FakeAPI {
	var ev []types.Event
	for i := range 3000 {
		ev = append(ev, cttest.MakeEvent(now.Add(-time.Duration(i)*time.Second), "InvokeModel",
			map[string]any{"type": "AssumedRole", "arn": "arn:aws:sts::123456789012:assumed-role/AWSReservedSSO_bedrock_1/alice@example.com"}, nil))
	}
	for i := range 1100 { // ~1 day of SSO sessions
		user := "bob@example.com"
		if i%100 == 7 {
			user = "alice@example.com"
		}
		ev = append(ev, samlSession(now.Add(-time.Duration(i)*78*time.Second), user, "AWSReservedSSO_bedrock_1"))
	}
	ev = append(ev,
		cttest.SSOConsoleLogin(now.Add(-2*24*time.Hour), "alice@example.com"),
		cttest.SSOConsoleLogin(now.Add(-5*24*time.Hour), "bob@example.com"),
		cttest.SSOConsoleLogin(now.Add(-40*24*time.Hour), "Alice@Example.com"),
		cttest.SSOConsoleLogin(now.Add(-100*24*time.Hour), "alice@example.com"), // outside 90 days
	)
	sortNewestFirst(ev)
	return &cttest.FakeAPI{Events: ev}
}

func sortNewestFirst(ev []types.Event) {
	for i := 1; i < len(ev); i++ {
		for j := i; j > 0 && ev[j].EventTime.After(*ev[j-1].EventTime); j-- {
			ev[j], ev[j-1] = ev[j-1], ev[j]
		}
	}
}

func run(t *testing.T, api *cttest.FakeAPI, payload map[string]any) Output {
	t.Helper()
	defer ctc.SetRateLimitForTest(10000)()
	tk := NewWithClientFactory(func(context.Context, string) (ctc.API, error) { return api, nil }, func() time.Time { return now })
	raw, _ := json.Marshal(payload)
	res, err := tk.Execute(context.Background(), raw)
	if err != nil || !res.Success {
		t.Fatalf("execute: %v %+v", err, res)
	}
	b, _ := json.Marshal(res.Details)
	var out Output
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestLogins_UserConsoleHistoryIsOneCall(t *testing.T) {
	api := account()
	out := run(t, api, map[string]any{"user": "alice@example.com", "include_sessions": false})

	if len(api.Calls) != 1 {
		t.Fatalf("90-day console history for one user must be 1 LookupEvents call, got %d", len(api.Calls))
	}
	in := api.Calls[0]
	if in.LookupAttributes[0].AttributeKey != types.LookupAttributeKeyEventName || aws.ToString(in.LookupAttributes[0].AttributeValue) != "ConsoleLogin" {
		t.Fatal("must filter server-side on EventName=ConsoleLogin, never Username")
	}
	c := out.ConsoleLogins
	if c.Matched != 2 || !c.Complete || len(c.Events) != 2 || len(c.Principals) != 1 || c.Principals[0].Count != 2 {
		t.Fatalf("expected alice's 2 logins within 90 days (case-insensitive), got %+v", c)
	}
	if out.LastLogin != now.Add(-2*24*time.Hour).Format(time.RFC3339) {
		t.Fatalf("last_login %q", out.LastLogin)
	}
}

func TestLogins_SessionsScanIsWindowBounded(t *testing.T) {
	api := account()
	out := run(t, api, map[string]any{"user": "alice@example.com", "session_hours": 6})
	s := out.Sessions
	if s == nil || !s.Complete {
		t.Fatalf("sessions section missing/incomplete: %+v", s)
	}
	// 6h of ~78s-spaced sessions ≈ 277 events ≈ 6 pages; never the full day.
	if s.Scanned > 300 || s.Pages > 6 {
		t.Fatalf("session scan not bounded by the window: scanned=%d pages=%d", s.Scanned, s.Pages)
	}
	if s.Matched != 3 || len(s.Principals) != 1 || s.Principals[0].Role != "AWSReservedSSO_bedrock_1" {
		t.Fatalf("expected alice's 3 sessions with role, got %+v", s)
	}
	if len(api.Calls) != 1+s.Pages {
		t.Fatalf("calls=%d", len(api.Calls))
	}
}

func TestLogins_StopAtFirstMatchIsCheapest(t *testing.T) {
	api := account()
	out := run(t, api, map[string]any{"user": "alice@example.com", "stop_at_first_match": true, "session_hours": 24})
	if len(api.Calls) != 2 {
		t.Fatalf("yes/no check should take one call per scan, got %d", len(api.Calls))
	}
	// Early stop happens at page boundaries, so a page may hold >1 match.
	if out.ConsoleLogins.Matched < 1 || out.Sessions.Matched < 1 || out.Sessions.StopReason != "max_matches" || out.LastLogin == "" {
		t.Fatalf("unexpected: console=%+v sessions=%+v", out.ConsoleLogins, out.Sessions)
	}
}

func TestLogins_AllPrincipalsAggregates(t *testing.T) {
	api := account()
	out := run(t, api, map[string]any{"include_sessions": false})
	c := out.ConsoleLogins
	if c.Matched != 3 || len(c.Principals) != 2 || c.Events != nil {
		t.Fatalf("expected 3 logins by 2 principals, no raw event list: %+v", c)
	}
	if c.Principals[0].Name != "alice@example.com" || c.Principals[1].Name != "bob@example.com" {
		t.Fatalf("principals must be ordered by last seen: %+v", c.Principals)
	}
}
