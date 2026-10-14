package cloudtrail_common

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"

	"github.com/loafoe/centcom-satellite/internal/task/cloudtrail_common/cttest"
)

func TestSummarize_PrincipalShapes(t *testing.T) {
	now := time.Now()
	cases := []struct {
		ev              types.Event
		name, role, typ string
		loginResult     string
		assumedRole     string
	}{
		{cttest.SSOConsoleLogin(now, "alice@example.com"), "alice@example.com", "AWSReservedSSO_AWSAdministratorAccess_abc", "AssumedRole", "Success", ""},
		{cttest.MakeEvent(now, "AssumeRoleWithSAML", map[string]any{"type": "SAMLUser", "userName": "bob@example.com", "principalId": "x:bob@example.com"},
			map[string]any{"requestParameters": map[string]any{"roleArn": "arn:aws:iam::123456789012:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_ReadOnly_1"}}),
			"bob@example.com", "", "SAMLUser", "", "arn:aws:iam::123456789012:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_ReadOnly_1"},
		{cttest.MakeEvent(now, "ConsoleLogin", map[string]any{"type": "IAMUser", "userName": "legacy-admin", "arn": "arn:aws:iam::123456789012:user/legacy-admin"},
			map[string]any{"responseElements": map[string]any{"ConsoleLogin": "Failure"}, "errorMessage": "Failed authentication"}),
			"legacy-admin", "", "IAMUser", "Failure", ""},
		{cttest.MakeEvent(now, "ConsoleLogin", map[string]any{"type": "Root", "arn": "arn:aws:iam::123456789012:root"}, nil), "root", "", "Root", "", ""},
	}
	for _, c := range cases {
		e := Summarize(c.ev, false)
		if e.Principal.Name != c.name || e.Principal.Role != c.role || e.Principal.Type != c.typ || e.LoginResult != c.loginResult || e.AssumedRole != c.assumedRole {
			t.Errorf("Summarize(%s/%s) = %+v", c.typ, c.name, e)
		}
		if e.Raw != nil {
			t.Error("raw must be omitted unless requested")
		}
	}
	if e := Summarize(cttest.SSOConsoleLogin(now, "a@x"), true); e.Raw == nil {
		t.Error("include_raw must attach the raw event")
	}
}

func fixture(n int, email func(i int) string) []types.Event {
	now := time.Now()
	out := make([]types.Event, n)
	for i := range n {
		out[i] = cttest.SSOConsoleLogin(now.Add(-time.Duration(i)*time.Minute), email(i))
	}
	return out
}

func TestRun_MatchesAcrossPagesAndReportsCoverage(t *testing.T) {
	defer SetRateLimitForTest(1000)()
	api := &cttest.FakeAPI{Events: fixture(120, func(i int) string {
		if i%40 == 0 {
			return "Alice@Example.com"
		}
		return "someone@example.com"
	})}
	res, err := Run(context.Background(), api, Query{Region: "us-east-1", Match: "alice@example.com", MaxPages: 10})
	if err != nil {
		t.Fatal(err)
	}
	if res.Matched != 3 || len(res.Events) != 3 || res.Pages != 3 || res.ScannedEvents != 120 || !res.Complete || res.StopReason != "exhausted" || res.NextToken != "" {
		t.Fatalf("unexpected result: %s", desc(res))
	}
	if res.CoveredTo <= res.CoveredFrom {
		t.Fatalf("coverage must span newest..oldest: %s..%s", res.CoveredFrom, res.CoveredTo)
	}
}

func TestRun_StopReasons(t *testing.T) {
	defer SetRateLimitForTest(1000)()
	all := func(int) string { return "u@example.com" }

	res, _ := Run(context.Background(), &cttest.FakeAPI{Events: fixture(200, all)}, Query{MaxPages: 2, ScanAll: true})
	if res.StopReason != "max_pages" || res.Complete || res.NextToken == "" || res.Pages != 2 {
		t.Fatalf("max_pages: %s", desc(res))
	}

	res, _ = Run(context.Background(), &cttest.FakeAPI{Events: fixture(200, all)}, Query{MaxMatches: 5})
	if res.StopReason != "max_matches" || len(res.Events) != 5 || res.Pages != 1 {
		t.Fatalf("max_matches: %s", desc(res))
	}

	res, _ = Run(context.Background(), &cttest.FakeAPI{Events: fixture(200, all)}, Query{MaxMatches: 5, ScanAll: true})
	if !res.Complete || res.Matched != 200 || len(res.Events) != 5 {
		t.Fatalf("scan_all must keep paging but cap kept events: %s", desc(res))
	}

	api := &cttest.FakeAPI{Events: fixture(200, all), ThrottleAtCall: 2}
	res, err := Run(context.Background(), api, Query{ScanAll: true})
	if err != nil {
		t.Fatalf("throttling must return partial results, not an error: %v", err)
	}
	if res.StopReason != "throttled" || res.Pages != 1 || res.NextToken == "" {
		t.Fatalf("throttled: %s", desc(res))
	}

	res, _ = Run(context.Background(), &cttest.FakeAPI{Events: fixture(200, all)}, Query{Deadline: time.Now().Add(time.Second)})
	if res.StopReason != "time_budget" || res.Pages != 0 {
		t.Fatalf("time_budget: %s", desc(res))
	}
}

func TestRun_ResumesFromNextToken(t *testing.T) {
	defer SetRateLimitForTest(1000)()
	api := &cttest.FakeAPI{Events: fixture(120, func(int) string { return "u@x" })}
	first, _ := Run(context.Background(), api, Query{MaxPages: 1, ScanAll: true})
	second, _ := Run(context.Background(), api, Query{NextToken: first.NextToken, ScanAll: true})
	if first.ScannedEvents+second.ScannedEvents != 120 || !second.Complete {
		t.Fatalf("resume lost events: %d + %d", first.ScannedEvents, second.ScannedEvents)
	}
}

func TestRun_RespectsRateLimit(t *testing.T) {
	defer SetRateLimitForTest(10)()
	start := time.Now()
	res, _ := Run(context.Background(), &cttest.FakeAPI{Events: fixture(200, func(int) string { return "u" })}, Query{ScanAll: true})
	if res.Pages != 4 {
		t.Fatalf("pages=%d", res.Pages)
	}
	if elapsed := time.Since(start); elapsed < 250*time.Millisecond {
		t.Fatalf("4 calls at 10 rps (burst 1) must take >=300ms, took %v", elapsed)
	}
}

func desc(r *Result) string {
	return fmt.Sprintf("matched=%d kept=%d pages=%d scanned=%d complete=%v stop=%s next=%q", r.Matched, len(r.Events), r.Pages, r.ScannedEvents, r.Complete, r.StopReason, r.NextToken)
}
