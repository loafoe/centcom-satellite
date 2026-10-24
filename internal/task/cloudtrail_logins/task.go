// Package cloudtrail_logins answers "who logged into this AWS account" (or
// "did user X log in") efficiently. A Username lookup would page through
// every API call the user made, so instead it filters server-side on the
// login event and matches the user client-side:
//
//   - console sign-ins: EventName=ConsoleLogin — low volume, usually one call
//     covers the full 90-day history;
//   - sessions (console and CLI/SDK via IAM Identity Center):
//     EventName=AssumeRoleWithSAML — high volume, so scanned over a short,
//     capped window.
package cloudtrail_logins

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"

	awshelper "github.com/loafoe/centcom-satellite/internal/aws"
	"github.com/loafoe/centcom-satellite/internal/task"
	ctc "github.com/loafoe/centcom-satellite/internal/task/cloudtrail_common"
)

const TaskName = "cloudtrail_logins"

const (
	// Console sign-ins and global STS calls are recorded in us-east-1.
	defaultRegion       = "us-east-1"
	defaultConsoleDays  = 90
	defaultSessionHours = 24
	maxSessionHours     = 7 * 24
	defaultMaxPages     = 30
	recentSessionEvents = 10
)

// Payload for cloudtrail_logins.
type Payload struct {
	// User filters to principals whose name/ARN contains it
	// (case-insensitive), typically an email. Empty lists everyone.
	User            string `json:"user,omitempty"`
	Region          string `json:"region,omitempty"`
	ConsoleDays     int    `json:"console_days,omitempty"`
	SessionHours    int    `json:"session_hours,omitempty"`
	IncludeSessions *bool  `json:"include_sessions,omitempty"`
	MaxPages        int    `json:"max_pages,omitempty"`
	// StopAtFirstMatch answers "has User logged in" as cheaply as possible:
	// each scan stops at the first matching (i.e. most recent) event, so
	// counts are not totals.
	StopAtFirstMatch bool `json:"stop_at_first_match,omitempty"`
}

// PrincipalSummary aggregates one principal+role's logins.
type PrincipalSummary struct {
	Name      string   `json:"name"`
	Role      string   `json:"role,omitempty"`
	Count     int      `json:"count"`
	Failures  int      `json:"failures,omitempty"`
	FirstSeen string   `json:"first_seen"`
	LastSeen  string   `json:"last_seen"`
	SourceIPs []string `json:"source_ips,omitempty"`
}

// Section is the result of one of the two scans.
type Section struct {
	Query       string             `json:"query"`
	WindowStart string             `json:"window_start"`
	Matched     int                `json:"matched"`
	Scanned     int                `json:"scanned_events"`
	Pages       int                `json:"pages"`
	CoveredFrom string             `json:"covered_from,omitempty"`
	CoveredTo   string             `json:"covered_to,omitempty"`
	Complete    bool               `json:"complete"`
	StopReason  string             `json:"stop_reason"`
	Principals  []PrincipalSummary `json:"principals"`
	Events      []ctc.Event        `json:"events,omitempty"`
}

// Output for cloudtrail_logins.
type Output struct {
	User          string   `json:"user,omitempty"`
	Region        string   `json:"region"`
	LastLogin     string   `json:"last_login,omitempty"`
	ConsoleLogins Section  `json:"console_logins"`
	Sessions      *Section `json:"sessions,omitempty"`
	Note          string   `json:"note"`
}

type Task struct {
	clientFactory ctc.ClientFactory
	now           func() time.Time
}

func New() *Task { return &Task{clientFactory: ctc.DefaultClientFactory, now: time.Now} }

func NewWithClientFactory(f ctc.ClientFactory, now func() time.Time) *Task {
	return &Task{clientFactory: f, now: now}
}

func (t *Task) Name() string { return TaskName }

type aggregator struct {
	byKey map[string]*PrincipalSummary
	ips   map[string]map[string]bool
}

func newAggregator() *aggregator {
	return &aggregator{byKey: map[string]*PrincipalSummary{}, ips: map[string]map[string]bool{}}
}

func roleOf(e ctc.Event) string {
	if e.AssumedRole != "" {
		return lastSegment(e.AssumedRole)
	}
	return e.Principal.Role
}

func lastSegment(arn string) string {
	for i := len(arn) - 1; i >= 0; i-- {
		if arn[i] == '/' {
			return arn[i+1:]
		}
	}
	return arn
}

func (a *aggregator) add(e ctc.Event) {
	role := roleOf(e)
	// Identity providers hand out the same email in varying case.
	key := strings.ToLower(e.Principal.Name) + "|" + role
	s, ok := a.byKey[key]
	if !ok {
		s = &PrincipalSummary{Name: e.Principal.Name, Role: role, FirstSeen: e.EventTime, LastSeen: e.EventTime}
		a.byKey[key] = s
		a.ips[key] = map[string]bool{}
	}
	s.Count++
	if e.LoginResult == "Failure" || e.ErrorCode != "" {
		s.Failures++
	}
	// Events arrive newest first.
	if e.EventTime < s.FirstSeen {
		s.FirstSeen = e.EventTime
	}
	if e.EventTime > s.LastSeen {
		s.LastSeen = e.EventTime
		s.Name = e.Principal.Name
	}
	if e.SourceIP != "" && len(a.ips[key]) < 5 {
		a.ips[key][e.SourceIP] = true
	}
}

func (a *aggregator) list() []PrincipalSummary {
	out := make([]PrincipalSummary, 0, len(a.byKey))
	for key, s := range a.byKey {
		for ip := range a.ips[key] {
			s.SourceIPs = append(s.SourceIPs, ip)
		}
		sort.Strings(s.SourceIPs)
		out = append(out, *s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].LastSeen > out[j].LastSeen })
	return out
}

func matchCap(keep int, firstOnly bool) int {
	if firstOnly {
		return 1
	}
	return max(keep, 1)
}

func (t *Task) scan(ctx context.Context, client ctc.API, region, eventName, user string, since time.Time, maxPages, keepEvents int, firstOnly bool, deadline time.Time) (Section, error) {
	agg := newAggregator()
	start := since
	res, err := ctc.Run(ctx, client, ctc.Query{
		Region:     region,
		Attribute:  &types.LookupAttribute{AttributeKey: types.LookupAttributeKeyEventName, AttributeValue: aws.String(eventName)},
		Start:      &start,
		Match:      user,
		MaxPages:   maxPages,
		MaxMatches: matchCap(keepEvents, firstOnly),
		ScanAll:    !firstOnly,
		Deadline:   deadline,
		OnMatch:    agg.add,
	})
	if err != nil {
		return Section{}, err
	}
	sec := Section{
		Query:       "EventName=" + eventName,
		WindowStart: since.UTC().Format(time.RFC3339),
		Matched:     res.Matched,
		Scanned:     res.ScannedEvents,
		Pages:       res.Pages,
		CoveredFrom: res.CoveredFrom,
		CoveredTo:   res.CoveredTo,
		Complete:    res.Complete,
		StopReason:  res.StopReason,
		Principals:  agg.list(),
	}
	if keepEvents > 0 {
		sec.Events = res.Events
	}
	return sec, nil
}

func (t *Task) Execute(ctx context.Context, rawPayload json.RawMessage) (*task.Result, error) {
	var p Payload
	if len(rawPayload) > 0 {
		if err := json.Unmarshal(rawPayload, &p); err != nil {
			return task.NewErrorResult(fmt.Sprintf("invalid payload: %v", err)), nil
		}
	}
	region := p.Region
	if region == "" {
		region = defaultRegion
	}
	consoleDays := p.ConsoleDays
	if consoleDays <= 0 || consoleDays > defaultConsoleDays {
		consoleDays = defaultConsoleDays
	}
	sessionHours := p.SessionHours
	if sessionHours <= 0 {
		sessionHours = defaultSessionHours
	}
	sessionHours = min(sessionHours, maxSessionHours)
	maxPages := p.MaxPages
	if maxPages <= 0 {
		maxPages = defaultMaxPages
	}
	includeSessions := p.IncludeSessions == nil || *p.IncludeSessions
	firstOnly := p.StopAtFirstMatch && p.User != ""

	client, err := t.clientFactory(ctx, region)
	if err != nil {
		return nil, fmt.Errorf("failed to build cloudtrail client: %w", err)
	}
	now := t.now()
	deadline := time.Now().Add(ctc.TimeBudget)

	keepConsole := 0
	if p.User != "" {
		keepConsole = 50
	}
	console, err := t.scan(ctx, client, region, "ConsoleLogin", p.User, now.AddDate(0, 0, -consoleDays), maxPages, keepConsole, firstOnly, deadline)
	if err != nil {
		return awshelper.WrapError("lookup ConsoleLogin events", err)
	}
	out := Output{User: p.User, Region: region, ConsoleLogins: console,
		Note: "MFA is enforced by the identity provider / IAM Identity Center, not recorded on these events. Identity Center's own sign-in happens in the management account and is not visible here; IAM users with access keys have no login event."}
	if len(console.Principals) > 0 {
		out.LastLogin = console.Principals[0].LastSeen
	}

	if includeSessions {
		keep := 0
		if p.User != "" {
			keep = recentSessionEvents
		}
		sessions, err := t.scan(ctx, client, region, "AssumeRoleWithSAML", p.User, now.Add(-time.Duration(sessionHours)*time.Hour), maxPages, keep, firstOnly, deadline)
		if err != nil {
			return awshelper.WrapError("lookup AssumeRoleWithSAML events", err)
		}
		out.Sessions = &sessions
		if len(sessions.Principals) > 0 && sessions.Principals[0].LastSeen > out.LastLogin {
			out.LastLogin = sessions.Principals[0].LastSeen
		}
	}

	who := "all principals"
	if p.User != "" {
		who = p.User
	}
	msg := fmt.Sprintf("%s: %d console logins in %dd", who, console.Matched, consoleDays)
	if out.Sessions != nil {
		msg += fmt.Sprintf(", %d SSO sessions in %dh", out.Sessions.Matched, sessionHours)
	}
	if !console.Complete || (out.Sessions != nil && !out.Sessions.Complete) {
		msg += " (partial: see covered_from / stop_reason)"
	}
	return task.NewSuccessResultWithDetails(msg, out), nil
}
