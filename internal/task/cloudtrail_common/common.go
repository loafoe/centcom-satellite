// Package cloudtrail_common holds the CloudTrail LookupEvents query engine
// shared by the cloudtrail_* tasks: rate limiting, pagination with a time
// budget, event summarisation and principal matching.
package cloudtrail_common

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
	"github.com/aws/smithy-go"
	"golang.org/x/time/rate"

	awshelper "github.com/loafoe/centcom-satellite/internal/aws"
)

// API is the subset of the CloudTrail client the tasks use.
type API interface {
	LookupEvents(context.Context, *cloudtrail.LookupEventsInput, ...func(*cloudtrail.Options)) (*cloudtrail.LookupEventsOutput, error)
}

// ClientFactory builds a CloudTrail client for a region.
type ClientFactory func(ctx context.Context, region string) (API, error)

// DefaultClientFactory uses the shared AWS config with adaptive retries, so
// throttling backs off client-side on top of our own rate limiter.
func DefaultClientFactory(ctx context.Context, region string) (API, error) {
	cfg, err := awshelper.LoadConfig(ctx, awshelper.Options{Region: region})
	if err != nil {
		return nil, err
	}
	return cloudtrail.NewFromConfig(cfg, func(o *cloudtrail.Options) {
		o.RetryMode = aws.RetryModeAdaptive
		o.RetryMaxAttempts = 5
	}), nil
}

const (
	pageSize = 50
	// TimeBudget keeps a query well inside the satellite's 60s HTTP write
	// timeout; a query that hits it returns partial results + next_token.
	TimeBudget = 45 * time.Second

	DefaultMaxPages   = 10
	MaxPagesCap       = 60
	DefaultMaxMatches = 50
	MaxMatchesCap     = 500
)

var (
	limitersMu sync.Mutex
	limiters   = map[string]*rate.Limiter{}
	// AWS allows LookupEvents 2 TPS per account per region; stay under it so
	// concurrent callers in this process share the budget instead of
	// tripping ThrottlingException.
	ratePerSecond rate.Limit = 1.5
)

// SetRateLimitForTest overrides the per-region rate and returns a restore
// func. Test-only.
func SetRateLimitForTest(r float64) func() {
	limitersMu.Lock()
	prev := ratePerSecond
	ratePerSecond = rate.Limit(r)
	limiters = map[string]*rate.Limiter{}
	limitersMu.Unlock()
	return func() {
		limitersMu.Lock()
		ratePerSecond = prev
		limiters = map[string]*rate.Limiter{}
		limitersMu.Unlock()
	}
}

func limiterFor(region string) *rate.Limiter {
	limitersMu.Lock()
	defer limitersMu.Unlock()
	l, ok := limiters[region]
	if !ok {
		l = rate.NewLimiter(ratePerSecond, 1)
		limiters[region] = l
	}
	return l
}

// AttributeKeys are the LookupEvents filter keys AWS accepts.
var AttributeKeys = map[string]types.LookupAttributeKey{
	"EventId":      types.LookupAttributeKeyEventId,
	"EventName":    types.LookupAttributeKeyEventName,
	"ReadOnly":     types.LookupAttributeKeyReadOnly,
	"Username":     types.LookupAttributeKeyUsername,
	"ResourceType": types.LookupAttributeKeyResourceType,
	"ResourceName": types.LookupAttributeKeyResourceName,
	"EventSource":  types.LookupAttributeKeyEventSource,
	"AccessKeyId":  types.LookupAttributeKeyAccessKeyId,
}

// Principal identifies who performed an event, normalised across identity
// types: Name is the human-meaningful part (IAM user name, SSO email/session
// name, root, or invoking service).
type Principal struct {
	Type          string `json:"type,omitempty"`
	Name          string `json:"name,omitempty"`
	ARN           string `json:"arn,omitempty"`
	AccountID     string `json:"account_id,omitempty"`
	Role          string `json:"role,omitempty"`
	SessionIssuer string `json:"session_issuer,omitempty"`
}

// Resource is a resource referenced by an event.
type Resource struct {
	Type string `json:"type,omitempty"`
	Name string `json:"name,omitempty"`
}

// Event is a compact summary of a CloudTrail event.
type Event struct {
	EventID      string     `json:"event_id"`
	EventTime    string     `json:"event_time"`
	EventName    string     `json:"event_name"`
	EventSource  string     `json:"event_source"`
	AWSRegion    string     `json:"aws_region,omitempty"`
	SourceIP     string     `json:"source_ip,omitempty"`
	UserAgent    string     `json:"user_agent,omitempty"`
	ReadOnly     *bool      `json:"read_only,omitempty"`
	Principal    Principal  `json:"principal"`
	AssumedRole  string     `json:"assumed_role,omitempty"`
	LoginResult  string     `json:"login_result,omitempty"`
	ErrorCode    string     `json:"error_code,omitempty"`
	ErrorMessage string     `json:"error_message,omitempty"`
	Resources    []Resource `json:"resources,omitempty"`
	Raw          any        `json:"raw,omitempty"`
}

type rawEvent struct {
	EventTime    string `json:"eventTime"`
	EventSource  string `json:"eventSource"`
	EventName    string `json:"eventName"`
	AWSRegion    string `json:"awsRegion"`
	SourceIP     string `json:"sourceIPAddress"`
	UserAgent    string `json:"userAgent"`
	ErrorCode    string `json:"errorCode"`
	ErrorMessage string `json:"errorMessage"`
	ReadOnly     *bool  `json:"readOnly"`
	UserIdentity struct {
		Type        string `json:"type"`
		PrincipalID string `json:"principalId"`
		ARN         string `json:"arn"`
		AccountID   string `json:"accountId"`
		UserName    string `json:"userName"`
		InvokedBy   string `json:"invokedBy"`
		Session     struct {
			Issuer struct {
				ARN      string `json:"arn"`
				UserName string `json:"userName"`
			} `json:"sessionIssuer"`
		} `json:"sessionContext"`
	} `json:"userIdentity"`
	RequestParameters map[string]any `json:"requestParameters"`
	ResponseElements  map[string]any `json:"responseElements"`
}

// Summarize converts a LookupEvents result into an Event.
func Summarize(e types.Event, includeRaw bool) Event {
	out := Event{
		EventID:     aws.ToString(e.EventId),
		EventName:   aws.ToString(e.EventName),
		EventSource: aws.ToString(e.EventSource),
	}
	if e.EventTime != nil {
		out.EventTime = e.EventTime.UTC().Format(time.RFC3339)
	}
	for _, r := range e.Resources {
		out.Resources = append(out.Resources, Resource{Type: aws.ToString(r.ResourceType), Name: aws.ToString(r.ResourceName)})
	}

	var raw rawEvent
	if err := json.Unmarshal([]byte(aws.ToString(e.CloudTrailEvent)), &raw); err != nil {
		out.Principal.Name = aws.ToString(e.Username)
		return out
	}
	out.AWSRegion = raw.AWSRegion
	out.SourceIP = raw.SourceIP
	out.UserAgent = raw.UserAgent
	out.ReadOnly = raw.ReadOnly
	out.ErrorCode = raw.ErrorCode
	out.ErrorMessage = raw.ErrorMessage

	ui := raw.UserIdentity
	p := Principal{Type: ui.Type, ARN: ui.ARN, AccountID: ui.AccountID, SessionIssuer: ui.Session.Issuer.ARN}
	switch ui.Type {
	case "AssumedRole":
		// arn:aws:sts::<acct>:assumed-role/<role>/<session>
		if parts := strings.Split(ui.ARN, "/"); len(parts) >= 3 {
			p.Role = parts[len(parts)-2]
			p.Name = parts[len(parts)-1]
		}
		if p.Role == "" {
			p.Role = ui.Session.Issuer.UserName
		}
	case "Root":
		p.Name = "root"
	case "AWSService":
		p.Name = ui.InvokedBy
	default:
		p.Name = ui.UserName
	}
	if p.Name == "" {
		p.Name = aws.ToString(e.Username)
	}
	out.Principal = p

	if roleArn, ok := raw.RequestParameters["roleArn"].(string); ok {
		out.AssumedRole = roleArn
	}
	if r, ok := raw.ResponseElements["ConsoleLogin"].(string); ok {
		out.LoginResult = r
	}
	if includeRaw {
		var full any
		if json.Unmarshal([]byte(aws.ToString(e.CloudTrailEvent)), &full) == nil {
			out.Raw = full
		}
	}
	return out
}

// Matches reports whether the event's principal contains needle
// (case-insensitive) in its name or ARN. An empty needle matches everything.
func (e Event) Matches(needle string) bool {
	if needle == "" {
		return true
	}
	n := strings.ToLower(needle)
	for _, s := range []string{e.Principal.Name, e.Principal.ARN} {
		if s != "" && strings.Contains(strings.ToLower(s), n) {
			return true
		}
	}
	return false
}

// Query is one LookupEvents scan.
type Query struct {
	Region     string
	Attribute  *types.LookupAttribute
	Start, End *time.Time
	Match      string
	MaxMatches int
	MaxPages   int
	NextToken  string
	IncludeRaw bool
	// Deadline bounds the whole scan; zero means now+TimeBudget.
	Deadline time.Time
	// ScanAll keeps paginating after MaxMatches events are kept (only the
	// kept list is capped), for callers that aggregate via OnMatch.
	ScanAll bool
	// OnMatch, if set, sees every matching event, including those beyond
	// MaxMatches that are not kept in Result.Events.
	OnMatch func(Event)
}

// Result is the outcome of a Query. Coverage is the [oldest, newest] event
// time actually scanned — the honest answer to "how far back did we look".
type Result struct {
	Events        []Event `json:"events"`
	Matched       int     `json:"matched"`
	ScannedEvents int     `json:"scanned_events"`
	Pages         int     `json:"pages"`
	CoveredFrom   string  `json:"covered_from,omitempty"`
	CoveredTo     string  `json:"covered_to,omitempty"`
	// Complete is true when the requested window was fully scanned.
	Complete bool `json:"complete"`
	// StopReason: exhausted | max_matches | max_pages | time_budget | throttled.
	StopReason string `json:"stop_reason"`
	NextToken  string `json:"next_token,omitempty"`
}

// Run executes q, paginating newest-first until the window is exhausted or
// a limit is hit. Throttling and budget exhaustion return partial results,
// never an error, so callers always learn what was covered.
func Run(ctx context.Context, api API, q Query) (*Result, error) {
	if q.MaxPages <= 0 {
		q.MaxPages = DefaultMaxPages
	}
	q.MaxPages = min(q.MaxPages, MaxPagesCap)
	if q.MaxMatches <= 0 {
		q.MaxMatches = DefaultMaxMatches
	}
	q.MaxMatches = min(q.MaxMatches, MaxMatchesCap)
	deadline := q.Deadline
	if deadline.IsZero() {
		deadline = time.Now().Add(TimeBudget)
	}

	res := &Result{Events: []Event{}}
	token := q.NextToken
	limiter := limiterFor(q.Region)
	for {
		if res.Pages >= q.MaxPages {
			res.StopReason = "max_pages"
			break
		}
		if time.Until(deadline) < 2*time.Second {
			res.StopReason = "time_budget"
			break
		}
		waitCtx, cancel := context.WithDeadline(ctx, deadline)
		err := limiter.Wait(waitCtx)
		cancel()
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			res.StopReason = "time_budget"
			break
		}

		in := &cloudtrail.LookupEventsInput{MaxResults: aws.Int32(pageSize), StartTime: q.Start, EndTime: q.End}
		if q.Attribute != nil {
			in.LookupAttributes = []types.LookupAttribute{*q.Attribute}
		}
		if token != "" {
			in.NextToken = aws.String(token)
		}
		callCtx, cancel := context.WithDeadline(ctx, deadline)
		out, err := api.LookupEvents(callCtx, in)
		cancel()
		if err != nil {
			if isThrottle(err) {
				res.StopReason = "throttled"
				break
			}
			if ctx.Err() == nil && time.Now().After(deadline) {
				res.StopReason = "time_budget"
				break
			}
			return nil, fmt.Errorf("lookup events: %w", err)
		}
		res.Pages++
		for _, e := range out.Events {
			res.ScannedEvents++
			t := ""
			if e.EventTime != nil {
				t = e.EventTime.UTC().Format(time.RFC3339)
			}
			if res.CoveredTo == "" {
				res.CoveredTo = t
			}
			res.CoveredFrom = t
			ev := Summarize(e, q.IncludeRaw)
			if !ev.Matches(q.Match) {
				continue
			}
			res.Matched++
			if q.OnMatch != nil {
				q.OnMatch(ev)
			}
			if len(res.Events) < q.MaxMatches {
				res.Events = append(res.Events, ev)
			}
		}
		token = aws.ToString(out.NextToken)
		if token == "" {
			res.StopReason = "exhausted"
			res.Complete = true
			break
		}
		if !q.ScanAll && res.Matched >= q.MaxMatches {
			res.StopReason = "max_matches"
			break
		}
	}
	if !res.Complete {
		res.NextToken = token
	}
	return res, nil
}

func isThrottle(err error) bool {
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		switch apiErr.ErrorCode() {
		case "ThrottlingException", "Throttling", "TooManyRequestsException", "RequestLimitExceeded":
			return true
		}
	}
	return false
}

// ParseTime parses an optional RFC3339 timestamp.
func ParseTime(field, v string) (*time.Time, error) {
	if v == "" {
		return nil, nil
	}
	t, err := time.Parse(time.RFC3339, v)
	if err != nil {
		return nil, fmt.Errorf("%s must be RFC3339: %v", field, err)
	}
	return &t, nil
}
