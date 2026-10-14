// Package cloudtrail_lookup_events queries the account's CloudTrail event
// history (management events, last 90 days, one region per call) with an
// optional single lookup attribute, time range and principal match.
package cloudtrail_lookup_events

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"

	"github.com/loafoe/centcom-satellite/internal/task"
	ctc "github.com/loafoe/centcom-satellite/internal/task/cloudtrail_common"
)

const TaskName = "cloudtrail_lookup_events"

// LookupAttribute is CloudTrail's single server-side filter.
type LookupAttribute struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// Payload for cloudtrail_lookup_events.
type Payload struct {
	Region          string           `json:"region,omitempty"`
	LookupAttribute *LookupAttribute `json:"lookup_attribute,omitempty"`
	StartTime       string           `json:"start_time,omitempty"`
	EndTime         string           `json:"end_time,omitempty"`
	// MatchPrincipal filters client-side on the principal name/ARN
	// (case-insensitive substring), e.g. an email or role name.
	MatchPrincipal string `json:"match_principal,omitempty"`
	MaxMatches     int    `json:"max_matches,omitempty"`
	MaxPages       int    `json:"max_pages,omitempty"`
	NextToken      string `json:"next_token,omitempty"`
	IncludeRaw     bool   `json:"include_raw,omitempty"`
}

// Output adds guidance to the query result.
type Output struct {
	*ctc.Result
	Region string `json:"region"`
	Hint   string `json:"hint,omitempty"`
}

type Task struct{ clientFactory ctc.ClientFactory }

func New() *Task { return &Task{clientFactory: ctc.DefaultClientFactory} }

func NewWithClientFactory(f ctc.ClientFactory) *Task { return &Task{clientFactory: f} }

func (t *Task) Name() string { return TaskName }

func (t *Task) Execute(ctx context.Context, rawPayload json.RawMessage) (*task.Result, error) {
	var p Payload
	if len(rawPayload) > 0 {
		if err := json.Unmarshal(rawPayload, &p); err != nil {
			return task.NewErrorResult(fmt.Sprintf("invalid payload: %v", err)), nil
		}
	}
	q := ctc.Query{
		Region:     p.Region,
		Match:      p.MatchPrincipal,
		MaxMatches: p.MaxMatches,
		MaxPages:   p.MaxPages,
		NextToken:  p.NextToken,
		IncludeRaw: p.IncludeRaw,
	}
	if p.LookupAttribute != nil {
		key, ok := ctc.AttributeKeys[p.LookupAttribute.Key]
		if !ok || p.LookupAttribute.Value == "" {
			return task.NewErrorResult(fmt.Sprintf("lookup_attribute.key must be one of EventId, EventName, ReadOnly, Username, ResourceType, ResourceName, EventSource, AccessKeyId with a non-empty value (got %q)", p.LookupAttribute.Key)), nil
		}
		q.Attribute = &types.LookupAttribute{AttributeKey: key, AttributeValue: aws.String(p.LookupAttribute.Value)}
	}
	var err error
	if q.Start, err = ctc.ParseTime("start_time", p.StartTime); err != nil {
		return task.NewErrorResult(err.Error()), nil
	}
	if q.End, err = ctc.ParseTime("end_time", p.EndTime); err != nil {
		return task.NewErrorResult(err.Error()), nil
	}

	client, err := t.clientFactory(ctx, p.Region)
	if err != nil {
		return nil, fmt.Errorf("failed to build cloudtrail client: %w", err)
	}
	res, err := ctc.Run(ctx, client, q)
	if err != nil {
		return task.NewErrorResult(err.Error()), nil
	}

	out := Output{Result: res, Region: p.Region}
	if p.LookupAttribute != nil && p.LookupAttribute.Key == "Username" && !res.Complete {
		out.Hint = "Username matches every API call the principal made, so busy principals exhaust the page budget quickly. To find logins use cloudtrail_logins, or lookup_attribute EventName=ConsoleLogin with match_principal."
	}
	msg := fmt.Sprintf("%d matching events (%d scanned over %d pages, stop: %s)", res.Matched, res.ScannedEvents, res.Pages, res.StopReason)
	if !res.Complete && res.CoveredFrom != "" {
		msg += fmt.Sprintf("; covered %s..%s only, continue with next_token", res.CoveredFrom, res.CoveredTo)
	}
	if strings.TrimSpace(p.Region) == "" {
		out.Region = "default"
	}
	return task.NewSuccessResultWithDetails(msg, out), nil
}
