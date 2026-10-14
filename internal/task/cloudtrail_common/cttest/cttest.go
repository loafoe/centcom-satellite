// Package cttest provides a fake CloudTrail LookupEvents API and realistic
// event builders for tests.
package cttest

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
	"github.com/aws/smithy-go"
)

// FakeAPI serves events newest-first in pages of pageSize and records calls.
type FakeAPI struct {
	Events         []types.Event
	Calls          []*cloudtrail.LookupEventsInput
	ThrottleAtCall int
}

func (f *FakeAPI) LookupEvents(_ context.Context, in *cloudtrail.LookupEventsInput, _ ...func(*cloudtrail.Options)) (*cloudtrail.LookupEventsOutput, error) {
	f.Calls = append(f.Calls, in)
	if f.ThrottleAtCall > 0 && len(f.Calls) == f.ThrottleAtCall {
		return nil, &smithy.GenericAPIError{Code: "ThrottlingException", Message: "Rate exceeded"}
	}
	start := 0
	if in.NextToken != nil {
		fmt.Sscanf(*in.NextToken, "%d", &start)
	}
	var filtered []types.Event
	for _, e := range f.Events {
		if in.StartTime != nil && e.EventTime.Before(*in.StartTime) {
			continue
		}
		if len(in.LookupAttributes) == 1 && in.LookupAttributes[0].AttributeKey == types.LookupAttributeKeyEventName &&
			aws.ToString(e.EventName) != aws.ToString(in.LookupAttributes[0].AttributeValue) {
			continue
		}
		filtered = append(filtered, e)
	}
	end := min(start+int(aws.ToInt32(in.MaxResults)), len(filtered))
	out := &cloudtrail.LookupEventsOutput{Events: filtered[start:end]}
	if end < len(filtered) {
		out.NextToken = aws.String(fmt.Sprint(end))
	}
	return out, nil
}

// MakeEvent builds a realistic LookupEvents record.
func MakeEvent(t time.Time, name string, identity map[string]any, extra map[string]any) types.Event {
	body := map[string]any{"eventTime": t.UTC().Format(time.RFC3339), "eventName": name, "eventSource": "signin.amazonaws.com",
		"awsRegion": "us-east-1", "sourceIPAddress": "203.0.113.7", "userAgent": "Mozilla/5.0", "userIdentity": identity}
	for k, v := range extra {
		body[k] = v
	}
	raw, _ := json.Marshal(body)
	return types.Event{EventId: aws.String(fmt.Sprintf("%s-%d", name, t.UnixNano())), EventName: aws.String(name),
		EventSource: aws.String("signin.amazonaws.com"), EventTime: aws.Time(t), CloudTrailEvent: aws.String(string(raw))}
}

func SSOConsoleLogin(t time.Time, email string) types.Event {
	return MakeEvent(t, "ConsoleLogin", map[string]any{
		"type": "AssumedRole", "accountId": "123456789012",
		"arn": "arn:aws:sts::123456789012:assumed-role/AWSReservedSSO_AWSAdministratorAccess_abc/" + email,
		"sessionContext": map[string]any{"sessionIssuer": map[string]any{
			"arn": "arn:aws:iam::123456789012:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_AWSAdministratorAccess_abc", "userName": "AWSReservedSSO_AWSAdministratorAccess_abc"}},
	}, map[string]any{"responseElements": map[string]any{"ConsoleLogin": "Success"}})
}
