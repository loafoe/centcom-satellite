package cloudtrail_lookup_events

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"

	ctc "github.com/loafoe/centcom-satellite/internal/task/cloudtrail_common"
	"github.com/loafoe/centcom-satellite/internal/task/cloudtrail_common/cttest"
)

func execute(t *testing.T, api *cttest.FakeAPI, payload string) (bool, string, Output) {
	t.Helper()
	defer ctc.SetRateLimitForTest(10000)()
	tk := NewWithClientFactory(func(context.Context, string) (ctc.API, error) { return api, nil })
	res, err := tk.Execute(context.Background(), json.RawMessage(payload))
	if err != nil {
		t.Fatal(err)
	}
	var out Output
	if res.Success {
		b, _ := json.Marshal(res.Details)
		_ = json.Unmarshal(b, &out)
	}
	return res.Success, res.Message + res.Error, out
}

func TestLookupEvents_PassesFiltersAndMatches(t *testing.T) {
	now := time.Now()
	api := &cttest.FakeAPI{Events: []types.Event{
		cttest.SSOConsoleLogin(now, "alice@example.com"),
		cttest.SSOConsoleLogin(now.Add(-time.Hour), "bob@example.com"),
	}}
	start := now.Add(-24 * time.Hour).UTC().Format(time.RFC3339)
	ok, msg, out := execute(t, api, `{"region":"us-east-1","lookup_attribute":{"key":"EventName","value":"ConsoleLogin"},"start_time":"`+start+`","match_principal":"ALICE"}`)
	if !ok || out.Matched != 1 || out.Events[0].Principal.Name != "alice@example.com" {
		t.Fatalf("ok=%v msg=%s out=%+v", ok, msg, out.Result)
	}
	in := api.Calls[0]
	if aws.ToString(in.LookupAttributes[0].AttributeValue) != "ConsoleLogin" || in.StartTime == nil || aws.ToInt32(in.MaxResults) != 50 {
		t.Fatalf("filters not passed through: %+v", in)
	}
}

func TestLookupEvents_ValidatesInput(t *testing.T) {
	for _, p := range []string{
		`{"lookup_attribute":{"key":"eventname","value":"x"}}`,
		`{"lookup_attribute":{"key":"EventName","value":""}}`,
		`{"start_time":"yesterday"}`,
		`{not json`,
	} {
		if ok, _, _ := execute(t, &cttest.FakeAPI{}, p); ok {
			t.Errorf("payload %s must be rejected", p)
		}
	}
}

func TestLookupEvents_UsernameHintWhenTruncated(t *testing.T) {
	var ev []types.Event
	now := time.Now()
	for i := range 200 {
		ev = append(ev, cttest.SSOConsoleLogin(now.Add(-time.Duration(i)*time.Second), "alice@example.com"))
	}
	_, _, out := execute(t, &cttest.FakeAPI{Events: ev}, `{"lookup_attribute":{"key":"Username","value":"alice@example.com"},"max_pages":1}`)
	if !strings.Contains(out.Hint, "cloudtrail_logins") || out.NextToken == "" {
		t.Fatalf("expected Username hint and next_token: %+v", out)
	}
}
