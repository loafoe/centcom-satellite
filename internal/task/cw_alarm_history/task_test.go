package cw_alarm_history

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cwtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
)

type fakeAPI struct {
	out *cloudwatch.DescribeAlarmHistoryOutput
	err error
}

func (f *fakeAPI) DescribeAlarmHistory(_ context.Context, _ *cloudwatch.DescribeAlarmHistoryInput, _ ...func(*cloudwatch.Options)) (*cloudwatch.DescribeAlarmHistoryOutput, error) {
	return f.out, f.err
}

func newTestTask(api describeAlarmHistoryAPI) *Task {
	return NewWithClientFactory(func(_ context.Context, _ string) (describeAlarmHistoryAPI, error) { return api, nil })
}

func TestExecute_ParsesHistoryData(t *testing.T) {
	ts := time.Date(2026, 6, 30, 10, 0, 0, 0, time.UTC)
	hist := `{"oldState":{"stateValue":"OK"},"newState":{"stateValue":"ALARM","stateReason":"breached"}}`
	api := &fakeAPI{out: &cloudwatch.DescribeAlarmHistoryOutput{
		AlarmHistoryItems: []cwtypes.AlarmHistoryItem{{
			Timestamp:   &ts,
			HistoryData: aws.String(hist),
		}},
	}}
	res, err := newTestTask(api).Execute(context.Background(), json.RawMessage(`{"alarm_name":"a"}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	items := res.Details.(HistoryList).Items
	if len(items) != 1 || items[0].NewState != "ALARM" || items[0].Reason != "breached" {
		t.Fatalf("unexpected parse: %+v", items)
	}
}

func TestExecute_MissingAlarmName(t *testing.T) {
	res, err := newTestTask(&fakeAPI{}).Execute(context.Background(), json.RawMessage(`{}`))
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if res.Success {
		t.Fatal("expected success=false when alarm_name missing")
	}
}

func TestExecute_ChronologicalSorting(t *testing.T) {
	ts1 := time.Date(2026, 6, 30, 12, 0, 0, 0, time.UTC)
	ts2 := time.Date(2026, 6, 30, 10, 0, 0, 0, time.UTC)
	ts3 := time.Date(2026, 6, 30, 11, 0, 0, 0, time.UTC)
	hist := `{"oldState":{"stateValue":"OK"},"newState":{"stateValue":"ALARM"}}`

	// Seed items out of chronological order
	api := &fakeAPI{out: &cloudwatch.DescribeAlarmHistoryOutput{
		AlarmHistoryItems: []cwtypes.AlarmHistoryItem{
			{Timestamp: &ts1, HistoryData: aws.String(hist)},
			{Timestamp: &ts2, HistoryData: aws.String(hist)},
			{Timestamp: &ts3, HistoryData: aws.String(hist)},
		},
	}}
	res, err := newTestTask(api).Execute(context.Background(), json.RawMessage(`{"alarm_name":"test"}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	items := res.Details.(HistoryList).Items
	if len(items) != 3 {
		t.Fatalf("expected 3 items, got %d", len(items))
	}
	// Assert ascending chronological order
	if items[0].Timestamp >= items[1].Timestamp || items[1].Timestamp >= items[2].Timestamp {
		t.Fatalf("items not sorted chronologically: %v", items)
	}
}

func TestExecute_SkipsMalformedHistoryData(t *testing.T) {
	ts1 := time.Date(2026, 7, 3, 10, 0, 0, 0, time.UTC)
	ts2 := time.Date(2026, 7, 3, 11, 0, 0, 0, time.UTC)
	validHist := `{"oldState":{"stateValue":"OK"},"newState":{"stateValue":"ALARM","stateReason":"breached"}}`
	malformedHist := `{not json`

	api := &fakeAPI{out: &cloudwatch.DescribeAlarmHistoryOutput{
		AlarmHistoryItems: []cwtypes.AlarmHistoryItem{
			{Timestamp: &ts1, HistoryData: aws.String(validHist)},
			{Timestamp: &ts2, HistoryData: aws.String(malformedHist)},
		},
	}}
	res, err := newTestTask(api).Execute(context.Background(), json.RawMessage(`{"alarm_name":"test"}`))
	if err != nil {
		t.Fatalf("expected nil error for best-effort processing, got %v", err)
	}
	if !res.Success {
		t.Fatalf("expected success=true, got false")
	}
	items := res.Details.(HistoryList).Items
	// Only the valid item should be present; malformed one skipped
	if len(items) != 1 {
		t.Fatalf("expected 1 item (malformed skipped), got %d", len(items))
	}
	if items[0].NewState != "ALARM" || items[0].Reason != "breached" {
		t.Fatalf("unexpected item: %+v", items[0])
	}
}
