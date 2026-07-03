package cw_logs_query

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	cwltypes "github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"
)

type fakeLogs struct {
	getCalls int
}

func (f *fakeLogs) StartQuery(_ context.Context, _ *cloudwatchlogs.StartQueryInput, _ ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.StartQueryOutput, error) {
	return &cloudwatchlogs.StartQueryOutput{QueryId: aws.String("q-1")}, nil
}

func (f *fakeLogs) GetQueryResults(_ context.Context, _ *cloudwatchlogs.GetQueryResultsInput, _ ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.GetQueryResultsOutput, error) {
	f.getCalls++
	if f.getCalls < 2 {
		return &cloudwatchlogs.GetQueryResultsOutput{Status: cwltypes.QueryStatusRunning}, nil
	}
	return &cloudwatchlogs.GetQueryResultsOutput{
		Status: cwltypes.QueryStatusComplete,
		Results: [][]cwltypes.ResultField{{
			{Field: aws.String("@timestamp"), Value: aws.String("2026-06-30 10:00:00.000")},
			{Field: aws.String("@message"), Value: aws.String("hello")},
		}},
	}, nil
}

func (f *fakeLogs) StopQuery(_ context.Context, _ *cloudwatchlogs.StopQueryInput, _ ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.StopQueryOutput, error) {
	return &cloudwatchlogs.StopQueryOutput{}, nil
}

func newTestTask(api logsInsightsAPI) *Task {
	t := NewWithClientFactory(func(_ context.Context, _ string) (logsInsightsAPI, error) { return api, nil })
	t.pollInterval = time.Millisecond
	return t
}

func TestExecute_PollsUntilComplete(t *testing.T) {
	api := &fakeLogs{}
	payload := `{"log_groups":["/aws/lambda/fn"],"query":"fields @message","start":"2026-06-30T09:00:00Z","end":"2026-06-30T11:00:00Z"}`
	res, err := newTestTask(api).Execute(context.Background(), json.RawMessage(payload))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	qr := res.Details.(QueryResult)
	if qr.Status != "Complete" || len(qr.Rows) != 1 || qr.Rows[0]["@message"] != "hello" {
		t.Fatalf("unexpected result: %+v", qr)
	}
	if api.getCalls < 2 {
		t.Fatalf("expected polling (>=2 GetQueryResults calls), got %d", api.getCalls)
	}
}

func TestExecute_MissingQuery(t *testing.T) {
	res, err := newTestTask(&fakeLogs{}).Execute(context.Background(), json.RawMessage(`{"log_groups":["g"],"start":"2026-06-30T09:00:00Z","end":"2026-06-30T11:00:00Z"}`))
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if res.Success {
		t.Fatal("expected success=false when query missing")
	}
}

type fakeLogsFailed struct{}

func (f *fakeLogsFailed) StartQuery(_ context.Context, _ *cloudwatchlogs.StartQueryInput, _ ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.StartQueryOutput, error) {
	return &cloudwatchlogs.StartQueryOutput{QueryId: aws.String("q-2")}, nil
}

func (f *fakeLogsFailed) GetQueryResults(_ context.Context, _ *cloudwatchlogs.GetQueryResultsInput, _ ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.GetQueryResultsOutput, error) {
	return &cloudwatchlogs.GetQueryResultsOutput{Status: cwltypes.QueryStatusFailed}, nil
}

func (f *fakeLogsFailed) StopQuery(_ context.Context, _ *cloudwatchlogs.StopQueryInput, _ ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.StopQueryOutput, error) {
	return &cloudwatchlogs.StopQueryOutput{}, nil
}

func TestExecute_TerminalFailure(t *testing.T) {
	api := &fakeLogsFailed{}
	payload := `{"log_groups":["/aws/lambda/fn"],"query":"fields @message","start":"2026-06-30T09:00:00Z","end":"2026-06-30T11:00:00Z"}`
	res, err := newTestTask(api).Execute(context.Background(), json.RawMessage(payload))
	if err != nil {
		t.Fatalf("expected nil Go error for terminal failure, got %v", err)
	}
	if res.Success {
		t.Fatalf("expected success=false for QueryStatusFailed, got result: %+v", res)
	}
	// Verify error field mentions the status
	if res.Error == "" {
		t.Fatalf("expected error field describing failure status, got empty. Full result: %+v", res)
	}
}
