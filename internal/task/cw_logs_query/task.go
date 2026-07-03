// Package cw_logs_query runs a CloudWatch Logs Insights query and polls for
// results until the query completes or the deadline is reached.
package cw_logs_query

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	cwltypes "github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"

	awshelper "github.com/loafoe/centcom-satellite/internal/aws"
	"github.com/loafoe/centcom-satellite/internal/task"
)

const TaskName = "cw_logs_query"

const (
	defaultLimit    = 100
	defaultTimeout  = 30 * time.Second
	maxTimeout      = 60 * time.Second
	defaultPollWait = 1 * time.Second
)

type logsInsightsAPI interface {
	StartQuery(context.Context, *cloudwatchlogs.StartQueryInput, ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.StartQueryOutput, error)
	GetQueryResults(context.Context, *cloudwatchlogs.GetQueryResultsInput, ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.GetQueryResultsOutput, error)
	StopQuery(context.Context, *cloudwatchlogs.StopQueryInput, ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.StopQueryOutput, error)
}

// Payload for cw_logs_query.
type Payload struct {
	LogGroups []string `json:"log_groups"`
	Query     string   `json:"query"`
	Start     string   `json:"start"` // RFC3339, required
	End       string   `json:"end"`   // RFC3339, required
	Limit     int32    `json:"limit,omitempty"`
	TimeoutMs int      `json:"timeout_ms,omitempty"`
	Region    string   `json:"region,omitempty"`
}

// QueryResult is the result payload.
type QueryResult struct {
	Status string              `json:"status"`
	Rows   []map[string]string `json:"rows"`
}

type Task struct {
	clientFactory func(ctx context.Context, region string) (logsInsightsAPI, error)
	pollInterval  time.Duration
}

func New() *Task {
	return &Task{
		clientFactory: func(ctx context.Context, region string) (logsInsightsAPI, error) {
			cfg, err := awshelper.LoadConfig(ctx, awshelper.Options{Region: region})
			if err != nil {
				return nil, err
			}
			return cloudwatchlogs.NewFromConfig(cfg), nil
		},
		pollInterval: defaultPollWait,
	}
}

func NewWithClientFactory(f func(ctx context.Context, region string) (logsInsightsAPI, error)) *Task {
	return &Task{clientFactory: f, pollInterval: defaultPollWait}
}

func (t *Task) Name() string { return TaskName }

func (t *Task) Execute(ctx context.Context, rawPayload json.RawMessage) (*task.Result, error) {
	var payload Payload
	if err := json.Unmarshal(rawPayload, &payload); err != nil {
		return task.NewErrorResult(fmt.Sprintf("invalid payload: %v", err)), nil
	}
	if len(payload.LogGroups) == 0 {
		return task.NewErrorResult("log_groups is required"), nil
	}
	if payload.Query == "" {
		return task.NewErrorResult("query is required"), nil
	}
	start, err := time.Parse(time.RFC3339, payload.Start)
	if err != nil {
		return task.NewErrorResult(fmt.Sprintf("invalid start (want RFC3339): %v", err)), nil
	}
	end, err := time.Parse(time.RFC3339, payload.End)
	if err != nil {
		return task.NewErrorResult(fmt.Sprintf("invalid end (want RFC3339): %v", err)), nil
	}
	limit := payload.Limit
	if limit <= 0 {
		limit = defaultLimit
	}
	timeout := defaultTimeout
	if payload.TimeoutMs > 0 {
		timeout = time.Duration(payload.TimeoutMs) * time.Millisecond
		if timeout > maxTimeout {
			timeout = maxTimeout
		}
	}

	client, err := t.clientFactory(ctx, payload.Region)
	if err != nil {
		return nil, fmt.Errorf("failed to build logs client: %w", err)
	}

	startOut, err := client.StartQuery(ctx, &cloudwatchlogs.StartQueryInput{
		LogGroupNames: payload.LogGroups,
		QueryString:   aws.String(payload.Query),
		StartTime:     aws.Int64(start.Unix()),
		EndTime:       aws.Int64(end.Unix()),
		Limit:         aws.Int32(limit),
	})
	if err != nil {
		return nil, fmt.Errorf("start query: %w", err)
	}
	queryID := aws.ToString(startOut.QueryId)

	deadline := time.Now().Add(timeout)
	for {
		out, err := client.GetQueryResults(ctx, &cloudwatchlogs.GetQueryResultsInput{QueryId: aws.String(queryID)})
		if err != nil {
			return nil, fmt.Errorf("get query results: %w", err)
		}

		switch out.Status {
		case cwltypes.QueryStatusComplete:
			return task.NewSuccessResultWithDetails(
				fmt.Sprintf("query complete: %d rows", len(out.Results)),
				buildResult(out),
			), nil
		case cwltypes.QueryStatusFailed, cwltypes.QueryStatusCancelled, cwltypes.QueryStatusTimeout:
			return task.NewErrorResult(fmt.Sprintf("query ended with status %s", out.Status)), nil
		}

		if time.Now().After(deadline) {
			_, _ = client.StopQuery(ctx, &cloudwatchlogs.StopQueryInput{QueryId: aws.String(queryID)})
			return task.NewErrorResult(fmt.Sprintf("query timed out after %s (last status %s)", timeout, out.Status)), nil
		}

		select {
		case <-ctx.Done():
			_, _ = client.StopQuery(ctx, &cloudwatchlogs.StopQueryInput{QueryId: aws.String(queryID)})
			return nil, ctx.Err()
		case <-time.After(t.pollInterval):
		}
	}
}

func buildResult(out *cloudwatchlogs.GetQueryResultsOutput) QueryResult {
	qr := QueryResult{Status: string(out.Status), Rows: []map[string]string{}}
	for _, row := range out.Results {
		m := map[string]string{}
		for _, f := range row {
			m[aws.ToString(f.Field)] = aws.ToString(f.Value)
		}
		qr.Rows = append(qr.Rows, m)
	}
	return qr
}
