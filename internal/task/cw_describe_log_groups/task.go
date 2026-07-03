// Package cw_describe_log_groups lists CloudWatch Logs log groups (discovery).
package cw_describe_log_groups

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"

	awshelper "github.com/loafoe/centcom-satellite/internal/aws"
	"github.com/loafoe/centcom-satellite/internal/task"
)

const TaskName = "cw_describe_log_groups"

const defaultLimit = 50

type describeLogGroupsAPI interface {
	DescribeLogGroups(context.Context, *cloudwatchlogs.DescribeLogGroupsInput, ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.DescribeLogGroupsOutput, error)
}

// Payload for cw_describe_log_groups.
type Payload struct {
	NamePrefix string `json:"name_prefix,omitempty"`
	Limit      int32  `json:"limit,omitempty"`
	Region     string `json:"region,omitempty"`
}

// LogGroup describes one log group.
type LogGroup struct {
	Name          string `json:"name"`
	ARN           string `json:"arn,omitempty"`
	StoredBytes   int64  `json:"stored_bytes"`
	RetentionDays int32  `json:"retention_days,omitempty"`
	Created       string `json:"created,omitempty"`
}

// LogGroupList is the result payload.
type LogGroupList struct {
	Total     int        `json:"total"`
	LogGroups []LogGroup `json:"log_groups"`
}

type Task struct {
	clientFactory func(ctx context.Context, region string) (describeLogGroupsAPI, error)
}

func New() *Task {
	return &Task{clientFactory: func(ctx context.Context, region string) (describeLogGroupsAPI, error) {
		cfg, err := awshelper.LoadConfig(ctx, awshelper.Options{Region: region})
		if err != nil {
			return nil, err
		}
		return cloudwatchlogs.NewFromConfig(cfg), nil
	}}
}

func NewWithClientFactory(f func(ctx context.Context, region string) (describeLogGroupsAPI, error)) *Task {
	return &Task{clientFactory: f}
}

func (t *Task) Name() string { return TaskName }

func (t *Task) Execute(ctx context.Context, rawPayload json.RawMessage) (*task.Result, error) {
	var payload Payload
	if len(rawPayload) > 0 {
		if err := json.Unmarshal(rawPayload, &payload); err != nil {
			return task.NewErrorResult(fmt.Sprintf("invalid payload: %v", err)), nil
		}
	}
	limit := payload.Limit
	if limit <= 0 {
		limit = defaultLimit
	}

	input := &cloudwatchlogs.DescribeLogGroupsInput{Limit: aws.Int32(limit)}
	if payload.NamePrefix != "" {
		input.LogGroupNamePrefix = aws.String(payload.NamePrefix)
	}

	client, err := t.clientFactory(ctx, payload.Region)
	if err != nil {
		return nil, fmt.Errorf("failed to build logs client: %w", err)
	}

	result := LogGroupList{LogGroups: []LogGroup{}}
	paginator := cloudwatchlogs.NewDescribeLogGroupsPaginator(client, input)
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("describe log groups: %w", err)
		}
		for _, g := range page.LogGroups {
			lg := LogGroup{
				Name:        aws.ToString(g.LogGroupName),
				ARN:         aws.ToString(g.Arn),
				StoredBytes: aws.ToInt64(g.StoredBytes),
			}
			if g.RetentionInDays != nil {
				lg.RetentionDays = *g.RetentionInDays
			}
			if g.CreationTime != nil {
				lg.Created = time.UnixMilli(*g.CreationTime).UTC().Format(time.RFC3339)
			}
			result.LogGroups = append(result.LogGroups, lg)
		}
	}
	result.Total = len(result.LogGroups)

	return task.NewSuccessResultWithDetails(fmt.Sprintf("found %d log groups", result.Total), result), nil
}
