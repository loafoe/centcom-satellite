package cw_describe_log_groups

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	cwltypes "github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"
)

type fakeDLG struct {
	in  *cloudwatchlogs.DescribeLogGroupsInput
	out *cloudwatchlogs.DescribeLogGroupsOutput
	err error
}

func (f *fakeDLG) DescribeLogGroups(_ context.Context, in *cloudwatchlogs.DescribeLogGroupsInput, _ ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.DescribeLogGroupsOutput, error) {
	f.in = in
	return f.out, f.err
}

func newTestTask(api *fakeDLG) *Task {
	return NewWithClientFactory(func(_ context.Context, _ string) (describeLogGroupsAPI, error) { return api, nil })
}

func TestExecute_NormalizesLogGroups(t *testing.T) {
	api := &fakeDLG{out: &cloudwatchlogs.DescribeLogGroupsOutput{
		LogGroups: []cwltypes.LogGroup{{
			LogGroupName:    aws.String("/aws/lambda/fn"),
			Arn:             aws.String("arn:aws:logs:eu-west-1:1:log-group:/aws/lambda/fn:*"),
			StoredBytes:     aws.Int64(2048),
			RetentionInDays: aws.Int32(14),
			CreationTime:    aws.Int64(1751284800000),
		}},
	}}
	res, err := newTestTask(api).Execute(context.Background(), json.RawMessage(`{"name_prefix":"/aws/lambda/"}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	list := res.Details.(LogGroupList)
	if list.Total != 1 {
		t.Fatalf("Total = %d, want 1", list.Total)
	}
	lg := list.LogGroups[0]
	if lg.Name != "/aws/lambda/fn" {
		t.Errorf("Name = %q, want /aws/lambda/fn", lg.Name)
	}
	if lg.ARN != "arn:aws:logs:eu-west-1:1:log-group:/aws/lambda/fn:*" {
		t.Errorf("ARN = %q, want expected ARN", lg.ARN)
	}
	if lg.StoredBytes != 2048 {
		t.Errorf("StoredBytes = %d, want 2048", lg.StoredBytes)
	}
	if lg.RetentionDays != 14 {
		t.Errorf("RetentionDays = %d, want 14", lg.RetentionDays)
	}
	if lg.Created != "2025-06-30T12:00:00Z" {
		t.Errorf("Created = %q, want 2025-06-30T12:00:00Z", lg.Created)
	}
	if aws.ToString(api.in.LogGroupNamePrefix) != "/aws/lambda/" {
		t.Fatalf("prefix not forwarded: %+v", api.in.LogGroupNamePrefix)
	}
}

type fakePaginatingDLG struct {
	callCount int
}

func (f *fakePaginatingDLG) DescribeLogGroups(_ context.Context, input *cloudwatchlogs.DescribeLogGroupsInput, _ ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.DescribeLogGroupsOutput, error) {
	f.callCount++
	if f.callCount == 1 {
		return &cloudwatchlogs.DescribeLogGroupsOutput{
			LogGroups: []cwltypes.LogGroup{{
				LogGroupName:    aws.String("/app/service-1"),
				Arn:             aws.String("arn:aws:logs:us-east-1:123:log-group:/app/service-1:*"),
				StoredBytes:     aws.Int64(4096),
				RetentionInDays: aws.Int32(7),
				CreationTime:    aws.Int64(1704067200000),
			}},
			NextToken: aws.String("token-1"),
		}, nil
	}
	// Second call
	return &cloudwatchlogs.DescribeLogGroupsOutput{
		LogGroups: []cwltypes.LogGroup{{
			LogGroupName:    aws.String("/app/service-2"),
			Arn:             aws.String("arn:aws:logs:us-east-1:123:log-group:/app/service-2:*"),
			StoredBytes:     aws.Int64(8192),
			RetentionInDays: aws.Int32(30),
			CreationTime:    aws.Int64(1704153600000),
		}},
		NextToken: nil,
	}, nil
}

func TestExecute_Pagination(t *testing.T) {
	api := &fakePaginatingDLG{}
	task := NewWithClientFactory(func(_ context.Context, _ string) (describeLogGroupsAPI, error) { return api, nil })

	res, err := task.Execute(context.Background(), json.RawMessage(`{}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.Success {
		t.Fatalf("expected success, got error: %s", res.Error)
	}
	list, ok := res.Details.(LogGroupList)
	if !ok {
		t.Fatalf("details type = %T, want LogGroupList", res.Details)
	}
	if list.Total != 2 {
		t.Fatalf("Total = %d, want 2 (across both pages)", list.Total)
	}
	wantNames := []string{"/app/service-1", "/app/service-2"}
	wantStoredBytes := []int64{4096, 8192}
	wantRetentionDays := []int32{7, 30}
	wantCreated := []string{"2024-01-01T00:00:00Z", "2024-01-02T00:00:00Z"}
	for i, want := range wantNames {
		if i >= len(list.LogGroups) {
			t.Fatalf("missing log group at index %d", i)
		}
		lg := list.LogGroups[i]
		if lg.Name != want {
			t.Errorf("LogGroups[%d].Name = %q, want %q", i, lg.Name, want)
		}
		if lg.StoredBytes != wantStoredBytes[i] {
			t.Errorf("LogGroups[%d].StoredBytes = %d, want %d", i, lg.StoredBytes, wantStoredBytes[i])
		}
		if lg.RetentionDays != wantRetentionDays[i] {
			t.Errorf("LogGroups[%d].RetentionDays = %d, want %d", i, lg.RetentionDays, wantRetentionDays[i])
		}
		if lg.Created != wantCreated[i] {
			t.Errorf("LogGroups[%d].Created = %q, want %q", i, lg.Created, wantCreated[i])
		}
	}
	if api.callCount != 2 {
		t.Errorf("DescribeLogGroups called %d times, want 2", api.callCount)
	}
}
