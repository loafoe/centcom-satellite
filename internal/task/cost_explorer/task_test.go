package cost_explorer

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/costexplorer"
	cetypes "github.com/aws/aws-sdk-go-v2/service/costexplorer/types"
)

type fakeCE struct {
	in  *costexplorer.GetCostAndUsageInput
	out *costexplorer.GetCostAndUsageOutput
	err error
}

func (f *fakeCE) GetCostAndUsage(_ context.Context, in *costexplorer.GetCostAndUsageInput, _ ...func(*costexplorer.Options)) (*costexplorer.GetCostAndUsageOutput, error) {
	f.in = in
	return f.out, f.err
}

func newTestTask(api *fakeCE) *Task {
	return NewWithClientFactory(func(_ context.Context) (getCostAndUsageAPI, error) { return api, nil })
}

func TestExecute_MapsNamespaceToServiceFilter(t *testing.T) {
	api := &fakeCE{out: &costexplorer.GetCostAndUsageOutput{
		ResultsByTime: []cetypes.ResultByTime{{
			TimePeriod: &cetypes.DateInterval{Start: aws.String("2026-06-01"), End: aws.String("2026-07-01")},
			Total: map[string]cetypes.MetricValue{
				"UnblendedCost": {Amount: aws.String("12.34"), Unit: aws.String("USD")},
			},
		}},
	}}
	res, err := newTestTask(api).Execute(context.Background(), json.RawMessage(`{"namespace":"AWS/EC2"}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.Success {
		t.Fatalf("expected success, got %s", res.Error)
	}
	if api.in.Filter == nil {
		t.Fatal("expected a SERVICE filter to be set for AWS/EC2 namespace")
	}
	report := res.Details.(CostReport)
	if len(report.Periods) != 1 || report.Periods[0].Amount != "12.34" {
		t.Fatalf("unexpected report: %+v", report)
	}
}

func TestExecute_NoNamespaceNoFilter(t *testing.T) {
	api := &fakeCE{out: &costexplorer.GetCostAndUsageOutput{}}
	if _, err := newTestTask(api).Execute(context.Background(), json.RawMessage(`{}`)); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if api.in.Filter != nil {
		t.Fatal("expected no filter when namespace omitted")
	}
}

func TestExecute_UnknownNamespaceError(t *testing.T) {
	api := &fakeCE{out: &costexplorer.GetCostAndUsageOutput{}}
	res, err := newTestTask(api).Execute(context.Background(), json.RawMessage(`{"namespace":"AWS/UnknownService"}`))
	if err != nil {
		t.Fatalf("expected user error returned as Result, got Go error: %v", err)
	}
	if res.Success {
		t.Fatal("expected failure for unknown namespace")
	}
	if res.Error == "" {
		t.Fatal("expected error message describing unknown namespace")
	}
}

func TestExecute_GroupByServiceAndRegion(t *testing.T) {
	api := &fakeCE{out: &costexplorer.GetCostAndUsageOutput{
		ResultsByTime: []cetypes.ResultByTime{{
			TimePeriod: &cetypes.DateInterval{Start: aws.String("2026-06-01"), End: aws.String("2026-07-01")},
			Groups: []cetypes.Group{
				{
					Keys: []string{"Amazon Elastic Compute Cloud - Compute", "eu-west-2"},
					Metrics: map[string]cetypes.MetricValue{
						"UnblendedCost": {Amount: aws.String("100.00"), Unit: aws.String("USD")},
					},
				},
				{
					Keys: []string{"Amazon Relational Database Service", "us-east-1"},
					Metrics: map[string]cetypes.MetricValue{
						"UnblendedCost": {Amount: aws.String("50.00"), Unit: aws.String("USD")},
					},
				},
			},
		}},
	}}
	res, err := newTestTask(api).Execute(context.Background(), json.RawMessage(`{"group_by":["SERVICE","REGION"]}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.Success {
		t.Fatalf("expected success, got %s", res.Error)
	}
	if len(api.in.GroupBy) != 2 {
		t.Fatalf("expected 2 GroupBy entries, got %d", len(api.in.GroupBy))
	}
	if aws.ToString(api.in.GroupBy[0].Key) != string(cetypes.DimensionService) {
		t.Fatalf("expected first GroupBy SERVICE, got %v", aws.ToString(api.in.GroupBy[0].Key))
	}
	if aws.ToString(api.in.GroupBy[1].Key) != string(cetypes.DimensionRegion) {
		t.Fatalf("expected second GroupBy REGION, got %v", aws.ToString(api.in.GroupBy[1].Key))
	}
	report := res.Details.(CostReport)
	if len(report.Periods) != 1 || len(report.Periods[0].Groups) != 2 {
		t.Fatalf("expected 1 period with 2 groups, got %+v", report)
	}
	g0 := report.Periods[0].Groups[0]
	if len(g0.Keys) != 2 || g0.Keys[1] != "eu-west-2" || g0.Amount != "100.00" {
		t.Fatalf("unexpected first group: %+v", g0)
	}
}

func TestExecute_GroupByUnsupportedDimension(t *testing.T) {
	api := &fakeCE{out: &costexplorer.GetCostAndUsageOutput{}}
	res, err := newTestTask(api).Execute(context.Background(), json.RawMessage(`{"group_by":["BOGUS"]}`))
	if err != nil {
		t.Fatalf("expected user error as Result, got Go error: %v", err)
	}
	if res.Success {
		t.Fatal("expected failure for unsupported group_by dimension")
	}
}

func TestExecute_GroupByTooMany(t *testing.T) {
	api := &fakeCE{out: &costexplorer.GetCostAndUsageOutput{}}
	res, err := newTestTask(api).Execute(context.Background(), json.RawMessage(`{"group_by":["SERVICE","REGION","AZ"]}`))
	if err != nil {
		t.Fatalf("expected user error as Result, got Go error: %v", err)
	}
	if res.Success {
		t.Fatal("expected failure for >2 group_by dimensions")
	}
}

func TestExecute_VerifyServiceMappingInFilter(t *testing.T) {
	api := &fakeCE{out: &costexplorer.GetCostAndUsageOutput{}}
	_, err := newTestTask(api).Execute(context.Background(), json.RawMessage(`{"namespace":"AWS/RDS"}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if api.in.Filter == nil || api.in.Filter.Dimensions == nil {
		t.Fatal("expected SERVICE dimension filter for AWS/RDS")
	}
	if api.in.Filter.Dimensions.Key != cetypes.DimensionService {
		t.Fatalf("expected dimension key SERVICE, got %v", api.in.Filter.Dimensions.Key)
	}
	expectedService := "Amazon Relational Database Service"
	if len(api.in.Filter.Dimensions.Values) != 1 || api.in.Filter.Dimensions.Values[0] != expectedService {
		t.Fatalf("expected filter value %q, got %v", expectedService, api.in.Filter.Dimensions.Values)
	}
}
