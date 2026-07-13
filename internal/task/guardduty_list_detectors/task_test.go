package guardduty_list_detectors

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/guardduty"
	gdtypes "github.com/aws/aws-sdk-go-v2/service/guardduty/types"
)

type fakeAPI struct {
	listOut *guardduty.ListDetectorsOutput
	getOut  map[string]*guardduty.GetDetectorOutput
}

func (f *fakeAPI) ListDetectors(_ context.Context, _ *guardduty.ListDetectorsInput, _ ...func(*guardduty.Options)) (*guardduty.ListDetectorsOutput, error) {
	return f.listOut, nil
}

func (f *fakeAPI) GetDetector(_ context.Context, in *guardduty.GetDetectorInput, _ ...func(*guardduty.Options)) (*guardduty.GetDetectorOutput, error) {
	return f.getOut[aws.ToString(in.DetectorId)], nil
}

func newTestTask(a api) *Task {
	return NewWithClientFactory(func(_ context.Context, _ string) (api, error) { return a, nil })
}

func TestExecute_NormalizesDetector(t *testing.T) {
	api := &fakeAPI{
		listOut: &guardduty.ListDetectorsOutput{DetectorIds: []string{"det-1"}},
		getOut: map[string]*guardduty.GetDetectorOutput{
			"det-1": {
				Status:                     gdtypes.DetectorStatusEnabled,
				ServiceRole:                aws.String("arn:aws:iam::1:role/gd"),
				FindingPublishingFrequency: gdtypes.FindingPublishingFrequencyFifteenMinutes,
				CreatedAt:                  aws.String("2026-01-01T00:00:00.000Z"),
				Features: []gdtypes.DetectorFeatureConfigurationResult{
					{Name: gdtypes.DetectorFeatureResultS3DataEvents, Status: gdtypes.FeatureStatusEnabled},
				},
			},
		},
	}

	res, err := newTestTask(api).Execute(context.Background(), json.RawMessage(`{}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.Success {
		t.Fatalf("expected success, got error: %s", res.Error)
	}
	list := res.Details.(DetectorList)
	if list.Total != 1 {
		t.Fatalf("total = %d, want 1", list.Total)
	}
	d := list.Detectors[0]
	if d.ID != "det-1" || d.Status != "ENABLED" {
		t.Errorf("detector = %+v", d)
	}
	if len(d.Features) != 1 || d.Features[0].Status != "ENABLED" {
		t.Errorf("features = %+v", d.Features)
	}
}

func TestExecute_InvalidPayload(t *testing.T) {
	res, err := newTestTask(&fakeAPI{}).Execute(context.Background(), json.RawMessage(`{`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Success {
		t.Fatal("expected success=false for invalid payload")
	}
}
