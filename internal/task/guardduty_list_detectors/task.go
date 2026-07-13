// Package guardduty_list_detectors lists GuardDuty detectors in a region and
// returns their status/health, powering the dashboard's detector header.
package guardduty_list_detectors

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/guardduty"

	awshelper "github.com/loafoe/centcom-satellite/internal/aws"
	"github.com/loafoe/centcom-satellite/internal/task"
	gdc "github.com/loafoe/centcom-satellite/internal/task/guardduty_common"
)

const TaskName = "guardduty_list_detectors"

// api is the narrow slice of the GuardDuty client used here.
type api interface {
	ListDetectors(context.Context, *guardduty.ListDetectorsInput, ...func(*guardduty.Options)) (*guardduty.ListDetectorsOutput, error)
	GetDetector(context.Context, *guardduty.GetDetectorInput, ...func(*guardduty.Options)) (*guardduty.GetDetectorOutput, error)
}

// Payload for guardduty_list_detectors.
type Payload struct {
	Region string `json:"region,omitempty"`
}

// DetectorList is the task result payload.
type DetectorList struct {
	Total     int            `json:"total"`
	Detectors []gdc.Detector `json:"detectors"`
}

// Task lists GuardDuty detectors.
type Task struct {
	clientFactory func(ctx context.Context, region string) (api, error)
}

// New builds a production task using the shared AWS config helper.
func New() *Task {
	return &Task{clientFactory: func(ctx context.Context, region string) (api, error) {
		cfg, err := awshelper.LoadConfig(ctx, awshelper.Options{Region: region})
		if err != nil {
			return nil, err
		}
		return guardduty.NewFromConfig(cfg), nil
	}}
}

// NewWithClientFactory builds a task with an injected client factory (tests).
func NewWithClientFactory(f func(ctx context.Context, region string) (api, error)) *Task {
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

	client, err := t.clientFactory(ctx, payload.Region)
	if err != nil {
		return nil, fmt.Errorf("failed to build guardduty client: %w", err)
	}

	result := DetectorList{Detectors: []gdc.Detector{}}
	paginator := guardduty.NewListDetectorsPaginator(client, &guardduty.ListDetectorsInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("list detectors: %w", err)
		}
		for _, id := range page.DetectorIds {
			det, err := client.GetDetector(ctx, &guardduty.GetDetectorInput{DetectorId: aws.String(id)})
			if err != nil {
				return nil, fmt.Errorf("get detector %s: %w", id, err)
			}
			result.Detectors = append(result.Detectors, normalizeDetector(id, det))
		}
	}
	result.Total = len(result.Detectors)

	return task.NewSuccessResultWithDetails(fmt.Sprintf("found %d detectors", result.Total), result), nil
}

func normalizeDetector(id string, d *guardduty.GetDetectorOutput) gdc.Detector {
	det := gdc.Detector{
		ID:                         id,
		Status:                     string(d.Status),
		ServiceRole:                aws.ToString(d.ServiceRole),
		FindingPublishingFrequency: string(d.FindingPublishingFrequency),
		CreatedAt:                  aws.ToString(d.CreatedAt),
		UpdatedAt:                  aws.ToString(d.UpdatedAt),
	}
	for _, f := range d.Features {
		det.Features = append(det.Features, gdc.DetectorFeature{
			Name:   string(f.Name),
			Status: string(f.Status),
		})
	}
	return det
}
