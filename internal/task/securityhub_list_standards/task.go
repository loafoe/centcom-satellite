// Package securityhub_list_standards lists the Security Hub subscription
// status plus the catalog of available compliance standards (CIS/PCI-DSS/FSBP)
// and each one's enablement status, powering the dashboard's hub header.
package securityhub_list_standards

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/securityhub"

	awshelper "github.com/loafoe/centcom-satellite/internal/aws"
	"github.com/loafoe/centcom-satellite/internal/task"
	shc "github.com/loafoe/centcom-satellite/internal/task/securityhub_common"
)

const TaskName = "securityhub_list_standards"

type api interface {
	DescribeHub(context.Context, *securityhub.DescribeHubInput, ...func(*securityhub.Options)) (*securityhub.DescribeHubOutput, error)
	DescribeStandards(context.Context, *securityhub.DescribeStandardsInput, ...func(*securityhub.Options)) (*securityhub.DescribeStandardsOutput, error)
	GetEnabledStandards(context.Context, *securityhub.GetEnabledStandardsInput, ...func(*securityhub.Options)) (*securityhub.GetEnabledStandardsOutput, error)
}

// Payload for securityhub_list_standards.
type Payload struct {
	Region string `json:"region,omitempty"`
}

// StandardsList is the task result payload.
type StandardsList struct {
	Hub       shc.HubStatus  `json:"hub"`
	Total     int            `json:"total"`
	Standards []shc.Standard `json:"standards"`
}

type Task struct {
	clientFactory func(ctx context.Context, region string) (api, error)
}

func New() *Task {
	return &Task{clientFactory: func(ctx context.Context, region string) (api, error) {
		cfg, err := awshelper.LoadConfig(ctx, awshelper.Options{Region: region})
		if err != nil {
			return nil, err
		}
		return securityhub.NewFromConfig(cfg), nil
	}}
}

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
		return nil, fmt.Errorf("failed to build securityhub client: %w", err)
	}

	hubOut, err := client.DescribeHub(ctx, &securityhub.DescribeHubInput{})
	if err != nil {
		return nil, fmt.Errorf("describe hub: %w", err)
	}

	statusByArn := map[string]string{}
	subPaginator := securityhub.NewGetEnabledStandardsPaginator(client, &securityhub.GetEnabledStandardsInput{})
	for subPaginator.HasMorePages() {
		page, err := subPaginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("get enabled standards: %w", err)
		}
		for _, sub := range page.StandardsSubscriptions {
			statusByArn[aws.ToString(sub.StandardsArn)] = string(sub.StandardsStatus)
		}
	}

	result := StandardsList{
		Hub: shc.HubStatus{
			HubArn:                  aws.ToString(hubOut.HubArn),
			SubscribedAt:            aws.ToString(hubOut.SubscribedAt),
			AutoEnableControls:      aws.ToBool(hubOut.AutoEnableControls),
			ControlFindingGenerator: string(hubOut.ControlFindingGenerator),
		},
		Standards: []shc.Standard{},
	}

	stdPaginator := securityhub.NewDescribeStandardsPaginator(client, &securityhub.DescribeStandardsInput{})
	for stdPaginator.HasMorePages() {
		page, err := stdPaginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("describe standards: %w", err)
		}
		for _, s := range page.Standards {
			arn := aws.ToString(s.StandardsArn)
			result.Standards = append(result.Standards, shc.Standard{
				StandardsArn:     arn,
				Name:             aws.ToString(s.Name),
				Description:      aws.ToString(s.Description),
				EnabledByDefault: aws.ToBool(s.EnabledByDefault),
				Status:           statusByArn[arn],
			})
		}
	}
	result.Total = len(result.Standards)

	return task.NewSuccessResultWithDetails(fmt.Sprintf("found %d standards", result.Total), result), nil
}
