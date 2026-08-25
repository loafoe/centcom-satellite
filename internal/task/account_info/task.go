// Package account_info reports which AWS account this satellite's AWS
// credentials currently resolve to — the assumed-role target account when
// cross-account AssumeRole is configured, otherwise the base IRSA/local
// account. It has no Kubernetes dependency, so it works even when this
// satellite isn't running inside (or connected to) a Kubernetes cluster.
package account_info

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	awshelper "github.com/loafoe/centcom-satellite/internal/aws"
	"github.com/loafoe/centcom-satellite/internal/task"
	"github.com/loafoe/centcom-satellite/internal/task/cluster_info"
)

const TaskName = "account_info"

type api interface {
	GetCallerIdentity(ctx context.Context, in *sts.GetCallerIdentityInput, optFns ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error)
}

// Info is the task result payload.
type Info struct {
	AWSAccountID  string                    `json:"aws_account_id,omitempty"`
	AWSCallerArn  string                    `json:"aws_caller_arn,omitempty"`
	AssumeRoleARN string                    `json:"assume_role_arn,omitempty"`
	Region        string                    `json:"region,omitempty"`
	Capabilities  cluster_info.Capabilities `json:"capabilities"`
}

type Task struct {
	// assumeRoleARN is echoed into the result so callers can see whether
	// AssumeRole is configured, without needing a second round-trip.
	assumeRoleARN string
	// capabilities advertises which optional task groups are enabled on
	// this agent — the same config-derived flags cluster_info reports, but
	// account_info has no Kubernetes dependency, so this is the only
	// capabilities source available on a cluster-less (AWS-only
	// AssumeRole) satellite, where cluster_info isn't registered at all.
	capabilities cluster_info.Capabilities
	// clientFactory returns the STS client plus the AWS region it resolved
	// to. It goes through awshelper.LoadConfig, which already transparently
	// applies the shared cross-account AssumeRole credentials when
	// configured — this task never needs its own AssumeRole logic.
	clientFactory func(ctx context.Context) (api, string, error)
}

func New(assumeRoleARN string) *Task {
	return &Task{
		assumeRoleARN: assumeRoleARN,
		clientFactory: func(ctx context.Context) (api, string, error) {
			cfg, err := awshelper.LoadConfig(ctx, awshelper.Options{})
			if err != nil {
				return nil, "", err
			}
			return sts.NewFromConfig(cfg), cfg.Region, nil
		},
	}
}

func NewWithClientFactory(assumeRoleARN string, f func(ctx context.Context) (api, string, error)) *Task {
	return &Task{assumeRoleARN: assumeRoleARN, clientFactory: f}
}

// WithCapabilities sets the capabilities to advertise, mirroring
// cluster_info's WithCapabilities.
func (t *Task) WithCapabilities(caps cluster_info.Capabilities) *Task {
	t.capabilities = caps
	return t
}

func (t *Task) Name() string { return TaskName }

func (t *Task) Execute(ctx context.Context, _ json.RawMessage) (*task.Result, error) {
	client, region, err := t.clientFactory(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to build sts client: %w", err)
	}

	out, err := client.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return nil, fmt.Errorf("get caller identity: %w", err)
	}

	info := Info{
		AWSAccountID:  aws.ToString(out.Account),
		AWSCallerArn:  aws.ToString(out.Arn),
		AssumeRoleARN: t.assumeRoleARN,
		Region:        region,
		Capabilities:  t.capabilities,
	}

	return task.NewSuccessResultWithDetails(fmt.Sprintf("resolved AWS account %s", info.AWSAccountID), info), nil
}
