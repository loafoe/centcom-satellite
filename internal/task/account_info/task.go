// Package account_info reports which AWS account this satellite's AWS
// credentials currently resolve to — the assumed-role target account when
// cross-account AssumeRole is configured, otherwise the base IRSA/local
// account. It has no Kubernetes dependency, so it works even when this
// satellite isn't running inside (or connected to) a Kubernetes cluster.
//
// This task is always registered, even on a satellite with no AWS
// credentials at all (e.g. a homelab/on-prem cluster) — see NewUnavailable.
// Before v0.112.0 it was simply never registered in that case, so a call
// 404'd ("task not registered"); centcom's own account_info caller treated
// that 404 (or, on an even older satellite, a straight 500 from a doomed
// live STS call) as the "not AWS" signal. Both of those are still handled
// as a fallback, but a definitive HTTP 200 + aws_available:false answer is
// now the primary, explicit signal.
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
	// AWSAvailable is the explicit "is this satellite AWS-bound at all"
	// signal, added in v0.112.0. It is a *bool, and the field is omitted
	// entirely (via omitempty on a nil pointer) whenever AWS credentials
	// ARE available, so a response from that path is byte-for-byte what an
	// older centcom expects — every pre-existing field populated exactly as
	// before, no new field to notice. It is only ever set, to false, by
	// NewUnavailable's Execute — there is no case where this task reports
	// AWSAvailable=true explicitly, success with no error already means
	// that.
	AWSAvailable *bool `json:"aws_available,omitempty"`
	// Reason is a short, human-readable explanation, set only alongside
	// AWSAvailable=false.
	Reason string `json:"reason,omitempty"`
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
	// configured — this task never needs its own AssumeRole logic. Left nil
	// for an unavailable Task (see NewUnavailable) — Execute never calls it
	// in that case, so no AWS SDK/IMDS round trip ever happens for a
	// satellite that's already known to have no AWS credentials.
	clientFactory func(ctx context.Context) (api, string, error)
	// unavailable, when true, makes Execute short-circuit to a successful
	// AWSAvailable=false result with no AWS API call at all. Set only by
	// NewUnavailable.
	unavailable bool
	// unavailableReason is echoed as Info.Reason when unavailable is true.
	unavailableReason string
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

// NewUnavailable returns a Task that always succeeds with
// Info.AWSAvailable=false and makes no AWS API call at all — for a
// satellite with no AWS credentials (see cmd/centcom-satellite/main.go's
// awsCredentialsAvailable gate). Registering this instead of simply not
// registering account_info (the pre-v0.112.0 behavior) means a caller
// always gets a definitive HTTP 200 answer, never a 404/"task not
// registered" or, on an even older code path, a 500 from a doomed live STS
// call.
func NewUnavailable(reason string) *Task {
	return &Task{unavailable: true, unavailableReason: reason}
}

// WithCapabilities sets the capabilities to advertise, mirroring
// cluster_info's WithCapabilities.
func (t *Task) WithCapabilities(caps cluster_info.Capabilities) *Task {
	t.capabilities = caps
	return t
}

func (t *Task) Name() string { return TaskName }

func (t *Task) Execute(ctx context.Context, _ json.RawMessage) (*task.Result, error) {
	if t.unavailable {
		notAvailable := false
		info := Info{
			Capabilities: t.capabilities,
			AWSAvailable: &notAvailable,
			Reason:       t.unavailableReason,
		}
		return task.NewSuccessResultWithDetails("this satellite has no AWS integration", info), nil
	}

	client, region, err := t.clientFactory(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to build sts client: %w", err)
	}

	out, err := client.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return awshelper.WrapError("get caller identity", err)
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
