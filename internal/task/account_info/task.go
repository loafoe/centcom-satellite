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
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	awshelper "github.com/loafoe/centcom-satellite/internal/aws"
	"github.com/loafoe/centcom-satellite/internal/task"
	"github.com/loafoe/centcom-satellite/internal/task/cluster_info"
)

const TaskName = "account_info"

// credsProbeTimeout bounds the credential-availability pre-check in
// Execute. A satellite with no AWS integration at all (no IRSA, no IMDS, no
// explicit keys - e.g. a homelab/on-prem cluster) would otherwise ride out
// the AWS SDK's full IMDS retry/timeout chain (~5s, confirmed live on the
// rpi homelab satellite) on every single poll before failing - this caps
// that at 2s, and more importantly lets Execute tell "no AWS here at all"
// apart from a real STS/API error. See Execute's use of credsAvailable.
const credsProbeTimeout = 2 * time.Second

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
	// credsAvailable reports whether AWS credentials can be resolved at
	// all, checked with a short bounded timeout before the real STS call
	// (see Execute and credsProbeTimeout). nil — the default for
	// NewWithClientFactory, used by every existing test — skips the check
	// entirely and always proceeds straight to clientFactory/the API call.
	credsAvailable func(ctx context.Context) error
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
		credsAvailable: func(ctx context.Context) error {
			cfg, err := awshelper.LoadConfig(ctx, awshelper.Options{})
			if err != nil {
				return err
			}
			probeCtx, cancel := context.WithTimeout(ctx, credsProbeTimeout)
			defer cancel()
			_, err = cfg.Credentials.Retrieve(probeCtx)
			return err
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
	if t.credsAvailable != nil {
		if err := t.credsAvailable(ctx); err != nil {
			// No AWS credentials resolvable at all - this satellite isn't
			// running against AWS (e.g. a homelab/on-prem cluster with no
			// IMDS/IRSA/explicit keys configured). Report it the same way
			// internal/server/handlers.go already reports a Kubernetes task
			// on an AWS-only satellite: ErrTaskNotFound -> a 404 "not
			// available", logged at Info level and counted as
			// not_available, not a 500 every poll for infrastructure that
			// was never there in the first place.
			return nil, fmt.Errorf("account_info not available on this satellite (no AWS credentials resolvable: %v): %w", err, task.ErrTaskNotFound)
		}
	}

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
