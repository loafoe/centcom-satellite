// Package aws provides shared AWS SDK v2 client configuration for tasks that
// retrieve data from AWS services (CloudWatch, CloudWatch Logs, Cost
// Explorer, GuardDuty, Security Hub), including optional cross-account
// access via STS AssumeRole.
package aws

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// Options controls how the AWS config is built for a request.
type Options struct {
	// Region overrides the default region when non-empty.
	Region string
}

// AssumeRoleOptions configures process-wide cross-account credentials.
type AssumeRoleOptions struct {
	// ARN is the target IAM role in the remote AWS account. Empty disables
	// the feature entirely (Init becomes a no-op).
	ARN string
	// ExternalID is passed to AssumeRole when non-empty.
	ExternalID string
	// SessionName is the STS RoleSessionName. Defaults to
	// "centcom-satellite" when empty.
	SessionName string
}

// assumeRoleCredentials holds the process-wide cached cross-account
// credentials provider, set once by Init before the HTTP server starts
// accepting requests. Left nil (the default) when AssumeRole isn't
// configured, in which case LoadConfig behaves exactly as it did before this
// feature existed.
var assumeRoleCredentials aws.CredentialsProvider

type stsAPI interface {
	GetCallerIdentity(ctx context.Context, in *sts.GetCallerIdentityInput, optFns ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error)
}

// Init sets up process-wide cross-account AssumeRole credentials when
// opts.ARN is set. It must be called once at startup, before any LoadConfig
// call and before the HTTP server starts accepting requests. It verifies the
// credentials with a single STS GetCallerIdentity call so misconfiguration
// (bad trust policy, wrong ExternalId) fails startup instead of surfacing
// later on the first task request.
func Init(ctx context.Context, opts AssumeRoleOptions) error {
	if opts.ARN == "" {
		return nil
	}

	baseCfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return fmt.Errorf("load base AWS config: %w", err)
	}

	sessionName := opts.SessionName
	if sessionName == "" {
		sessionName = "centcom-satellite"
	}

	provider := stscreds.NewAssumeRoleProvider(sts.NewFromConfig(baseCfg), opts.ARN, func(o *stscreds.AssumeRoleOptions) {
		o.RoleSessionName = sessionName
		if opts.ExternalID != "" {
			o.ExternalID = aws.String(opts.ExternalID)
		}
	})
	cached := aws.NewCredentialsCache(provider)

	verifyCfg := baseCfg.Copy()
	verifyCfg.Credentials = cached
	accountID, err := verifyCallerIdentity(ctx, sts.NewFromConfig(verifyCfg))
	if err != nil {
		return fmt.Errorf("verify assumed-role credentials for %s: %w", opts.ARN, err)
	}

	assumeRoleCredentials = cached
	slog.Info("cross-account AssumeRole configured", "role_arn", opts.ARN, "account_id", accountID)
	return nil
}

// verifyCallerIdentity calls STS GetCallerIdentity and returns the resolved
// account ID, extracted so Init's fail-fast check is unit-testable without a
// real STS call.
func verifyCallerIdentity(ctx context.Context, api stsAPI) (string, error) {
	out, err := api.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return "", err
	}
	return aws.ToString(out.Account), nil
}

// LoadConfig builds an aws.Config from the SDK default credential chain
// (IRSA / Pod Identity in EKS), applying the per-request Region from opts.
// When Init has configured process-wide cross-account credentials, those
// override the default chain's credentials — every AWS task calling
// LoadConfig then transparently operates against the remote account.
func LoadConfig(ctx context.Context, opts Options) (aws.Config, error) {
	loadOpts := []func(*config.LoadOptions) error{}
	if opts.Region != "" {
		loadOpts = append(loadOpts, config.WithRegion(opts.Region))
	}

	cfg, err := config.LoadDefaultConfig(ctx, loadOpts...)
	if err != nil {
		return aws.Config{}, err
	}

	if assumeRoleCredentials != nil {
		cfg.Credentials = assumeRoleCredentials
	}

	return cfg, nil
}

// HasCredentials reports whether AWS credentials appear to be available,
// matching the detection used elsewhere in centcom-satellite.
func HasCredentials() bool {
	indicators := []string{
		"AWS_ACCESS_KEY_ID",
		"AWS_ROLE_ARN",
		"AWS_WEB_IDENTITY_TOKEN_FILE",
		"AWS_CONTAINER_CREDENTIALS_FULL_URI",
		"AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
	}
	for _, env := range indicators {
		if os.Getenv(env) != "" {
			return true
		}
	}
	if _, err := os.Stat("/var/run/secrets/eks.amazonaws.com/serviceaccount/token"); err == nil {
		return true
	}
	return false
}
