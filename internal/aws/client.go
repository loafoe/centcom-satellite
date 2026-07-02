// Package aws provides shared AWS SDK v2 client configuration for tasks that
// retrieve data from AWS services (CloudWatch, CloudWatch Logs, Cost Explorer).
package aws

import (
	"context"
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
	// AssumeRoleARN, when non-empty, wraps the base credentials in an
	// STS AssumeRole provider for cross-account access.
	AssumeRoleARN string
}

// LoadConfig builds an aws.Config from the SDK default credential chain
// (IRSA / Pod Identity in EKS), applying the per-request Region and optional
// AssumeRole from opts.
func LoadConfig(ctx context.Context, opts Options) (aws.Config, error) {
	loadOpts := []func(*config.LoadOptions) error{}
	if opts.Region != "" {
		loadOpts = append(loadOpts, config.WithRegion(opts.Region))
	}

	cfg, err := config.LoadDefaultConfig(ctx, loadOpts...)
	if err != nil {
		return aws.Config{}, err
	}

	if opts.AssumeRoleARN != "" {
		stsClient := sts.NewFromConfig(cfg)
		provider := stscreds.NewAssumeRoleProvider(stsClient, opts.AssumeRoleARN)
		cfg.Credentials = aws.NewCredentialsCache(provider)
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
