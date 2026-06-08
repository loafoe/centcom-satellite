package cluster_info

import (
	"context"
	"os"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// detectAWSAccountID attempts to retrieve the AWS account ID via STS
// GetCallerIdentity. Returns empty string if not running on AWS or if
// the call fails (no permissions, no credentials, timeout, etc).
func (t *Task) detectAWSAccountID(ctx context.Context) string {
	// Quick check: skip entirely if no AWS credential indicators are present
	if !hasAWSCredentials() {
		return ""
	}

	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return ""
	}

	client := sts.NewFromConfig(cfg)
	output, err := client.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return ""
	}
	if output.Account == nil {
		return ""
	}
	return *output.Account
}

// hasAWSCredentials checks if AWS credential sources are available.
func hasAWSCredentials() bool {
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
	// EKS pod identity: token file exists at well-known path
	if _, err := os.Stat("/var/run/secrets/eks.amazonaws.com/serviceaccount/token"); err == nil {
		return true
	}
	return false
}
