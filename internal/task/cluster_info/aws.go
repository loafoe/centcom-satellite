package cluster_info

import (
	"context"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// detectAWSAccountID attempts to retrieve the AWS account ID via STS
// GetCallerIdentity. Returns empty string if not running on AWS or if
// the call fails (no permissions, no credentials, timeout, etc).
func (t *Task) detectAWSAccountID(ctx context.Context) string {
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
