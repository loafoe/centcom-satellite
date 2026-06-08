package cluster_info

import (
	"context"
	"encoding/json"
	"os"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
)

// detectAWSAccountID tries Crossplane EnvironmentConfig first (fast, no external
// call), then falls back to STS GetCallerIdentity if credentials are available.
func (t *Task) detectAWSAccountID(ctx context.Context) string {
	if id := t.detectAccountFromCrossplane(ctx); id != "" {
		return id
	}
	return t.detectAccountFromSTS(ctx)
}

// detectAccountFromCrossplane reads the accountId from the hsp-addons or
// hsp-addons-compat EnvironmentConfig. Returns empty if neither exists.
func (t *Task) detectAccountFromCrossplane(ctx context.Context) string {
	cfg, err := rest.InClusterConfig()
	if err != nil {
		return ""
	}
	dyn, err := dynamic.NewForConfig(cfg)
	if err != nil {
		return ""
	}

	gvr := schema.GroupVersionResource{
		Group:    "apiextensions.crossplane.io",
		Version:  "v1beta1",
		Resource: "environmentconfigs",
	}

	for _, name := range []string{"hsp-addons", "hsp-addons-compat"} {
		obj, err := dyn.Resource(gvr).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			continue
		}
		data, ok := obj.Object["data"]
		if !ok {
			continue
		}
		dataBytes, err := json.Marshal(data)
		if err != nil {
			continue
		}
		var envData struct {
			AccountID string `json:"accountId"`
		}
		if err := json.Unmarshal(dataBytes, &envData); err != nil {
			continue
		}
		if envData.AccountID != "" {
			return envData.AccountID
		}
	}
	return ""
}

// detectAccountFromSTS uses STS GetCallerIdentity as fallback.
func (t *Task) detectAccountFromSTS(ctx context.Context) string {
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
	if _, err := os.Stat("/var/run/secrets/eks.amazonaws.com/serviceaccount/token"); err == nil {
		return true
	}
	return false
}
