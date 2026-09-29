package helm_application

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	apitypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic"

	"github.com/loafoe/centcom-satellite/internal/task"
	"github.com/loafoe/centcom-satellite/internal/task/get_resource"
)

const SyncTaskName = "helm_application_sync"

type SyncTask struct{ dynamicClient dynamic.Interface }

func NewSync(dynamicClient dynamic.Interface) *SyncTask {
	return &SyncTask{dynamicClient: dynamicClient}
}

func (t *SyncTask) Name() string { return SyncTaskName }

// Execute patches the argocd.argoproj.io/refresh annotation onto the
// HelmApplication composite - the Composition's patch-and-transform step
// forwards every composite annotation onto the generated ArgoCD
// Application (confirmed by reading helmapp-composition.yaml's
// render-argocd-app step), so this reaches ArgoCD's own hard-refresh
// mechanism without the satellite needing separate access to the
// argoproj.io Application object itself.
func (t *SyncTask) Execute(ctx context.Context, payloadBytes json.RawMessage) (*task.Result, error) {
	var p struct{ APIVersion, Name, Namespace string }
	if err := json.Unmarshal(payloadBytes, &p); err != nil {
		return task.NewErrorResult("invalid payload: " + err.Error()), nil
	}
	if p.APIVersion == "" || p.Name == "" || p.Namespace == "" {
		return task.NewErrorResult("apiVersion, name, and namespace are required"), nil
	}
	gv, err := schema.ParseGroupVersion(p.APIVersion)
	if err != nil {
		return task.NewErrorResult("invalid apiVersion: " + err.Error()), nil
	}
	client := t.dynamicClient.Resource(gv.WithResource(helmApplicationsResource)).Namespace(p.Namespace)

	patch := []byte(fmt.Sprintf(`{"metadata":{"annotations":{"argocd.argoproj.io/refresh":%q}}}`, time.Now().UTC().Format(time.RFC3339Nano)))
	updated, err := client.Patch(ctx, p.Name, apitypes.MergePatchType, patch, metav1.PatchOptions{})
	if err != nil {
		return nil, err
	}
	return task.NewSuccessResultWithDetails("sync requested", get_resource.ExtractSummary(updated, true)), nil
}
