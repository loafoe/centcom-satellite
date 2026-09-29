package helm_application

import (
	"context"
	"encoding/json"

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

// Execute patches the argocd.argoproj.io/refresh annotation (value "hard" -
// the value ArgoCD's own convention treats as a hard-refresh trigger, not
// an arbitrary timestamp) onto the HelmApplication composite - the
// Composition's patch-and-transform step forwards every composite
// annotation onto the generated ArgoCD Application (confirmed by reading
// helmapp-composition.yaml's render-argocd-app step), so this reaches
// ArgoCD's own refresh mechanism without the satellite needing separate
// access to the argoproj.io Application object itself.
//
// Known limitation, not fully resolved (code review flagged this, not
// verified against a real ArgoCD instance yet): since the composite
// permanently retains this annotation once set (there is no cheap, race-
// free way for the satellite to remove it again - Crossplane's reconcile
// loop runs on its own schedule, not synchronously with this call), a
// second sync_application call is a no-op patch (same value, nothing
// changes) rather than a fresh trigger, and there is some risk of a
// standing "refresh" annotation being re-forwarded on every Crossplane
// reconcile. Needs live verification against real ArgoCD before this is
// used for anything beyond periodic/manual troubleshooting.
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

	patch := []byte(`{"metadata":{"annotations":{"argocd.argoproj.io/refresh":"hard"}}}`)
	updated, err := client.Patch(ctx, p.Name, apitypes.MergePatchType, patch, metav1.PatchOptions{})
	if err != nil {
		return task.NewErrorResult(err.Error()), nil
	}
	return task.NewSuccessResultWithDetails("sync requested", get_resource.ExtractSummary(updated, true)), nil
}
