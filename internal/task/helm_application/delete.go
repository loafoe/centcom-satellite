package helm_application

import (
	"context"
	"encoding/json"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"

	"github.com/loafoe/centcom-satellite/internal/task"
)

const DeleteTaskName = "helm_application_delete"

type DeleteTask struct{ dynamicClient dynamic.Interface }

func NewDelete(dynamicClient dynamic.Interface) *DeleteTask {
	return &DeleteTask{dynamicClient: dynamicClient}
}

func (t *DeleteTask) Name() string { return DeleteTaskName }

func (t *DeleteTask) Execute(ctx context.Context, payloadBytes json.RawMessage) (*task.Result, error) {
	var p struct{ APIVersion, Name, Namespace string }
	if err := json.Unmarshal(payloadBytes, &p); err != nil {
		return task.NewErrorResult("invalid payload: " + err.Error()), nil
	}
	if p.APIVersion == "" || p.Name == "" || p.Namespace == "" {
		return task.NewErrorResult("apiVersion, name, and namespace are required"), nil
	}
	if isProtectedApplicationName(p.Name) {
		// Hard safety rail, not a bug fix: "bootstrap" is the root composite
		// that bootstraps core cluster infrastructure on clusters following
		// this convention (confirmed live on dip-ce-k3s-eu) - deleting it
		// could cascade-destroy the cluster. This lives here, in the task
		// itself, rather than only in centcom's admin gate, so it can't be
		// bypassed by any caller including the unauthenticated call_task
		// path - the delete request never reaches the API server at all.
		return task.NewErrorResult("refusing to delete HelmApplication \"" + p.Name + "\": this name is protected and can never be deleted via a satellite"), nil
	}
	gv, err := schema.ParseGroupVersion(p.APIVersion)
	if err != nil {
		return task.NewErrorResult("invalid apiVersion: " + err.Error()), nil
	}
	client := t.dynamicClient.Resource(gv.WithResource(helmApplicationsResource)).Namespace(p.Namespace)

	if err := client.Delete(ctx, p.Name, metav1.DeleteOptions{}); err != nil {
		if apierrors.IsNotFound(err) {
			return task.NewSuccessResultWithDetails("already deleted", nil), nil
		}
		return task.NewErrorResult(err.Error()), nil
	}

	// A namespace-scoped composite with no finalizers deletes synchronously;
	// re-Get once to detect the "stuck behind a finalizer" case without an
	// unbounded wait loop.
	obj, err := client.Get(ctx, p.Name, metav1.GetOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			return task.NewSuccessResultWithDetails("deleted", nil), nil
		}
		return task.NewErrorResult(err.Error()), nil
	}
	// Every live composite legitimately carries Crossplane's own
	// "composite.apiextensions.crossplane.io" finalizer throughout a normal
	// in-progress delete - that alone is not stuck. Only the specific,
	// forbidden ArgoCD finalizer (the guardrail documented in
	// crossplane-compositions/kustomize/base/helmapp/README.md - it should
	// never be set on the composite itself) indicates a genuinely wedged
	// delete.
	for _, f := range obj.GetFinalizers() {
		if f == argoCDResourcesFinalizer {
			return task.NewErrorResult((&StuckDeletingError{Name: p.Name, Finalizers: obj.GetFinalizers()}).Error()), nil
		}
	}
	return task.NewSuccessResultWithDetails("delete accepted, terminating", nil), nil
}

const argoCDResourcesFinalizer = "resources-finalizer.argocd.argoproj.io"

// protectedApplicationNames can never be deleted via helm_application_delete,
// regardless of namespace, caller, or admin status - a hardcoded safety
// rail, not a permission that can be granted.
var protectedApplicationNames = map[string]bool{
	"bootstrap": true,
}

func isProtectedApplicationName(name string) bool {
	return protectedApplicationNames[name]
}
