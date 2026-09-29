// Package helm_application provides create/update/delete/sync tasks for
// the dip.io HelmApplication Crossplane composite - the write path behind
// centcom's Applications view. Unlike get_resource/list_resources, these
// tasks build their schema.GroupVersionResource directly from the caller-
// supplied apiVersion rather than going through the satellite's shared,
// startup-time-cached RESTMapper: HelmApplication's resource name and
// namespaced-ness are fixed by its own XRD (scope: Namespaced), so no
// generic REST discovery is needed for this specific, known resource.
package helm_application

import (
	"context"
	"encoding/json"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"

	"github.com/loafoe/centcom-satellite/internal/task"
	"github.com/loafoe/centcom-satellite/internal/task/get_resource"
)

const ApplyTaskName = "helm_application_apply"

const helmApplicationsResource = "helmapplications"

// ApplyPayload is the wire payload for helm_application_apply. Resource
// Version is optional: empty means "create, or blindly overwrite spec on
// update" (used by the free-form deploy path when the caller never read an
// existing object); non-empty enforces optimistic concurrency against the
// caller's last-read ResourceVersion.
type ApplyPayload struct {
	APIVersion      string            `json:"apiVersion"`
	Name            string            `json:"name"`
	Namespace       string            `json:"namespace"`
	Spec            map[string]any    `json:"spec"`
	Labels          map[string]string `json:"labels,omitempty"`
	ResourceVersion string            `json:"resourceVersion,omitempty"`
	DryRun          bool              `json:"dryRun,omitempty"`
}

// dryRunOptions returns the metav1.DryRun value for a Create/Update call
// matching the caller's DryRun flag - nil (not sent as an all-things-dry-
// run request) when dryRun is false.
func dryRunOptions(dryRun bool) []string {
	if !dryRun {
		return nil
	}
	return []string{metav1.DryRunAll}
}

type ApplyTask struct{ dynamicClient dynamic.Interface }

func NewApply(dynamicClient dynamic.Interface) *ApplyTask {
	return &ApplyTask{dynamicClient: dynamicClient}
}

func (t *ApplyTask) Name() string { return ApplyTaskName }

func (t *ApplyTask) Execute(ctx context.Context, payloadBytes json.RawMessage) (*task.Result, error) {
	var p ApplyPayload
	if err := json.Unmarshal(payloadBytes, &p); err != nil {
		return task.NewErrorResult("invalid payload: " + err.Error()), nil
	}
	if p.APIVersion == "" || p.Name == "" || p.Namespace == "" || p.Spec == nil {
		return task.NewErrorResult("apiVersion, name, namespace, and spec are required"), nil
	}
	gv, err := schema.ParseGroupVersion(p.APIVersion)
	if err != nil {
		return task.NewErrorResult("invalid apiVersion: " + err.Error()), nil
	}
	client := t.dynamicClient.Resource(gv.WithResource(helmApplicationsResource)).Namespace(p.Namespace)
	dryRun := dryRunOptions(p.DryRun)

	existing, getErr := client.Get(ctx, p.Name, metav1.GetOptions{})
	if getErr != nil && !apierrors.IsNotFound(getErr) {
		return nil, getErr
	}

	if existing == nil {
		obj := &unstructured.Unstructured{Object: map[string]any{
			"apiVersion": p.APIVersion,
			"kind":       "HelmApplication",
			"metadata": map[string]any{
				"name":      p.Name,
				"namespace": p.Namespace,
			},
			"spec": p.Spec,
		}}
		if p.Labels != nil {
			obj.SetLabels(p.Labels)
		}
		created, err := client.Create(ctx, obj, metav1.CreateOptions{DryRun: dryRun})
		if err != nil {
			return nil, err
		}
		return task.NewSuccessResultWithDetails("created", get_resource.ExtractSummary(created, true)), nil
	}

	if p.ResourceVersion != "" && existing.GetResourceVersion() != p.ResourceVersion {
		return nil, &ConflictError{Name: p.Name}
	}
	existing.Object["spec"] = p.Spec
	if p.Labels != nil {
		existing.SetLabels(p.Labels)
	}
	updated, err := client.Update(ctx, existing, metav1.UpdateOptions{DryRun: dryRun})
	if err != nil {
		if apierrors.IsConflict(err) {
			return nil, &ConflictError{Name: p.Name}
		}
		return nil, err
	}
	return task.NewSuccessResultWithDetails("updated", get_resource.ExtractSummary(updated, true)), nil
}
