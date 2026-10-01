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
	"fmt"

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

// ApplyPayload is the wire payload for helm_application_apply.
//
// CreateOnly, when true, refuses instead of updating if the object already
// exists - centcom's deploy_application sets this (a fresh deploy has no
// business silently replacing something with the same name), while
// update_application leaves it false and instead supplies ResourceVersion.
//
// ResourceVersion, when set, enforces optimistic concurrency against the
// caller's last-read value, AND requires the object to already exist (a
// caller who read a ResourceVersion has necessarily seen the object; if
// it's now missing, that's a real "someone deleted it" condition to
// surface, not ground to silently create a new one under the same name).
// Empty means create-or-blind-update, used by the free-form path when the
// caller never read an existing object.
type ApplyPayload struct {
	APIVersion      string            `json:"apiVersion"`
	Name            string            `json:"name"`
	Namespace       string            `json:"namespace"`
	Spec            map[string]any    `json:"spec"`
	Labels          map[string]string `json:"labels,omitempty"`
	ResourceVersion string            `json:"resourceVersion,omitempty"`
	CreateOnly      bool              `json:"createOnly,omitempty"`
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
		return task.NewErrorResult(getErr.Error()), nil
	}

	if existing == nil {
		if p.ResourceVersion != "" {
			// The caller read a ResourceVersion, so they necessarily saw
			// the object before - if it's gone now, that's a real
			// "someone deleted it out from under you" condition to
			// surface, not grounds to silently create a new one.
			return task.NewErrorResult("HelmApplication " + p.Name + " not found (it existed when you read its resourceVersion, but has since been deleted)"), nil
		}
		if err := validateHelmApplicationSpec(p.Spec); err != nil {
			return task.NewErrorResult("refusing to write an invalid spec: " + err.Error()), nil
		}
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
			return task.NewErrorResult(err.Error()), nil
		}
		return task.NewSuccessResultWithDetails("created", get_resource.ExtractSummary(created, true)), nil
	}

	if p.CreateOnly {
		return task.NewErrorResult("HelmApplication " + p.Name + " already exists (use update_application to modify it)"), nil
	}
	if p.ResourceVersion != "" && existing.GetResourceVersion() != p.ResourceVersion {
		return task.NewErrorResult((&ConflictError{Name: p.Name}).Error()), nil
	}

	// Deep-merge the caller-supplied spec into the existing spec, rather
	// than replacing it wholesale at either the top level or within a
	// nested object like source - centcom's spec builder can only ever
	// express a subset of source's fields at once (e.g. repoURL +
	// targetRevision + helm.valuesObject, never chart), so a shallow,
	// top-level-only merge silently drops sibling fields an update never
	// meant to touch (e.g. dropping source.chart, or destination/
	// syncPolicy/project/spec.crossplane.* on a top-level replace).
	existingSpec, _, _ := unstructured.NestedMap(existing.Object, "spec")
	if existingSpec == nil {
		existingSpec = map[string]any{}
	}
	mergedSpec := deepMergeMap(existingSpec, p.Spec)

	if err := validateHelmApplicationSpec(mergedSpec); err != nil {
		return task.NewErrorResult("refusing to write an invalid spec: " + err.Error()), nil
	}

	existing.Object["spec"] = mergedSpec
	if p.Labels != nil {
		existing.SetLabels(p.Labels)
	}
	updated, err := client.Update(ctx, existing, metav1.UpdateOptions{DryRun: dryRun})
	if err != nil {
		if apierrors.IsConflict(err) {
			return task.NewErrorResult((&ConflictError{Name: p.Name}).Error()), nil
		}
		return task.NewErrorResult(err.Error()), nil
	}
	return task.NewSuccessResultWithDetails("updated", get_resource.ExtractSummary(updated, true)), nil
}

// deepMergeMap merges overlay into base, recursing into nested
// map[string]any values on both sides so a partial update only ever
// touches the keys it actually names - a sibling key present in base but
// absent from overlay is left untouched at every depth, not just the top
// level. Non-map values (scalars, slices) in overlay replace base's value
// at that key outright; base is not mutated.
func deepMergeMap(base, overlay map[string]any) map[string]any {
	merged := make(map[string]any, len(base)+len(overlay))
	for k, v := range base {
		merged[k] = v
	}
	for k, overlayVal := range overlay {
		baseVal, exists := merged[k]
		if !exists {
			merged[k] = overlayVal
			continue
		}
		baseMap, baseIsMap := baseVal.(map[string]any)
		overlayMap, overlayIsMap := overlayVal.(map[string]any)
		if baseIsMap && overlayIsMap {
			merged[k] = deepMergeMap(baseMap, overlayMap)
			continue
		}
		merged[k] = overlayVal
	}
	return merged
}

// validateHelmApplicationSpec enforces the invariant ArgoCD itself requires
// of source.repoURL and either source.path or source.chart
// (InvalidSpecError otherwise): a spec failing this can be admitted by the
// HelmApplication XRD (source is x-kubernetes-preserve-unknown-fields), but
// leaves the composed Application inert. Caught here, before the write,
// instead of discovered later as a live resource stuck in that state.
func validateHelmApplicationSpec(spec map[string]any) error {
	source, ok := spec["source"].(map[string]any)
	if !ok {
		return nil
	}
	repoURL, _ := source["repoURL"].(string)
	if repoURL == "" {
		return nil
	}
	chart, _ := source["chart"].(string)
	path, _ := source["path"].(string)
	if chart == "" && path == "" {
		return &InvalidSpecError{Reason: "spec.source.repoURL is set but neither spec.source.chart nor spec.source.path is present"}
	}
	helm, _ := source["helm"].(map[string]any)
	if helm != nil {
		if valuesObject, ok := helm["valuesObject"].(map[string]any); ok {
			if badPath := findItemWrappedArray(valuesObject, "spec.source.helm.valuesObject"); badPath != "" {
				return &InvalidSpecError{Reason: fmt.Sprintf(
					"%s is a {\"item\": [...]} -wrapped map, not a plain JSON array - this is never a legitimate "+
						"Helm value and is the signature of a caller mis-encoding a list (the same corruption class "+
						"that left grafana-kustomize's valuesObject fully stringified and its Application unable to "+
						"render)", badPath)}
			}
		}
	}
	return nil
}

// findItemWrappedArray recursively looks for the specific shape {"item":
// [...]} - a map whose only key is literally "item" and whose value is a
// list. This is a narrow, high-confidence anti-pattern check, not a general
// type validator: unlike a numeric- or boolean-looking string (which many
// legitimate Helm values genuinely are - a port, a version, a zip code),
// this exact wrapper shape has no legitimate Helm-values use and has only
// ever been observed as a caller's list-encoding bug. Returns the dotted
// path to the first occurrence found, or "" if none.
func findItemWrappedArray(m map[string]any, path string) string {
	if len(m) == 1 {
		if item, ok := m["item"]; ok {
			if _, isSlice := item.([]any); isSlice {
				return path
			}
		}
	}
	for k, v := range m {
		if nested, ok := v.(map[string]any); ok {
			if found := findItemWrappedArray(nested, path+"."+k); found != "" {
				return found
			}
		}
	}
	return ""
}
