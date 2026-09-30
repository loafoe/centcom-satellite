package helm_application

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	k8stesting "k8s.io/client-go/testing"
)

var gvr = schema.GroupVersionResource{Group: "dip.io", Version: "v1", Resource: "helmapplications"}

// newFakeClient wires a fake dynamic client that knows the HelmApplication
// List kind (required for the fake tracker's List/Watch support), seeded
// with any given objects.
func newFakeClient(objects ...runtime.Object) *dynamicfake.FakeDynamicClient {
	scheme := runtime.NewScheme()
	return dynamicfake.NewSimpleDynamicClientWithCustomListKinds(
		scheme,
		map[schema.GroupVersionResource]string{gvr: "HelmApplicationList"},
		objects...,
	)
}

func existingHelmApp(name, namespace, resourceVersion string) *unstructured.Unstructured {
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "dip.io/v1",
		"kind":       "HelmApplication",
		"metadata": map[string]any{
			"name":            name,
			"namespace":       namespace,
			"resourceVersion": resourceVersion,
		},
		"spec": map[string]any{
			"source": map[string]any{"repoURL": "oci://old", "targetRevision": "0.9.0", "chart": "test-chart"},
		},
	}}
}

func TestApplyTask_CreatesNewResource(t *testing.T) {
	dc := newFakeClient()
	task := NewApply(dc)

	payload, err := json.Marshal(ApplyPayload{
		APIVersion: "dip.io/v1", Name: "my-app", Namespace: "argocd",
		Spec: map[string]any{"source": map[string]any{"repoURL": "oci://x", "targetRevision": "1.0.0", "chart": "x"}},
	})
	require.NoError(t, err)

	result, err := task.Execute(context.Background(), payload)
	require.NoError(t, err)
	require.True(t, result.Success)

	obj, err := dc.Resource(gvr).Namespace("argocd").Get(context.Background(), "my-app", metav1.GetOptions{})
	require.NoError(t, err)
	spec, _, _ := unstructured.NestedMap(obj.Object, "spec")
	assert.NotNil(t, spec["source"])
}

func TestApplyTask_UpdatesExistingResource(t *testing.T) {
	dc := newFakeClient(existingHelmApp("my-app", "argocd", "rv-1"))
	task := NewApply(dc)

	payload, err := json.Marshal(ApplyPayload{
		APIVersion: "dip.io/v1", Name: "my-app", Namespace: "argocd",
		Spec:            map[string]any{"source": map[string]any{"repoURL": "oci://new", "targetRevision": "2.0.0"}},
		ResourceVersion: "rv-1",
	})
	require.NoError(t, err)

	result, err := task.Execute(context.Background(), payload)
	require.NoError(t, err)
	require.True(t, result.Success)

	obj, err := dc.Resource(gvr).Namespace("argocd").Get(context.Background(), "my-app", metav1.GetOptions{})
	require.NoError(t, err)
	repoURL, _, _ := unstructured.NestedString(obj.Object, "spec", "source", "repoURL")
	assert.Equal(t, "oci://new", repoURL)
}

func TestApplyTask_UpdateWithStaleResourceVersionConflicts(t *testing.T) {
	dc := newFakeClient(existingHelmApp("my-app", "argocd", "rv-1"))
	task := NewApply(dc)

	payload, err := json.Marshal(ApplyPayload{
		APIVersion: "dip.io/v1", Name: "my-app", Namespace: "argocd",
		Spec:            map[string]any{"source": map[string]any{"repoURL": "oci://new", "targetRevision": "2.0.0"}},
		ResourceVersion: "rv-0-stale",
	})
	require.NoError(t, err)

	result, err := task.Execute(context.Background(), payload)
	require.NoError(t, err, "the conflict must be encoded in the Result, not returned as a Go error - a raw error is turned into a generic 500 by the satellite's HTTP handler, losing this message entirely")
	require.False(t, result.Success)
	assert.Contains(t, result.Error, "modified since")
}

// TestApplyTask_DryRunOptionIsBuiltCorrectly unit-tests dryRunOptions
// directly, rather than asserting on the fake dynamic client's behavior:
// k8s.io/client-go/dynamic/fake's CreateActionImpl/UpdateActionImpl carry
// no DryRun field at all in this client-go version (confirmed by reading
// k8s.io/client-go/testing/actions.go) - the fake tracker always persists
// regardless of the DryRun option, so it cannot verify this property. The
// real guarantee (a real apiserver actually honors DryRun) is proven live
// in Task 2.6's e2e verification against the real dip-ce-k3s-eu cluster,
// not here.
func TestApplyTask_DryRunOptionIsBuiltCorrectly(t *testing.T) {
	assert.Equal(t, []string{metav1.DryRunAll}, dryRunOptions(true))
	assert.Nil(t, dryRunOptions(false))
}

func TestApplyTask_DryRunSucceedsWithoutError(t *testing.T) {
	// Verifies the dry-run code path itself doesn't error/panic - the
	// "does the fake actually skip persisting" property is not
	// verifiable with this fake (see TestApplyTask_DryRunOptionIsBuiltCorrectly).
	dc := newFakeClient()
	task := NewApply(dc)

	payload, err := json.Marshal(ApplyPayload{
		APIVersion: "dip.io/v1", Name: "my-app", Namespace: "argocd",
		Spec:   map[string]any{"source": map[string]any{"repoURL": "oci://x", "targetRevision": "1.0.0", "chart": "x"}},
		DryRun: true,
	})
	require.NoError(t, err)

	result, err := task.Execute(context.Background(), payload)
	require.NoError(t, err)
	require.True(t, result.Success)
}

func TestApplyTask_MissingRequiredFields(t *testing.T) {
	dc := newFakeClient()
	task := NewApply(dc)

	payload, err := json.Marshal(ApplyPayload{APIVersion: "dip.io/v1"})
	require.NoError(t, err)

	result, err := task.Execute(context.Background(), payload)
	require.NoError(t, err)
	assert.False(t, result.Success)
	assert.Contains(t, result.Error, "required")
}

// TestApplyTask_CreateOnlyRefusesExistingObject is the regression test for
// a real bug found in code review: deploy_application (which never
// supplies a ResourceVersion, and previously had no way to say "this must
// be new") could silently replace ANY existing HelmApplication's spec -
// including live infrastructure like dex-issuer - if the caller happened
// to reuse an existing name. CreateOnly makes that explicit and refuses
// instead of falling through to Update.
func TestApplyTask_CreateOnlyRefusesExistingObject(t *testing.T) {
	dc := newFakeClient(existingHelmApp("dex-issuer", "argocd", "rv-1"))
	task := NewApply(dc)

	payload, err := json.Marshal(ApplyPayload{
		APIVersion: "dip.io/v1", Name: "dex-issuer", Namespace: "argocd", CreateOnly: true,
		Spec: map[string]any{"source": map[string]any{"repoURL": "oci://langfuse", "targetRevision": "1.0.0"}},
	})
	require.NoError(t, err)

	result, err := task.Execute(context.Background(), payload)
	require.NoError(t, err)
	require.False(t, result.Success, "must refuse rather than silently overwrite an existing object")
	assert.Contains(t, result.Error, "already exists")

	obj, getErr := dc.Resource(gvr).Namespace("argocd").Get(context.Background(), "dex-issuer", metav1.GetOptions{})
	require.NoError(t, getErr)
	repoURL, _, _ := unstructured.NestedString(obj.Object, "spec", "source", "repoURL")
	assert.Equal(t, "oci://old", repoURL, "the existing object must be untouched")
}

// TestApplyTask_UpdatePreservesFieldsNotInCallerSpec is the regression test
// for a real bug found in code review: update replaced the ENTIRE spec
// wholesale with only the caller's source/values, silently dropping fields
// centcom's own spec builder can't even express - destination, syncPolicy,
// project, spec.crossplane.* - which would retarget or break a live
// composite like dex-issuer (e.g. dropping destination.namespace would
// retarget it into the composite's own namespace, where default syncPolicy
// has prune:true).
func TestApplyTask_UpdatePreservesFieldsNotInCallerSpec(t *testing.T) {
	obj := existingHelmApp("dex-issuer", "argocd", "rv-1")
	obj.Object["spec"] = map[string]any{
		"source":      map[string]any{"repoURL": "oci://old", "targetRevision": "0.9.0", "chart": "dex"},
		"destination": map[string]any{"namespace": "dex-system"},
		"project":     "default",
		"syncPolicy":  map[string]any{"automated": map[string]any{"prune": false}},
	}
	dc := newFakeClient(obj)
	task := NewApply(dc)

	payload, err := json.Marshal(ApplyPayload{
		APIVersion: "dip.io/v1", Name: "dex-issuer", Namespace: "argocd",
		ResourceVersion: "rv-1",
		Spec:            map[string]any{"source": map[string]any{"repoURL": "oci://new", "targetRevision": "1.0.0"}},
	})
	require.NoError(t, err)

	result, err := task.Execute(context.Background(), payload)
	require.NoError(t, err)
	require.True(t, result.Success)

	updated, getErr := dc.Resource(gvr).Namespace("argocd").Get(context.Background(), "dex-issuer", metav1.GetOptions{})
	require.NoError(t, getErr)
	repoURL, _, _ := unstructured.NestedString(updated.Object, "spec", "source", "repoURL")
	assert.Equal(t, "oci://new", repoURL, "the caller-supplied field must still be updated")
	// Regression guard: an update that only names repoURL/targetRevision
	// inside source must not wholesale-replace source and drop chart -
	// the exact shape of the incident this merge fix was written for
	// (update_application dropped spec.source.chart, leaving the app in
	// ArgoCD's InvalidSpecError state).
	chart, found, _ := unstructured.NestedString(updated.Object, "spec", "source", "chart")
	assert.True(t, found, "source.chart must be preserved, not dropped by a same-key nested replace")
	assert.Equal(t, "dex", chart)
	namespace, found, _ := unstructured.NestedString(updated.Object, "spec", "destination", "namespace")
	assert.True(t, found, "destination.namespace must be preserved, not dropped")
	assert.Equal(t, "dex-system", namespace)
	project, found, _ := unstructured.NestedString(updated.Object, "spec", "project")
	assert.True(t, found, "project must be preserved, not dropped")
	assert.Equal(t, "default", project)
}

// TestApplyTask_UpdateRefusesToDropChartOrPath guards the invariant ArgoCD
// itself requires: a merged source with repoURL set but neither chart nor
// path is refused before the write, never committed and left for someone
// to discover later as a live resource stuck in ArgoCD's InvalidSpecError
// state (the original incident this validation was added for).
func TestApplyTask_UpdateRefusesToDropChartOrPath(t *testing.T) {
	obj := existingHelmApp("no-chart-yet", "argocd", "rv-1")
	obj.Object["spec"] = map[string]any{
		"source": map[string]any{"repoURL": "oci://old", "targetRevision": "0.9.0"},
	}
	dc := newFakeClient(obj)
	task := NewApply(dc)

	payload, err := json.Marshal(ApplyPayload{
		APIVersion: "dip.io/v1", Name: "no-chart-yet", Namespace: "argocd",
		ResourceVersion: "rv-1",
		Spec:            map[string]any{"source": map[string]any{"repoURL": "oci://new", "targetRevision": "1.0.0"}},
	})
	require.NoError(t, err)

	result, err := task.Execute(context.Background(), payload)
	require.NoError(t, err)
	require.False(t, result.Success)
	assert.Contains(t, result.Error, "chart")

	unchanged, getErr := dc.Resource(gvr).Namespace("argocd").Get(context.Background(), "no-chart-yet", metav1.GetOptions{})
	require.NoError(t, getErr)
	repoURL, _, _ := unstructured.NestedString(unchanged.Object, "spec", "source", "repoURL")
	assert.Equal(t, "oci://old", repoURL, "a refused update must not be partially applied")
}

// TestApplyTask_CreateRefusesInvalidSpec covers the same guard on the
// create path (deploy_application), not just update.
func TestApplyTask_CreateRefusesInvalidSpec(t *testing.T) {
	dc := newFakeClient()
	task := NewApply(dc)

	payload, err := json.Marshal(ApplyPayload{
		APIVersion: "dip.io/v1", Name: "my-app", Namespace: "argocd",
		Spec: map[string]any{"source": map[string]any{"repoURL": "oci://x", "targetRevision": "1.0.0"}},
	})
	require.NoError(t, err)

	result, err := task.Execute(context.Background(), payload)
	require.NoError(t, err)
	require.False(t, result.Success)
	assert.Contains(t, result.Error, "chart")

	_, getErr := dc.Resource(gvr).Namespace("argocd").Get(context.Background(), "my-app", metav1.GetOptions{})
	assert.True(t, apierrors.IsNotFound(getErr), "a refused create must not create the object")
}

// TestApplyTask_UpdateOnMissingObjectReturnsNotFound is the regression test
// for finding #12: a caller who supplies a ResourceVersion (meaning they
// read the object before) but the object no longer exists must get a clear
// not-found error, not have apply silently fall through to Create - that
// would hide the fact that someone deleted it out from under the caller.
func TestApplyTask_UpdateOnMissingObjectReturnsNotFound(t *testing.T) {
	dc := newFakeClient()
	task := NewApply(dc)

	payload, err := json.Marshal(ApplyPayload{
		APIVersion: "dip.io/v1", Name: "my-app", Namespace: "argocd", ResourceVersion: "rv-1",
		Spec: map[string]any{"source": map[string]any{"repoURL": "oci://x", "targetRevision": "1.0.0"}},
	})
	require.NoError(t, err)

	result, err := task.Execute(context.Background(), payload)
	require.NoError(t, err)
	require.False(t, result.Success)
	assert.Contains(t, result.Error, "not found")
}

func TestDeleteTask_DeletesCleanly(t *testing.T) {
	dc := newFakeClient(existingHelmApp("my-app", "argocd", "rv-1"))
	task := NewDelete(dc)

	payload, err := json.Marshal(map[string]any{"apiVersion": "dip.io/v1", "name": "my-app", "namespace": "argocd"})
	require.NoError(t, err)

	result, err := task.Execute(context.Background(), payload)
	require.NoError(t, err)
	require.True(t, result.Success)
}

func TestDeleteTask_AlreadyDeletedIsSuccess(t *testing.T) {
	dc := newFakeClient()
	task := NewDelete(dc)

	payload, err := json.Marshal(map[string]any{"apiVersion": "dip.io/v1", "name": "my-app", "namespace": "argocd"})
	require.NoError(t, err)

	result, err := task.Execute(context.Background(), payload)
	require.NoError(t, err)
	require.True(t, result.Success)
}

// TestDeleteTask_RefusesToDeleteBootstrap is a hard safety guardrail, not a
// bug fix: the "bootstrap" HelmApplication on dip-ce-k3s-eu (and by
// convention, any cluster following the same pattern) is the root
// composite that bootstraps core cluster infrastructure - deleting it
// could cascade-destroy the cluster. This check lives in the satellite
// task itself (not just an admin gate in centcom) so it can't be bypassed
// by any caller of this task, including the unauthenticated call_task path
// (see Critical #4 in the Phase 2 review) - defense in depth, the same
// posture as the Secret denylist in get_resource.
func TestDeleteTask_RefusesToDeleteBootstrap(t *testing.T) {
	dc := newFakeClient(existingHelmApp("bootstrap", "argocd", "rv-1"))
	task := NewDelete(dc)

	payload, err := json.Marshal(map[string]any{"apiVersion": "dip.io/v1", "name": "bootstrap", "namespace": "argocd"})
	require.NoError(t, err)

	result, err := task.Execute(context.Background(), payload)
	require.NoError(t, err)
	require.False(t, result.Success, "must refuse to delete the bootstrap HelmApplication")
	assert.Contains(t, result.Error, "bootstrap")

	_, getErr := dc.Resource(gvr).Namespace("argocd").Get(context.Background(), "bootstrap", metav1.GetOptions{})
	require.NoError(t, getErr, "bootstrap must still exist - the delete must never reach the API server")
}

// TestDeleteTask_RefusesToDeleteBootstrapRegardlessOfNamespace confirms the
// guardrail is name-based, not scoped to one namespace - "bootstrap" is
// protected everywhere, since a satellite may have it in any namespace.
func TestDeleteTask_RefusesToDeleteBootstrapRegardlessOfNamespace(t *testing.T) {
	dc := newFakeClient(existingHelmApp("bootstrap", "some-other-ns", "rv-1"))
	task := NewDelete(dc)

	payload, err := json.Marshal(map[string]any{"apiVersion": "dip.io/v1", "name": "bootstrap", "namespace": "some-other-ns"})
	require.NoError(t, err)

	result, err := task.Execute(context.Background(), payload)
	require.NoError(t, err)
	require.False(t, result.Success)
}

func TestDeleteTask_ReportsStuckFinalizer(t *testing.T) {
	// k8s.io/client-go/dynamic/fake's ObjectTracker does not implement
	// finalizer-aware delete blocking the way a real apiserver does (Delete
	// on an object with finalizers just removes it outright) - a
	// PrependReactor simulates the real behavior: a "delete" against an
	// object carrying finalizers marks it terminating but does not remove
	// it, exactly what this task's own Get-after-Delete check relies on.
	obj := existingHelmApp("my-app", "argocd", "rv-1")
	obj.SetFinalizers([]string{"resources-finalizer.argocd.argoproj.io"})
	now := metav1.Now()
	obj.SetDeletionTimestamp(&now)
	dc := newFakeClient(obj)
	dc.PrependReactor("delete", "helmapplications", func(action k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, nil // handled: pretend the delete call succeeded, but leave the tracker's copy untouched.
	})
	task := NewDelete(dc)

	payload, err := json.Marshal(map[string]any{"apiVersion": "dip.io/v1", "name": "my-app", "namespace": "argocd"})
	require.NoError(t, err)

	result, err := task.Execute(context.Background(), payload)
	require.NoError(t, err, "the error must be encoded in the Result, not returned as a Go error - a raw error is turned into a generic 500 by the satellite's HTTP handler, losing this message entirely")
	require.False(t, result.Success)
	assert.Contains(t, result.Error, "resources-finalizer.argocd.argoproj.io")
}

// TestDeleteTask_CrossplaneOwnFinalizerAloneIsNotStuck is the regression
// test for a real bug found in code review: every live HelmApplication
// composite carries Crossplane's own "composite.apiextensions.crossplane.io"
// finalizer as a normal part of its lifecycle (confirmed live on
// dip-ce-k3s-eu's bootstrap/cloudnative-pg-operator/dex-issuer composites)
// - only the specific, forbidden "resources-finalizer.argocd.argoproj.io"
// (the guardrail documented in crossplane-compositions' README) indicates a
// genuinely stuck delete. Before this fix, ANY finalizer at all - including
// Crossplane's own, present on every single real delete - was reported as
// stuck, making every successful delete look like a failure.
func TestDeleteTask_CrossplaneOwnFinalizerAloneIsNotStuck(t *testing.T) {
	obj := existingHelmApp("my-app", "argocd", "rv-1")
	obj.SetFinalizers([]string{"composite.apiextensions.crossplane.io"})
	now := metav1.Now()
	obj.SetDeletionTimestamp(&now)
	dc := newFakeClient(obj)
	dc.PrependReactor("delete", "helmapplications", func(action k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, nil
	})
	task := NewDelete(dc)

	payload, err := json.Marshal(map[string]any{"apiVersion": "dip.io/v1", "name": "my-app", "namespace": "argocd"})
	require.NoError(t, err)

	result, err := task.Execute(context.Background(), payload)
	require.NoError(t, err)
	require.True(t, result.Success, "Crossplane's own composite finalizer alone must not be reported as stuck - it's present on every legitimate in-progress delete")
}

func TestSyncTask_PatchesArgoCDOperationAnnotation(t *testing.T) {
	dc := newFakeClient(existingHelmApp("my-app", "argocd", "rv-1"))
	task := NewSync(dc)

	payload, err := json.Marshal(map[string]any{"apiVersion": "dip.io/v1", "name": "my-app", "namespace": "argocd"})
	require.NoError(t, err)

	result, err := task.Execute(context.Background(), payload)
	require.NoError(t, err)
	require.True(t, result.Success)

	obj, err := dc.Resource(gvr).Namespace("argocd").Get(context.Background(), "my-app", metav1.GetOptions{})
	require.NoError(t, err)
	value, found, _ := unstructured.NestedString(obj.Object, "metadata", "annotations", "argocd.argoproj.io/refresh")
	require.True(t, found, "expected the refresh annotation to be set")
	// "hard" is the value ArgoCD's own convention actually treats as a
	// hard-refresh trigger - an arbitrary timestamp value (the original
	// implementation) is not documented to trigger anything.
	assert.Equal(t, "hard", value)
}
