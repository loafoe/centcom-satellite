package helm_application

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
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
			"source": map[string]any{"repoURL": "oci://old", "targetRevision": "0.9.0"},
		},
	}}
}

func TestApplyTask_CreatesNewResource(t *testing.T) {
	dc := newFakeClient()
	task := NewApply(dc)

	payload, err := json.Marshal(ApplyPayload{
		APIVersion: "dip.io/v1", Name: "my-app", Namespace: "argocd",
		Spec: map[string]any{"source": map[string]any{"repoURL": "oci://x", "targetRevision": "1.0.0"}},
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

	_, err = task.Execute(context.Background(), payload)
	var conflictErr *ConflictError
	require.True(t, errors.As(err, &conflictErr), "expected a ConflictError, got %v", err)
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
		Spec:   map[string]any{"source": map[string]any{"repoURL": "oci://x", "targetRevision": "1.0.0"}},
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
