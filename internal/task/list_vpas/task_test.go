package list_vpas

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	k8stesting "k8s.io/client-go/testing"
)

func newTestTask(client *dynamicfake.FakeDynamicClient) *Task {
	return New(nil, client)
}

func fakeDynamicClient() *dynamicfake.FakeDynamicClient {
	scheme := runtime.NewScheme()
	return dynamicfake.NewSimpleDynamicClientWithCustomListKinds(
		scheme,
		map[schema.GroupVersionResource]string{
			vpaGVR: "VerticalPodAutoscalerList",
		},
	)
}

// TestExecute_VPACRDNotInstalled verifies the genuinely-not-installed case
// still reports the friendly, correctly-labeled empty result.
func TestExecute_VPACRDNotInstalled(t *testing.T) {
	client := fakeDynamicClient()
	client.PrependReactor("list", "verticalpodautoscalers", func(action k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewNotFound(
			schema.GroupResource{Group: "autoscaling.k8s.io", Resource: "verticalpodautoscalers"}, "")
	})

	result, err := newTestTask(client).Execute(context.Background(), json.RawMessage(`{}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Success {
		t.Fatalf("expected success=true (empty list), got error: %s", result.Error)
	}
	list := result.Details.(*VPAList)
	if list.VPAInstalled {
		t.Error("VPAInstalled = true, want false")
	}
}

// TestExecute_OtherListErrorNotMislabeledAsCRDMissing is the regression
// test for the false-negative bug: any List() failure (RBAC denial,
// apiserver timeout, network failure, ...) used to be reported identically
// to "VPA CRD not installed" - a confident, wrong answer that hides the
// real problem (e.g. an RBAC gap) behind a misleading "not installed"
// message instead of surfacing it. A Forbidden error must not be reported
// as success/not-installed, and must not become an opaque 500 either.
func TestExecute_OtherListErrorNotMislabeledAsCRDMissing(t *testing.T) {
	client := fakeDynamicClient()
	client.PrependReactor("list", "verticalpodautoscalers", func(action k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewForbidden(
			schema.GroupResource{Group: "autoscaling.k8s.io", Resource: "verticalpodautoscalers"}, "",
			errors.New("User cannot list resource"))
	})

	result, err := newTestTask(client).Execute(context.Background(), json.RawMessage(`{}`))
	if err != nil {
		t.Fatalf("expected a Result, not a Go error (must not become an opaque 500): %v", err)
	}
	if result.Success {
		t.Fatal("expected success=false for a Forbidden list error")
	}
	if list, ok := result.Details.(*VPAList); ok && !list.VPAInstalled {
		t.Error("a Forbidden error was mislabeled as 'VPA CRD not installed' - the real cause (RBAC) is hidden")
	}
}
