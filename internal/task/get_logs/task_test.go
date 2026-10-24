package get_logs

import (
	"context"
	"encoding/json"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func fakePod(ns, name string, containers ...string) *corev1.Pod {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
	}
	for _, c := range containers {
		pod.Spec.Containers = append(pod.Spec.Containers, corev1.Container{Name: c})
	}
	return pod
}

// The GetLogs(previous: true) BadRequest scenario itself (the ri-obs-use1-ct
// incident) is covered at the classification level by
// internal/k8s.TestWrapError_ClientFault, using the exact real apiserver
// message - client-go's fake Pods.GetLogs doesn't propagate a reactor error
// through Stream() (verified empirically: the reactor fires but Stream()
// still returns a nil error), so it can't be driven end-to-end through
// Execute in a unit test. TestExecute_PodNotFound below exercises the same
// Execute -> k8sclient.WrapError path via the "get pod" call instead, which
// *is* reliably fakeable.

// TestExecute_PodNotFound verifies the "get pod" call's own NotFound error
// is likewise a self-describing Result, not an opaque 500.
func TestExecute_PodNotFound(t *testing.T) {
	clientset := fake.NewSimpleClientset()
	tsk := New(clientset)

	payload, err := json.Marshal(Payload{Namespace: "default", PodName: "does-not-exist"})
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}

	result, execErr := tsk.Execute(context.Background(), json.RawMessage(payload))
	if execErr != nil {
		t.Fatalf("expected a Result, not a Go error: %v", execErr)
	}
	if result.Success {
		t.Fatal("expected success=false for a nonexistent pod")
	}
}

// TestExecute_RetrievesLogs is a basic happy-path sanity check.
func TestExecute_RetrievesLogs(t *testing.T) {
	pod := fakePod("default", "myapp", "app")
	clientset := fake.NewSimpleClientset(pod)
	tsk := New(clientset)

	payload, err := json.Marshal(Payload{Namespace: "default", PodName: "myapp"})
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}

	result, execErr := tsk.Execute(context.Background(), json.RawMessage(payload))
	if execErr != nil {
		t.Fatalf("unexpected error: %v", execErr)
	}
	if !result.Success {
		t.Fatalf("expected success, got error: %s", result.Error)
	}
}
