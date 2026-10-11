package get_events

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
)

func fakeEvent(ns, name, reason string) *corev1.Event {
	return &corev1.Event{
		ObjectMeta:     metav1.ObjectMeta{Name: name, Namespace: ns},
		Reason:         reason,
		Type:           "Warning",
		Count:          1,
		LastTimestamp:  metav1.Now(),
		InvolvedObject: corev1.ObjectReference{Kind: "Pod", Name: name},
	}
}

func TestExecute_EmptyNamespaceListsAllNamespaces(t *testing.T) {
	clientset := fake.NewSimpleClientset(
		fakeEvent("default", "ev-a", "Scheduled"),
		fakeEvent("kube-system", "ev-b", "Pulled"),
	)
	tsk := New(clientset)

	result, err := tsk.Execute(context.Background(), json.RawMessage(`{}`))
	require.NoError(t, err)
	require.True(t, result.Success, "result: %+v", result)

	list, ok := result.Details.(*EventList)
	require.True(t, ok, "details: %#v", result.Details)
	assert.Equal(t, 2, list.Total)
	assert.False(t, list.Truncated)
}

func TestExecute_NamespaceScopedStillWorks(t *testing.T) {
	clientset := fake.NewSimpleClientset(
		fakeEvent("default", "ev-a", "Scheduled"),
		fakeEvent("kube-system", "ev-b", "Pulled"),
	)
	tsk := New(clientset)

	result, err := tsk.Execute(context.Background(), json.RawMessage(`{"namespace":"default"}`))
	require.NoError(t, err)
	require.True(t, result.Success)

	list, ok := result.Details.(*EventList)
	require.True(t, ok, "details: %#v", result.Details)
	assert.Equal(t, 1, list.Total)
}

func TestExecute_DefaultLimitTruncatesAllNamespacesResult(t *testing.T) {
	objs := make([]runtime.Object, 0, 205)
	for i := 0; i < 205; i++ {
		objs = append(objs, fakeEvent("default", fmt.Sprintf("ev-%d", i), "Scheduled"))
	}
	clientset := fake.NewSimpleClientset(objs...)
	tsk := New(clientset)

	result, err := tsk.Execute(context.Background(), json.RawMessage(`{}`))
	require.NoError(t, err)
	require.True(t, result.Success)

	list, ok := result.Details.(*EventList)
	require.True(t, ok, "details: %#v", result.Details)
	assert.Equal(t, 205, list.Total, "Total must report the real count, not the truncated length")
	assert.Len(t, list.Events, 200, "default limit caps the returned slice at 200")
	assert.True(t, list.Truncated)
}
