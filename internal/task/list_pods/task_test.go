package list_pods

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestTask_Execute_ResolvesDeploymentOwnerThroughReplicaSet(t *testing.T) {
	truthy := true
	rs := &appsv1.ReplicaSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "checkout-7d8f9c6b5d",
			Namespace: "default",
			OwnerReferences: []metav1.OwnerReference{
				{Kind: "Deployment", Name: "checkout", Controller: &truthy},
			},
		},
	}
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "checkout-7d8f9c6b5d-x9z2k",
			Namespace: "default",
			OwnerReferences: []metav1.OwnerReference{
				{Kind: "ReplicaSet", Name: "checkout-7d8f9c6b5d", Controller: &truthy},
			},
		},
	}

	task := New(fake.NewSimpleClientset(rs, pod))
	result, err := task.Execute(context.Background(), json.RawMessage(`{}`))
	require.NoError(t, err)
	require.True(t, result.Success)

	list, ok := result.Details.(*PodList)
	require.True(t, ok)
	require.Len(t, list.Pods, 1)
	assert.Equal(t, "Deployment", list.Pods[0].OwnerKind)
	assert.Equal(t, "checkout", list.Pods[0].OwnerName)
}

func TestTask_Execute_StatefulSetOwnerResolvedDirectly(t *testing.T) {
	truthy := true
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "redis-2",
			Namespace: "default",
			OwnerReferences: []metav1.OwnerReference{
				{Kind: "StatefulSet", Name: "redis", Controller: &truthy},
			},
		},
	}

	task := New(fake.NewSimpleClientset(pod))
	result, err := task.Execute(context.Background(), json.RawMessage(`{}`))
	require.NoError(t, err)
	require.True(t, result.Success)

	list, ok := result.Details.(*PodList)
	require.True(t, ok)
	require.Len(t, list.Pods, 1)
	assert.Equal(t, "StatefulSet", list.Pods[0].OwnerKind)
	assert.Equal(t, "redis", list.Pods[0].OwnerName)
}

func TestTask_Execute_BarePodHasNoOwner(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "debug-pod", Namespace: "default"},
	}

	task := New(fake.NewSimpleClientset(pod))
	result, err := task.Execute(context.Background(), json.RawMessage(`{}`))
	require.NoError(t, err)
	require.True(t, result.Success)

	list, ok := result.Details.(*PodList)
	require.True(t, ok)
	require.Len(t, list.Pods, 1)
	assert.Equal(t, "", list.Pods[0].OwnerKind)
	assert.Equal(t, "", list.Pods[0].OwnerName)
}

// TestTask_Execute_AllNamespaces_DoesNotCollideReplicaSetNamesAcrossNamespaces
// is the correctness check that motivated keying resolveReplicaSetOwners by
// namespace+name rather than bare name: two unrelated Deployments in two
// different namespaces producing identically-named ReplicaSets must each
// resolve to their OWN Deployment, not whichever one the map saw last.
func TestTask_Execute_AllNamespaces_DoesNotCollideReplicaSetNamesAcrossNamespaces(t *testing.T) {
	truthy := true
	rsA := &appsv1.ReplicaSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "web-7d8f9c6b5d",
			Namespace: "team-a",
			OwnerReferences: []metav1.OwnerReference{
				{Kind: "Deployment", Name: "web-a", Controller: &truthy},
			},
		},
	}
	rsB := &appsv1.ReplicaSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "web-7d8f9c6b5d", // same name, different namespace
			Namespace: "team-b",
			OwnerReferences: []metav1.OwnerReference{
				{Kind: "Deployment", Name: "web-b", Controller: &truthy},
			},
		},
	}
	podA := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "web-7d8f9c6b5d-aaa",
			Namespace: "team-a",
			OwnerReferences: []metav1.OwnerReference{
				{Kind: "ReplicaSet", Name: "web-7d8f9c6b5d", Controller: &truthy},
			},
		},
	}
	podB := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "web-7d8f9c6b5d-bbb",
			Namespace: "team-b",
			OwnerReferences: []metav1.OwnerReference{
				{Kind: "ReplicaSet", Name: "web-7d8f9c6b5d", Controller: &truthy},
			},
		},
	}

	task := New(fake.NewSimpleClientset(rsA, rsB, podA, podB))
	result, err := task.Execute(context.Background(), json.RawMessage(`{}`))
	require.NoError(t, err)
	require.True(t, result.Success)

	list, ok := result.Details.(*PodList)
	require.True(t, ok)
	require.Len(t, list.Pods, 2)

	byName := map[string]PodInfo{}
	for _, p := range list.Pods {
		byName[p.Name] = p
	}
	assert.Equal(t, "web-a", byName["web-7d8f9c6b5d-aaa"].OwnerName)
	assert.Equal(t, "web-b", byName["web-7d8f9c6b5d-bbb"].OwnerName)
}

func TestTask_Execute_RestartsSummedAcrossContainers(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "multi-container", Namespace: "default"},
		Status: corev1.PodStatus{
			ContainerStatuses: []corev1.ContainerStatus{
				{Name: "a", RestartCount: 3},
				{Name: "b", RestartCount: 4},
			},
		},
	}
	task := New(fake.NewSimpleClientset(pod))
	result, err := task.Execute(context.Background(), json.RawMessage(`{}`))
	require.NoError(t, err)
	require.True(t, result.Success)

	list, ok := result.Details.(*PodList)
	require.True(t, ok)
	require.Len(t, list.Pods, 1)
	assert.Equal(t, int32(7), list.Pods[0].Restarts)
}
