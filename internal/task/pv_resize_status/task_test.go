package pv_resize_status

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestTask_Name(t *testing.T) {
	assert.Equal(t, TaskName, New(fake.NewSimpleClientset()).Name())
}

func TestTask_Execute_MissingArgs(t *testing.T) {
	result, err := New(fake.NewSimpleClientset()).Execute(context.Background(), json.RawMessage("{}"))
	require.NoError(t, err)
	assert.False(t, result.Success)
	assert.Contains(t, result.Error, "namespace and pvc_name are required")
}

func TestTask_Execute_PVCNotFound(t *testing.T) {
	result, err := New(fake.NewSimpleClientset()).Execute(context.Background(),
		json.RawMessage(`{"namespace":"default","pvc_name":"missing"}`))
	require.NoError(t, err)
	assert.False(t, result.Success)
	assert.Contains(t, result.Error, "PVC not found")
}

// TestTask_Execute_NoMountingPod covers the case that used to require
// scanning every node in the cluster: a PVC exists but isn't currently
// mounted by any pod. getFilesystemStats must degrade gracefully (no
// filesystem stats, no error) instead of failing the whole call.
func TestTask_Execute_NoMountingPod(t *testing.T) {
	pvc := &corev1.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{Name: "data", Namespace: "default"},
		Spec: corev1.PersistentVolumeClaimSpec{
			Resources: corev1.VolumeResourceRequirements{
				Requests: corev1.ResourceList{
					corev1.ResourceStorage: *resource.NewQuantity(10*1024*1024*1024, resource.BinarySI),
				},
			},
		},
		Status: corev1.PersistentVolumeClaimStatus{
			Phase: corev1.ClaimBound,
			Capacity: corev1.ResourceList{
				corev1.ResourceStorage: *resource.NewQuantity(10*1024*1024*1024, resource.BinarySI),
			},
		},
	}
	clientset := fake.NewSimpleClientset(pvc)

	result, err := New(clientset).Execute(context.Background(),
		json.RawMessage(`{"namespace":"default","pvc_name":"data"}`))
	require.NoError(t, err)
	assert.True(t, result.Success)
	assert.Contains(t, result.Message, "ready")
}

