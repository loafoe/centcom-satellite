package storage_status

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestTask_Name(t *testing.T) {
	assert.Equal(t, "storage_status", New(fake.NewSimpleClientset()).Name())
}

func TestTask_Execute_StorageHealth(t *testing.T) {
	now := time.Now()
	recentTime := metav1.NewTime(now.Add(-2 * time.Minute))
	oldTime := metav1.NewTime(now.Add(-6 * time.Minute))

	// PVC 1: Pending, but brand new (2 min old). Should be counted in statistics but NOT flagged as problematic.
	pvcNew := &corev1.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "pvc-new",
			Namespace:         "default",
			CreationTimestamp: recentTime,
		},
		Spec: corev1.PersistentVolumeClaimSpec{
			Resources: corev1.VolumeResourceRequirements{
				Requests: corev1.ResourceList{
					corev1.ResourceStorage: *resource.NewQuantity(10*1024*1024*1024, resource.BinarySI),
				},
			},
		},
		Status: corev1.PersistentVolumeClaimStatus{
			Phase: corev1.ClaimPending,
		},
	}

	// PVC 2: Pending, but old (6 min old). Should be counted and flagged as problematic.
	pvcOld := &corev1.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "pvc-old",
			Namespace:         "default",
			CreationTimestamp: oldTime,
		},
		Spec: corev1.PersistentVolumeClaimSpec{
			Resources: corev1.VolumeResourceRequirements{
				Requests: corev1.ResourceList{
					corev1.ResourceStorage: *resource.NewQuantity(10*1024*1024*1024, resource.BinarySI),
				},
			},
		},
		Status: corev1.PersistentVolumeClaimStatus{
			Phase: corev1.ClaimPending,
		},
	}

	// PV 1: Released PV. Should be counted but NOT make the overall report unhealthy.
	pvReleased := &corev1.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{
			Name: "pv-released",
		},
		Spec: corev1.PersistentVolumeSpec{
			PersistentVolumeReclaimPolicy: corev1.PersistentVolumeReclaimRetain,
			Capacity: corev1.ResourceList{
				corev1.ResourceStorage: *resource.NewQuantity(10*1024*1024*1024, resource.BinarySI),
			},
		},
		Status: corev1.PersistentVolumeStatus{
			Phase: corev1.VolumeReleased,
		},
	}

	// Scenario A: Only new pending PVC and released PV. Overall health should be healthy (true).
	taskA := New(fake.NewSimpleClientset(pvcNew, pvReleased))
	resA, err := taskA.Execute(context.Background(), json.RawMessage(`{}`))
	require.NoError(t, err)
	require.True(t, resA.Success)

	reportA, ok := resA.Details.(*StorageReport)
	require.True(t, ok)
	assert.True(t, reportA.Healthy, "Expected report to be healthy with only new PVC and released PV")
	assert.Equal(t, 1, reportA.PVCSummary.Pending)
	assert.Equal(t, 1, reportA.PVSummary.Released)
	assert.Empty(t, reportA.ProblematicPVCs, "New PVC should not be flagged as problematic")

	// Scenario B: Old pending PVC included. Overall health should be unhealthy (false).
	taskB := New(fake.NewSimpleClientset(pvcNew, pvcOld, pvReleased))
	resB, err := taskB.Execute(context.Background(), json.RawMessage(`{}`))
	require.NoError(t, err)

	reportB, ok := resB.Details.(*StorageReport)
	require.True(t, ok)
	assert.False(t, reportB.Healthy, "Expected report to be unhealthy due to old stuck pending PVC")
	assert.Equal(t, 2, reportB.PVCSummary.Pending)
	require.Len(t, reportB.ProblematicPVCs, 1, "Only the old PVC should be flagged as problematic")
	assert.Equal(t, "pvc-old", reportB.ProblematicPVCs[0].Name)
}
