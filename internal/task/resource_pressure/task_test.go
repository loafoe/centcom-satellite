package resource_pressure

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestTask_Name(t *testing.T) {
	assert.Equal(t, "resource_pressure", New(fake.NewSimpleClientset()).Name())
}

func TestTask_Execute_PendingPods(t *testing.T) {
	now := time.Now()
	recentTime := metav1.NewTime(now.Add(-2 * time.Minute))
	oldTime := metav1.NewTime(now.Add(-6 * time.Minute))

	// Pod 1: Pending, but new (2 min old). Should NOT be flagged as a problematic pending pod.
	podNew := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "pod-new",
			Namespace:         "default",
			CreationTimestamp: recentTime,
		},
		Status: corev1.PodStatus{
			Phase: corev1.PodPending,
			Conditions: []corev1.PodCondition{
				{
					Type:   corev1.PodScheduled,
					Status: corev1.ConditionFalse,
					Reason: "Unschedulable",
				},
			},
		},
	}

	// Pod 2: Pending, but old (6 min old). Should be flagged as a problematic pending pod.
	podOld := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "pod-old",
			Namespace:         "default",
			CreationTimestamp: oldTime,
		},
		Status: corev1.PodStatus{
			Phase: corev1.PodPending,
			Conditions: []corev1.PodCondition{
				{
					Type:   corev1.PodScheduled,
					Status: corev1.ConditionFalse,
					Reason: "Unschedulable",
				},
			},
		},
	}

	task := New(fake.NewSimpleClientset(podNew, podOld))
	res, err := task.Execute(context.Background(), json.RawMessage(`{}`))
	require.NoError(t, err)
	require.True(t, res.Success)

	report, ok := res.Details.(*ResourceReport)
	require.True(t, ok)

	// Verify only pod-old is in report.PendingPods
	require.Len(t, report.PendingPods, 1)
	assert.Equal(t, "pod-old", report.PendingPods[0].Name)
}
