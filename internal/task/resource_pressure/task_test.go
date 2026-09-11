package resource_pressure

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

func nodeWithCapacity(name, cpu, mem string) *corev1.Node {
	return &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Status: corev1.NodeStatus{
			Capacity: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse(cpu),
				corev1.ResourceMemory: resource.MustParse(mem),
			},
			Allocatable: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse(cpu),
				corev1.ResourceMemory: resource.MustParse(mem),
				corev1.ResourcePods:   resource.MustParse("110"),
			},
		},
	}
}

func podRequesting(name, node, cpu, mem string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default"},
		Spec: corev1.PodSpec{
			NodeName: node,
			Containers: []corev1.Container{{
				Name: "c",
				Resources: corev1.ResourceRequirements{
					Requests: corev1.ResourceList{
						corev1.ResourceCPU:    resource.MustParse(cpu),
						corev1.ResourceMemory: resource.MustParse(mem),
					},
				},
			}},
		},
		Status: corev1.PodStatus{Phase: corev1.PodRunning},
	}
}

// TestTask_Execute_NodePressure_DefaultThresholdIsHighBinPacking guards the
// Karpenter/cluster-autoscaler-aware default: a node bin-packed to 85%
// allocation (efficient, intentional scheduling density — not a real
// problem) must NOT be reported as "under pressure" by default. Only a
// node genuinely near its scheduling ceiling (>=90% by default) should be
// flagged, and the threshold must be tunable via the payload for callers
// who want a different bar.
func TestTask_Execute_NodePressure_DefaultThresholdIsHighBinPacking(t *testing.T) {
	node := nodeWithCapacity("packed-node", "1000m", "1000Mi")
	// 850m / 1000m = 85% CPU allocation — efficient bin-packing, not pressure.
	pod := podRequesting("pod-a", "packed-node", "850m", "100Mi")

	task := New(fake.NewSimpleClientset(node, pod))
	res, err := task.Execute(context.Background(), json.RawMessage(`{}`))
	require.NoError(t, err)
	require.True(t, res.Success)

	report, ok := res.Details.(*ResourceReport)
	require.True(t, ok)
	assert.Empty(t, report.NodePressure, "85%% allocation should not be flagged as pressure under the default (raised) threshold")
}

// TestTask_Execute_NodePressure_AboveDefaultThresholdStillFlagged confirms
// the raised default threshold still catches a node genuinely near its
// scheduling ceiling.
func TestTask_Execute_NodePressure_AboveDefaultThresholdStillFlagged(t *testing.T) {
	node := nodeWithCapacity("tight-node", "1000m", "1000Mi")
	pod := podRequesting("pod-a", "tight-node", "950m", "100Mi")

	task := New(fake.NewSimpleClientset(node, pod))
	res, err := task.Execute(context.Background(), json.RawMessage(`{}`))
	require.NoError(t, err)
	require.True(t, res.Success)

	report, ok := res.Details.(*ResourceReport)
	require.True(t, ok)
	require.Len(t, report.NodePressure, 1)
	assert.Equal(t, "tight-node", report.NodePressure[0].Name)
}

// TestTask_Execute_NodePressure_ThresholdTunable verifies the threshold can
// be lowered back via the payload for a caller who wants the old, more
// sensitive behavior.
func TestTask_Execute_NodePressure_ThresholdTunable(t *testing.T) {
	node := nodeWithCapacity("packed-node", "1000m", "1000Mi")
	pod := podRequesting("pod-a", "packed-node", "850m", "100Mi")

	task := New(fake.NewSimpleClientset(node, pod))
	res, err := task.Execute(context.Background(), json.RawMessage(`{"min_pressure_percent": 70}`))
	require.NoError(t, err)
	require.True(t, res.Success)

	report, ok := res.Details.(*ResourceReport)
	require.True(t, ok)
	require.Len(t, report.NodePressure, 1, "with an explicit 70%% threshold, 85%% allocation should be flagged")
}

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
