package cluster_health

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestTask_Name(t *testing.T) {
	assert.Equal(t, "cluster_health", New(fake.NewSimpleClientset()).Name())
}

func TestTask_Execute_PodRestarts(t *testing.T) {
	now := time.Now()
	recentRestartTime := metav1.NewTime(now.Add(-1 * time.Hour))
	oldRestartTime := metav1.NewTime(now.Add(-4 * time.Hour))

	// Pod 1: Restarted recently (1 hour ago), count > 5. Should be flagged.
	podRecent := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "pod-recent",
			Namespace:         "default",
			CreationTimestamp: metav1.NewTime(now.Add(-5 * time.Hour)),
		},
		Status: corev1.PodStatus{
			Phase: corev1.PodRunning,
			ContainerStatuses: []corev1.ContainerStatus{
				{
					Name:         "container-recent",
					RestartCount: 6,
					State: corev1.ContainerState{
						Running: &corev1.ContainerStateRunning{
							StartedAt: recentRestartTime,
						},
					},
					LastTerminationState: corev1.ContainerState{
						Terminated: &corev1.ContainerStateTerminated{
							FinishedAt: recentRestartTime,
							Reason:     "OOMKilled",
							Message:    "OOM killed container",
							ExitCode:   137,
						},
					},
				},
			},
		},
	}

	// Pod 2: Restarted long ago (4 hours ago), count > 5. Should be omitted.
	podOld := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "pod-old",
			Namespace:         "default",
			CreationTimestamp: metav1.NewTime(now.Add(-5 * time.Hour)),
		},
		Status: corev1.PodStatus{
			Phase: corev1.PodRunning,
			ContainerStatuses: []corev1.ContainerStatus{
				{
					Name:         "container-old",
					RestartCount: 8,
					State: corev1.ContainerState{
						Running: &corev1.ContainerStateRunning{
							StartedAt: oldRestartTime,
						},
					},
					LastTerminationState: corev1.ContainerState{
						Terminated: &corev1.ContainerStateTerminated{
							FinishedAt: oldRestartTime,
							Reason:     "Error",
							Message:    "some failure message",
							ExitCode:   1,
						},
					},
				},
			},
		},
	}

	// Pod 3: Currently waiting in CrashLoopBackOff. Should always be flagged regardless of timestamps.
	podWaiting := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "pod-waiting",
			Namespace:         "default",
			CreationTimestamp: metav1.NewTime(now.Add(-5 * time.Hour)),
		},
		Status: corev1.PodStatus{
			Phase: corev1.PodRunning,
			ContainerStatuses: []corev1.ContainerStatus{
				{
					Name:         "container-waiting",
					RestartCount: 1,
					State: corev1.ContainerState{
						Waiting: &corev1.ContainerStateWaiting{
							Reason:  "CrashLoopBackOff",
							Message: "Back-off restarting failed container",
						},
					},
				},
			},
		},
	}

	task := New(fake.NewSimpleClientset(podRecent, podOld, podWaiting))

	result, err := task.Execute(context.Background(), json.RawMessage(`{"namespace":"default"}`))
	require.NoError(t, err)
	require.True(t, result.Success)

	report, ok := result.Details.(*HealthReport)
	require.True(t, ok, "expected HealthReport in Details")

	// Verify only pod-recent and pod-waiting are returned
	assert.Len(t, report.UnhealthyPods, 2)

	var foundRecent, foundWaiting bool
	for _, up := range report.UnhealthyPods {
		switch up.Name {
		case "pod-recent":
			foundRecent = true
			assert.Equal(t, "HighRestarts", up.Phase)
			assert.Equal(t, int32(6), up.RestartCount)
			require.NotNil(t, up.LastRestartTime)
			assert.Equal(t, recentRestartTime.Unix(), up.LastRestartTime.Unix())
			assert.Equal(t, "OOMKilled", up.LastRestartReason)
			assert.Equal(t, "OOM killed container", up.LastRestartMessage)
		case "pod-waiting":
			foundWaiting = true
			assert.Equal(t, "Waiting", up.Phase)
			assert.Equal(t, "CrashLoopBackOff", up.Reason)
		}
	}
	assert.True(t, foundRecent, "expected pod-recent to be flagged")
	assert.True(t, foundWaiting, "expected pod-waiting to be flagged")
}

func TestTask_Execute_PodRestarts_ConfigurableWindow(t *testing.T) {
	now := time.Now()
	restartTime := metav1.NewTime(now.Add(-1 * time.Hour))

	// Restarted 1 hour ago, count > 5. Within the default 3h window, but
	// outside a caller-supplied 30-minute window.
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "pod-recent",
			Namespace:         "default",
			CreationTimestamp: metav1.NewTime(now.Add(-5 * time.Hour)),
		},
		Status: corev1.PodStatus{
			Phase: corev1.PodRunning,
			ContainerStatuses: []corev1.ContainerStatus{
				{
					Name:         "container-recent",
					RestartCount: 6,
					State: corev1.ContainerState{
						Running: &corev1.ContainerStateRunning{
							StartedAt: restartTime,
						},
					},
					LastTerminationState: corev1.ContainerState{
						Terminated: &corev1.ContainerStateTerminated{
							FinishedAt: restartTime,
							Reason:     "OOMKilled",
							Message:    "OOM killed container",
							ExitCode:   137,
						},
					},
				},
			},
		},
	}

	task := New(fake.NewSimpleClientset(pod))

	result, err := task.Execute(context.Background(), json.RawMessage(`{"namespace":"default","restart_window_minutes":30}`))
	require.NoError(t, err)
	require.True(t, result.Success)

	report, ok := result.Details.(*HealthReport)
	require.True(t, ok, "expected HealthReport in Details")

	assert.Empty(t, report.UnhealthyPods, "restart 1h ago should be excluded by a 30-minute window")
}

func probeWarningEvent(name string, reason, message string) *corev1.Event {
	return &corev1.Event{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: "default",
		},
		InvolvedObject: corev1.ObjectReference{
			Kind:      "Pod",
			Name:      "some-pod",
			Namespace: "default",
		},
		Type:          corev1.EventTypeWarning,
		Reason:        reason,
		Message:       message,
		Count:         1,
		LastTimestamp: metav1.NewTime(time.Now()),
	}
}

// TestTask_Execute_ProbeWarnings_ExcludedByDefault guards the fix for a
// real report: transient startup/liveness/readiness probe failures during
// node churn/rebalancing were making buildSummary say "Cluster has
// issues" (via len(RecentEvents) > 0) even though nothing else was wrong
// and report.Healthy stayed true — noise, not a real problem. By default,
// Warning events with Reason "Unhealthy" (kubelet's reason for all three
// probe types) must be excluded from RecentEvents and must not affect the
// summary.
func TestTask_Execute_ProbeWarnings_ExcludedByDefault(t *testing.T) {
	ev := probeWarningEvent("centcom.abc123", "Unhealthy", "Liveness probe failed: Get \"http://10.0.0.1:8080/health\": context deadline exceeded")
	task := New(fake.NewSimpleClientset(ev))

	result, err := task.Execute(context.Background(), json.RawMessage(`{}`))
	require.NoError(t, err)
	require.True(t, result.Success)

	report, ok := result.Details.(*HealthReport)
	require.True(t, ok)

	assert.Empty(t, report.RecentEvents, "probe-failure warning events should be excluded by default")
	assert.True(t, report.Healthy)
	assert.Equal(t, "Cluster is healthy - all workloads running, no node issues, no recent warnings", report.Summary)
}

// TestTask_Execute_ProbeWarnings_IncludedWhenRequested verifies the
// filtering is a lever, not a removal: a caller who explicitly wants to
// see probe warnings can still get them.
func TestTask_Execute_ProbeWarnings_IncludedWhenRequested(t *testing.T) {
	ev := probeWarningEvent("centcom.abc123", "Unhealthy", "Readiness probe failed: dial tcp: connect: connection refused")
	task := New(fake.NewSimpleClientset(ev))

	result, err := task.Execute(context.Background(), json.RawMessage(`{"include_probe_warnings": true}`))
	require.NoError(t, err)
	require.True(t, result.Success)

	report, ok := result.Details.(*HealthReport)
	require.True(t, ok)

	require.Len(t, report.RecentEvents, 1)
	assert.Equal(t, "Unhealthy", report.RecentEvents[0].Reason)
}

// TestTask_Execute_NonProbeWarnings_StillReportedByDefault ensures the
// probe-specific filter doesn't over-broadly suppress unrelated warning
// events.
func TestTask_Execute_NonProbeWarnings_StillReportedByDefault(t *testing.T) {
	ev := probeWarningEvent("some-pod.def456", "FailedScheduling", "0/3 nodes are available: insufficient cpu")
	task := New(fake.NewSimpleClientset(ev))

	result, err := task.Execute(context.Background(), json.RawMessage(`{}`))
	require.NoError(t, err)
	require.True(t, result.Success)

	report, ok := result.Details.(*HealthReport)
	require.True(t, ok)

	require.Len(t, report.RecentEvents, 1)
	assert.Equal(t, "FailedScheduling", report.RecentEvents[0].Reason)
}

// TestTask_Execute_UnhealthyPod_ResolvesDeploymentOwnerThroughReplicaSet is
// the regression test for Phase 2 of the Kubernetes Overview plan (the
// Issues model's "re-parent to the owning workload" mechanic, which needs
// this field and didn't exist before): a Deployment-managed pod's direct
// OwnerReference points at its ReplicaSet, not the Deployment — this must
// resolve one hop further to the FINAL controller.
func TestTask_Execute_UnhealthyPod_ResolvesDeploymentOwnerThroughReplicaSet(t *testing.T) {
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
		Status: corev1.PodStatus{Phase: corev1.PodFailed, Reason: "Evicted"},
	}

	task := New(fake.NewSimpleClientset(rs, pod))
	result, err := task.Execute(context.Background(), json.RawMessage(`{}`))
	require.NoError(t, err)
	require.True(t, result.Success)

	report, ok := result.Details.(*HealthReport)
	require.True(t, ok)
	require.Len(t, report.UnhealthyPods, 1)
	assert.Equal(t, "Deployment", report.UnhealthyPods[0].OwnerKind)
	assert.Equal(t, "checkout", report.UnhealthyPods[0].OwnerName)
}

func TestTask_Execute_UnhealthyPod_StatefulSetOwnerResolvedDirectly(t *testing.T) {
	truthy := true
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "redis-2",
			Namespace: "default",
			OwnerReferences: []metav1.OwnerReference{
				{Kind: "StatefulSet", Name: "redis", Controller: &truthy},
			},
		},
		Status: corev1.PodStatus{Phase: corev1.PodFailed, Reason: "Evicted"},
	}

	task := New(fake.NewSimpleClientset(pod))
	result, err := task.Execute(context.Background(), json.RawMessage(`{}`))
	require.NoError(t, err)
	require.True(t, result.Success)

	report, ok := result.Details.(*HealthReport)
	require.True(t, ok)
	require.Len(t, report.UnhealthyPods, 1)
	assert.Equal(t, "StatefulSet", report.UnhealthyPods[0].OwnerKind)
	assert.Equal(t, "redis", report.UnhealthyPods[0].OwnerName)
}

func TestTask_Execute_UnhealthyPod_BarePodHasNoOwner(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "debug-pod", Namespace: "default"},
		Status:     corev1.PodStatus{Phase: corev1.PodFailed, Reason: "Evicted"},
	}

	task := New(fake.NewSimpleClientset(pod))
	result, err := task.Execute(context.Background(), json.RawMessage(`{}`))
	require.NoError(t, err)
	require.True(t, result.Success)

	report, ok := result.Details.(*HealthReport)
	require.True(t, ok)
	require.Len(t, report.UnhealthyPods, 1)
	assert.Equal(t, "", report.UnhealthyPods[0].OwnerKind)
	assert.Equal(t, "", report.UnhealthyPods[0].OwnerName)
}

func notReadyNode(name string, age time.Duration) *corev1.Node {
	return &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name:              name,
			CreationTimestamp: metav1.NewTime(time.Now().Add(-age)),
		},
		Status: corev1.NodeStatus{
			Conditions: []corev1.NodeCondition{
				{Type: corev1.NodeReady, Status: corev1.ConditionFalse},
			},
		},
	}
}

func TestTask_Execute_NotReadyNode_WithinGracePeriod_NotFlagged(t *testing.T) {
	node := notReadyNode("karpenter-fresh", 2*time.Minute)
	task := New(fake.NewSimpleClientset(node))
	result, err := task.Execute(context.Background(), json.RawMessage(`{}`))
	require.NoError(t, err)
	require.True(t, result.Success)

	report, ok := result.Details.(*HealthReport)
	require.True(t, ok)
	assert.Empty(t, report.NodeIssues, "a NotReady node still inside its default 5m grace period must not be flagged")
}

func TestTask_Execute_NotReadyNode_PastGracePeriod_Flagged(t *testing.T) {
	node := notReadyNode("genuinely-stuck", 10*time.Minute)
	task := New(fake.NewSimpleClientset(node))
	result, err := task.Execute(context.Background(), json.RawMessage(`{}`))
	require.NoError(t, err)
	require.True(t, result.Success)

	report, ok := result.Details.(*HealthReport)
	require.True(t, ok)
	require.Len(t, report.NodeIssues, 1)
	assert.Equal(t, "genuinely-stuck", report.NodeIssues[0].Name)
	assert.Contains(t, report.NodeIssues[0].Conditions, "NotReady")
}

func TestTask_Execute_NotReadyNode_CustomGracePeriodHonored(t *testing.T) {
	node := notReadyNode("karpenter-fresh", 2*time.Minute)
	task := New(fake.NewSimpleClientset(node))
	result, err := task.Execute(context.Background(), json.RawMessage(`{"node_grace_period_minutes":1}`))
	require.NoError(t, err)
	require.True(t, result.Success)

	report, ok := result.Details.(*HealthReport)
	require.True(t, ok)
	require.Len(t, report.NodeIssues, 1, "a 1m grace period must not cover a 2m-old node")
	assert.Equal(t, "karpenter-fresh", report.NodeIssues[0].Name)
}

func TestTask_Execute_FreshNode_MemoryPressureStillFlagged(t *testing.T) {
	node := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "fresh-but-pressured",
			CreationTimestamp: metav1.NewTime(time.Now().Add(-1 * time.Minute)),
		},
		Status: corev1.NodeStatus{
			Conditions: []corev1.NodeCondition{
				{Type: corev1.NodeReady, Status: corev1.ConditionTrue},
				{Type: corev1.NodeMemoryPressure, Status: corev1.ConditionTrue},
			},
		},
	}
	task := New(fake.NewSimpleClientset(node))
	result, err := task.Execute(context.Background(), json.RawMessage(`{}`))
	require.NoError(t, err)
	require.True(t, result.Success)

	report, ok := result.Details.(*HealthReport)
	require.True(t, ok)
	require.Len(t, report.NodeIssues, 1, "the grace period only exempts NotReady, not other pressure conditions")
	assert.Contains(t, report.NodeIssues[0].Conditions, "MemoryPressure")
}

func disruptedNotReadyNode(name string) *corev1.Node {
	node := notReadyNode(name, 10*time.Minute) // past the default grace period
	node.Spec.Taints = []corev1.Taint{
		{Key: "karpenter.sh/disrupted", Effect: corev1.TaintEffectNoSchedule},
	}
	return node
}

func TestTask_Execute_KarpenterDisruptedNode_NotFlaggedByDefault(t *testing.T) {
	node := disruptedNotReadyNode("being-consolidated")
	task := New(fake.NewSimpleClientset(node))
	result, err := task.Execute(context.Background(), json.RawMessage(`{}`))
	require.NoError(t, err)
	require.True(t, result.Success)

	report, ok := result.Details.(*HealthReport)
	require.True(t, ok)
	assert.Empty(t, report.NodeIssues, "a node Karpenter has already tainted karpenter.sh/disrupted must not be flagged NotReady")
}

func TestTask_Execute_KarpenterDisruptedNode_FlaggedWhenIncluded(t *testing.T) {
	node := disruptedNotReadyNode("being-consolidated")
	task := New(fake.NewSimpleClientset(node))
	result, err := task.Execute(context.Background(), json.RawMessage(`{"include_karpenter_disrupted":true}`))
	require.NoError(t, err)
	require.True(t, result.Success)

	report, ok := result.Details.(*HealthReport)
	require.True(t, ok)
	require.Len(t, report.NodeIssues, 1, "include_karpenter_disrupted:true must restore the NotReady flag")
	assert.Equal(t, "being-consolidated", report.NodeIssues[0].Name)
}

func TestTask_Execute_NotReadyNode_WithoutTaint_StillFlaggedPastGracePeriod(t *testing.T) {
	// Guards against the taint check accidentally subsuming the grace
	// period check (or vice versa): a genuinely stuck node with NO
	// Karpenter taint, past its grace period, must still be flagged.
	node := notReadyNode("genuinely-stuck-no-taint", 10*time.Minute)
	task := New(fake.NewSimpleClientset(node))
	result, err := task.Execute(context.Background(), json.RawMessage(`{}`))
	require.NoError(t, err)
	require.True(t, result.Success)

	report, ok := result.Details.(*HealthReport)
	require.True(t, ok)
	require.Len(t, report.NodeIssues, 1)
	assert.Contains(t, report.NodeIssues[0].Conditions, "NotReady")
}

func TestTask_Execute_KarpenterDisruptedNode_MemoryPressureStillFlagged(t *testing.T) {
	node := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "disrupted-but-pressured",
			CreationTimestamp: metav1.NewTime(time.Now().Add(-10 * time.Minute)),
		},
		Spec: corev1.NodeSpec{
			Taints: []corev1.Taint{{Key: "karpenter.sh/disrupted", Effect: corev1.TaintEffectNoSchedule}},
		},
		Status: corev1.NodeStatus{
			Conditions: []corev1.NodeCondition{
				{Type: corev1.NodeReady, Status: corev1.ConditionFalse},
				{Type: corev1.NodeMemoryPressure, Status: corev1.ConditionTrue},
			},
		},
	}
	task := New(fake.NewSimpleClientset(node))
	result, err := task.Execute(context.Background(), json.RawMessage(`{}`))
	require.NoError(t, err)
	require.True(t, result.Success)

	report, ok := result.Details.(*HealthReport)
	require.True(t, ok)
	require.Len(t, report.NodeIssues, 1, "the disrupted taint only exempts NotReady, not other pressure conditions")
	assert.Equal(t, []string{"MemoryPressure"}, report.NodeIssues[0].Conditions)
}
