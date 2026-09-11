package cluster_health

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
