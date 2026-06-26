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
		if up.Name == "pod-recent" {
			foundRecent = true
			assert.Equal(t, "HighRestarts", up.Phase)
			assert.Equal(t, int32(6), up.RestartCount)
			require.NotNil(t, up.LastRestartTime)
			assert.Equal(t, recentRestartTime.Unix(), up.LastRestartTime.Unix())
			assert.Equal(t, "OOMKilled", up.LastRestartReason)
			assert.Equal(t, "OOM killed container", up.LastRestartMessage)
		} else if up.Name == "pod-waiting" {
			foundWaiting = true
			assert.Equal(t, "Waiting", up.Phase)
			assert.Equal(t, "CrashLoopBackOff", up.Reason)
		}
	}
	assert.True(t, foundRecent, "expected pod-recent to be flagged")
	assert.True(t, foundWaiting, "expected pod-waiting to be flagged")
}
