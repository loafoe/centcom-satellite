// Package list_workloads provides workload listing functionality.
package list_workloads

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/loafoe/pico-agent/internal/task"
)

const TaskName = "list_workloads"

// Payload for list_workloads task.
type Payload struct {
	Namespace string `json:"namespace"`      // required
	Kind      string `json:"kind,omitempty"` // deployment/statefulset/daemonset/all (default: all)
}

// WorkloadList contains the workload listing.
type WorkloadList struct {
	Total     int            `json:"total"`
	Workloads []WorkloadInfo `json:"workloads"`
}

// WorkloadInfo contains workload details.
type WorkloadInfo struct {
	Name         string            `json:"name"`
	Namespace    string            `json:"namespace"`
	Kind         string            `json:"kind"`
	Replicas     ReplicaStatus     `json:"replicas"`
	Images       []string          `json:"images"`
	Labels       map[string]string `json:"labels,omitempty"`
	CreationTime string            `json:"creation_time"`
	Age          string            `json:"age"`
}

// ReplicaStatus contains replica information.
type ReplicaStatus struct {
	Desired int32 `json:"desired"`
	Ready   int32 `json:"ready"`
}

// Task handles workload listing.
type Task struct {
	clientset kubernetes.Interface
}

// New creates a new list workloads task.
func New(clientset kubernetes.Interface) *Task {
	return &Task{clientset: clientset}
}

// Name returns the task type identifier.
func (t *Task) Name() string {
	return TaskName
}

// Execute lists workloads in a namespace.
func (t *Task) Execute(ctx context.Context, rawPayload json.RawMessage) (*task.Result, error) {
	var payload Payload
	if len(rawPayload) > 0 && string(rawPayload) != "{}" {
		if err := json.Unmarshal(rawPayload, &payload); err != nil {
			return task.NewErrorResult(fmt.Sprintf("invalid payload: %v", err)), nil
		}
	}

	if payload.Namespace == "" {
		return task.NewErrorResult("namespace is required"), nil
	}

	// Default kind to "all" if empty
	if payload.Kind == "" {
		payload.Kind = "all"
	}

	var workloads []WorkloadInfo

	// List Deployments
	if payload.Kind == "deployment" || payload.Kind == "all" {
		deployments, err := t.clientset.AppsV1().Deployments(payload.Namespace).List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, fmt.Errorf("failed to list deployments: %w", err)
		}
		for i := range deployments.Items {
			workloads = append(workloads, t.buildDeploymentInfo(&deployments.Items[i]))
		}
	}

	// List StatefulSets
	if payload.Kind == "statefulset" || payload.Kind == "all" {
		statefulsets, err := t.clientset.AppsV1().StatefulSets(payload.Namespace).List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, fmt.Errorf("failed to list statefulsets: %w", err)
		}
		for i := range statefulsets.Items {
			workloads = append(workloads, t.buildStatefulSetInfo(&statefulsets.Items[i]))
		}
	}

	// List DaemonSets
	if payload.Kind == "daemonset" || payload.Kind == "all" {
		daemonsets, err := t.clientset.AppsV1().DaemonSets(payload.Namespace).List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, fmt.Errorf("failed to list daemonsets: %w", err)
		}
		for i := range daemonsets.Items {
			workloads = append(workloads, t.buildDaemonSetInfo(&daemonsets.Items[i]))
		}
	}

	// Sort by Kind then Name
	sort.Slice(workloads, func(i, j int) bool {
		if workloads[i].Kind != workloads[j].Kind {
			return workloads[i].Kind < workloads[j].Kind
		}
		return workloads[i].Name < workloads[j].Name
	})

	result := &WorkloadList{
		Total:     len(workloads),
		Workloads: workloads,
	}

	return task.NewSuccessResultWithDetails(
		fmt.Sprintf("Found %d workloads in namespace %s", result.Total, payload.Namespace),
		result,
	), nil
}

func (t *Task) buildDeploymentInfo(deployment *appsv1.Deployment) WorkloadInfo {
	images := extractImages(deployment.Spec.Template.Spec.Containers)
	var desired int32 = 1
	if deployment.Spec.Replicas != nil {
		desired = *deployment.Spec.Replicas
	}

	return WorkloadInfo{
		Name:      deployment.Name,
		Namespace: deployment.Namespace,
		Kind:      "Deployment",
		Replicas: ReplicaStatus{
			Desired: desired,
			Ready:   deployment.Status.ReadyReplicas,
		},
		Images:       images,
		Labels:       deployment.Labels,
		CreationTime: deployment.CreationTimestamp.Format(time.RFC3339),
		Age:          formatAge(deployment.CreationTimestamp.Time),
	}
}

func (t *Task) buildStatefulSetInfo(statefulset *appsv1.StatefulSet) WorkloadInfo {
	images := extractImages(statefulset.Spec.Template.Spec.Containers)
	var desired int32 = 1
	if statefulset.Spec.Replicas != nil {
		desired = *statefulset.Spec.Replicas
	}

	return WorkloadInfo{
		Name:      statefulset.Name,
		Namespace: statefulset.Namespace,
		Kind:      "StatefulSet",
		Replicas: ReplicaStatus{
			Desired: desired,
			Ready:   statefulset.Status.ReadyReplicas,
		},
		Images:       images,
		Labels:       statefulset.Labels,
		CreationTime: statefulset.CreationTimestamp.Format(time.RFC3339),
		Age:          formatAge(statefulset.CreationTimestamp.Time),
	}
}

func (t *Task) buildDaemonSetInfo(daemonset *appsv1.DaemonSet) WorkloadInfo {
	images := extractImages(daemonset.Spec.Template.Spec.Containers)

	return WorkloadInfo{
		Name:      daemonset.Name,
		Namespace: daemonset.Namespace,
		Kind:      "DaemonSet",
		Replicas: ReplicaStatus{
			Desired: daemonset.Status.DesiredNumberScheduled,
			Ready:   daemonset.Status.NumberReady,
		},
		Images:       images,
		Labels:       daemonset.Labels,
		CreationTime: daemonset.CreationTimestamp.Format(time.RFC3339),
		Age:          formatAge(daemonset.CreationTimestamp.Time),
	}
}

func extractImages(containers []corev1.Container) []string {
	images := make([]string, 0, len(containers))
	for _, c := range containers {
		images = append(images, c.Image)
	}
	return images
}

func formatAge(t time.Time) string {
	d := time.Since(t)
	switch {
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd", int(d.Hours()/24))
	}
}
