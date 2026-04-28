// Package list_pods provides pod listing functionality.
package list_pods

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/loafoe/pico-agent/internal/task"
)

const TaskName = "list_pods"

// Payload for list_pods task.
type Payload struct {
	Namespace     string `json:"namespace"`
	LabelSelector string `json:"label_selector,omitempty"`
	FieldSelector string `json:"field_selector,omitempty"`
}

// PodList contains the pod listing.
type PodList struct {
	Total int       `json:"total"`
	Pods  []PodInfo `json:"pods"`
}

// PodInfo contains pod details.
type PodInfo struct {
	Name       string          `json:"name"`
	Namespace  string          `json:"namespace"`
	Status     string          `json:"status"`
	Node       string          `json:"node"`
	Restarts   int32           `json:"restarts"`
	Age        string          `json:"age"`
	Containers []ContainerInfo `json:"containers"`
}

// ContainerInfo contains container details.
type ContainerInfo struct {
	Name     string            `json:"name"`
	Image    string            `json:"image"`
	State    string            `json:"state"`
	Ready    bool              `json:"ready"`
	Restarts int32             `json:"restarts"`
	Requests map[string]string `json:"requests,omitempty"`
	Limits   map[string]string `json:"limits,omitempty"`
}

// Task handles pod listing.
type Task struct {
	clientset kubernetes.Interface
}

// New creates a new list pods task.
func New(clientset kubernetes.Interface) *Task {
	return &Task{clientset: clientset}
}

// Name returns the task type identifier.
func (t *Task) Name() string {
	return TaskName
}

// Execute lists pods in a namespace.
func (t *Task) Execute(ctx context.Context, rawPayload json.RawMessage) (*task.Result, error) {
	var payload Payload
	if len(rawPayload) > 0 && string(rawPayload) != "{}" {
		if err := json.Unmarshal(rawPayload, &payload); err != nil {
			return task.NewErrorResult(fmt.Sprintf("invalid payload: %v", err)), nil
		}
	}

	// Empty namespace means all namespaces
	namespace := payload.Namespace
	if namespace == "" {
		namespace = metav1.NamespaceAll
	}

	listOpts := metav1.ListOptions{}
	if payload.LabelSelector != "" {
		listOpts.LabelSelector = payload.LabelSelector
	}
	if payload.FieldSelector != "" {
		listOpts.FieldSelector = payload.FieldSelector
	}

	pods, err := t.clientset.CoreV1().Pods(namespace).List(ctx, listOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to list pods: %w", err)
	}

	result := &PodList{
		Total: len(pods.Items),
		Pods:  make([]PodInfo, 0, len(pods.Items)),
	}

	for i := range pods.Items {
		pod := &pods.Items[i]
		podInfo := t.buildPodInfo(pod)
		result.Pods = append(result.Pods, podInfo)
	}

	// Sort alphabetically by name
	sort.Slice(result.Pods, func(i, j int) bool {
		return result.Pods[i].Name < result.Pods[j].Name
	})

	msg := fmt.Sprintf("Found %d pods in namespace %s", result.Total, namespace)
	if namespace == metav1.NamespaceAll {
		msg = fmt.Sprintf("Found %d pods across all namespaces", result.Total)
	}
	return task.NewSuccessResultWithDetails(msg, result), nil
}

func (t *Task) buildPodInfo(pod *corev1.Pod) PodInfo {
	info := PodInfo{
		Name:       pod.Name,
		Namespace:  pod.Namespace,
		Status:     getPodStatus(pod),
		Node:       pod.Spec.NodeName,
		Age:        formatAge(pod.CreationTimestamp.Time),
		Containers: make([]ContainerInfo, 0, len(pod.Spec.Containers)),
	}

	// Build container status map for quick lookup
	containerStatusMap := make(map[string]corev1.ContainerStatus)
	for i := range pod.Status.ContainerStatuses {
		cs := &pod.Status.ContainerStatuses[i]
		containerStatusMap[cs.Name] = *cs
		info.Restarts += cs.RestartCount
	}

	// Build container info from spec and status
	for i := range pod.Spec.Containers {
		container := &pod.Spec.Containers[i]
		containerInfo := ContainerInfo{
			Name:  container.Name,
			Image: container.Image,
		}

		// Get resource requests
		if len(container.Resources.Requests) > 0 {
			containerInfo.Requests = make(map[string]string)
			for name, qty := range container.Resources.Requests {
				containerInfo.Requests[string(name)] = qty.String()
			}
		}

		// Get resource limits
		if len(container.Resources.Limits) > 0 {
			containerInfo.Limits = make(map[string]string)
			for name, qty := range container.Resources.Limits {
				containerInfo.Limits[string(name)] = qty.String()
			}
		}

		// Get container status if available
		if cs, ok := containerStatusMap[container.Name]; ok {
			containerInfo.Ready = cs.Ready
			containerInfo.Restarts = cs.RestartCount
			containerInfo.State = getContainerState(cs.State)
		} else {
			containerInfo.State = "Unknown"
		}

		info.Containers = append(info.Containers, containerInfo)
	}

	return info
}

func getPodStatus(pod *corev1.Pod) string {
	// Check for deletion
	if pod.DeletionTimestamp != nil {
		return "Terminating"
	}

	// Check container statuses for more specific reasons
	for _, cs := range pod.Status.ContainerStatuses {
		if cs.State.Waiting != nil && cs.State.Waiting.Reason != "" {
			return cs.State.Waiting.Reason
		}
		if cs.State.Terminated != nil && cs.State.Terminated.Reason != "" {
			return cs.State.Terminated.Reason
		}
	}

	// Fall back to pod phase
	return string(pod.Status.Phase)
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

func getContainerState(state corev1.ContainerState) string {
	if state.Running != nil {
		return "Running"
	}
	if state.Waiting != nil {
		if state.Waiting.Reason != "" {
			return fmt.Sprintf("Waiting: %s", state.Waiting.Reason)
		}
		return "Waiting"
	}
	if state.Terminated != nil {
		if state.Terminated.Reason != "" {
			return fmt.Sprintf("Terminated: %s", state.Terminated.Reason)
		}
		return "Terminated"
	}
	return "Unknown"
}
