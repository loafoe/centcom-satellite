// Package list_configmaps provides ConfigMap metadata listing functionality.
//
// This task returns metadata only — names, namespaces, key names, per-key data
// sizes, and age. It never returns ConfigMap values. Use the get_configmap task
// (which redacts secret-looking values) to read values.
package list_configmaps

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/loafoe/pico-agent/internal/task"
)

const TaskName = "list_configmaps"

// Payload contains optional parameters for the list_configmaps task.
type Payload struct {
	Namespace     string `json:"namespace,omitempty"`
	LabelSelector string `json:"label_selector,omitempty"`
}

// ConfigMapList contains the ConfigMap metadata listing.
type ConfigMapList struct {
	Total      int             `json:"total"`
	ConfigMaps []ConfigMapInfo `json:"configmaps"`
}

// ConfigMapInfo contains ConfigMap metadata. Values are intentionally excluded.
type ConfigMapInfo struct {
	Name      string            `json:"name"`
	Namespace string            `json:"namespace"`
	Keys      []string          `json:"keys"`
	DataSizes map[string]int    `json:"data_sizes"`
	Age       string            `json:"age"`
	Labels    map[string]string `json:"labels,omitempty"`
}

// Task handles ConfigMap metadata listing.
type Task struct {
	clientset kubernetes.Interface
}

// New creates a new list configmaps task.
func New(clientset kubernetes.Interface) *Task {
	return &Task{clientset: clientset}
}

// Name returns the task type identifier.
func (t *Task) Name() string {
	return TaskName
}

// Execute lists ConfigMap metadata in a namespace (or all namespaces).
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

	configmaps, err := t.clientset.CoreV1().ConfigMaps(namespace).List(ctx, listOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to list configmaps: %w", err)
	}

	result := &ConfigMapList{
		Total:      len(configmaps.Items),
		ConfigMaps: make([]ConfigMapInfo, 0, len(configmaps.Items)),
	}

	for i := range configmaps.Items {
		cm := &configmaps.Items[i]
		info := ConfigMapInfo{
			Name:      cm.Name,
			Namespace: cm.Namespace,
			Keys:      make([]string, 0, len(cm.Data)+len(cm.BinaryData)),
			DataSizes: make(map[string]int, len(cm.Data)+len(cm.BinaryData)),
			Age:       formatAge(cm.CreationTimestamp.Time),
			Labels:    copyLabels(cm.Labels),
		}
		for k, v := range cm.Data {
			info.Keys = append(info.Keys, k)
			info.DataSizes[k] = len(v)
		}
		for k, v := range cm.BinaryData {
			info.Keys = append(info.Keys, k)
			info.DataSizes[k] = len(v)
		}
		sort.Strings(info.Keys)
		result.ConfigMaps = append(result.ConfigMaps, info)
	}

	// Sort by namespace then name
	sort.Slice(result.ConfigMaps, func(i, j int) bool {
		if result.ConfigMaps[i].Namespace != result.ConfigMaps[j].Namespace {
			return result.ConfigMaps[i].Namespace < result.ConfigMaps[j].Namespace
		}
		return result.ConfigMaps[i].Name < result.ConfigMaps[j].Name
	})

	msg := fmt.Sprintf("Found %d configmaps in namespace %s", result.Total, namespace)
	if namespace == metav1.NamespaceAll {
		msg = fmt.Sprintf("Found %d configmaps across all namespaces", result.Total)
	}

	return task.NewSuccessResultWithDetails(msg, result), nil
}

// copyLabels returns a copy of the labels map, or nil if empty.
func copyLabels(labels map[string]string) map[string]string {
	if len(labels) == 0 {
		return nil
	}
	result := make(map[string]string, len(labels))
	for k, v := range labels {
		result[k] = v
	}
	return result
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
