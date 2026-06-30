// Package list_namespaces provides namespace listing functionality.
package list_namespaces

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/loafoe/centcom-satellite/internal/task"
)

const TaskName = "list_namespaces"

// Payload contains optional parameters for the list_namespaces task.
type Payload struct {
	IncludeMetadata bool `json:"include_metadata"`
}

// NamespaceList contains the namespace listing.
type NamespaceList struct {
	Total      int             `json:"total"`
	Namespaces []NamespaceInfo `json:"namespaces"`
}

// NamespaceInfo contains namespace details.
type NamespaceInfo struct {
	Name        string            `json:"name"`
	Status      string            `json:"status"`
	Age         string            `json:"age"`
	Labels      map[string]string `json:"labels,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty"`
}

// Task handles namespace listing.
type Task struct {
	clientset kubernetes.Interface
}

// New creates a new list namespaces task.
func New(clientset kubernetes.Interface) *Task {
	return &Task{clientset: clientset}
}

// Name returns the task type identifier.
func (t *Task) Name() string {
	return TaskName
}

// Execute lists all namespaces.
func (t *Task) Execute(ctx context.Context, payload json.RawMessage) (*task.Result, error) {
	var params Payload
	if len(payload) > 0 {
		_ = json.Unmarshal(payload, &params)
	}

	namespaces, err := t.clientset.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list namespaces: %w", err)
	}

	result := &NamespaceList{
		Total:      len(namespaces.Items),
		Namespaces: make([]NamespaceInfo, 0, len(namespaces.Items)),
	}

	for i := range namespaces.Items {
		ns := &namespaces.Items[i]
		info := NamespaceInfo{
			Name:   ns.Name,
			Status: string(ns.Status.Phase),
			Age:    formatAge(ns.CreationTimestamp.Time),
		}

		if params.IncludeMetadata {
			info.Labels = copyLabels(ns.Labels)
			info.Annotations = filterAnnotations(ns.Annotations)
		}

		result.Namespaces = append(result.Namespaces, info)
	}

	// Sort alphabetically
	sort.Slice(result.Namespaces, func(i, j int) bool {
		return result.Namespaces[i].Name < result.Namespaces[j].Name
	})

	return task.NewSuccessResultWithDetails(
		fmt.Sprintf("Found %d namespaces", result.Total),
		result,
	), nil
}

// copyLabels returns a copy of the labels map, or empty map if nil.
func copyLabels(labels map[string]string) map[string]string {
	if labels == nil {
		return map[string]string{}
	}
	result := make(map[string]string, len(labels))
	for k, v := range labels {
		result[k] = v
	}
	return result
}

// filterAnnotations returns annotations with noisy keys filtered out.
func filterAnnotations(annotations map[string]string) map[string]string {
	if annotations == nil {
		return map[string]string{}
	}
	result := make(map[string]string)
	for k, v := range annotations {
		if shouldExcludeAnnotation(k) {
			continue
		}
		result[k] = v
	}
	return result
}

// shouldExcludeAnnotation returns true for annotations that bloat responses.
func shouldExcludeAnnotation(key string) bool {
	if key == "kubectl.kubernetes.io/last-applied-configuration" {
		return true
	}
	lower := strings.ToLower(key)
	if strings.Contains(lower, "last-applied") || strings.Contains(lower, "managed-fields") {
		return true
	}
	return false
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
