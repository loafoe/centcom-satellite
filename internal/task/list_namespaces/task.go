// Package list_namespaces provides namespace listing functionality.
package list_namespaces

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

const TaskName = "list_namespaces"

// NamespaceList contains the namespace listing.
type NamespaceList struct {
	Total      int             `json:"total"`
	Namespaces []NamespaceInfo `json:"namespaces"`
}

// NamespaceInfo contains namespace details.
type NamespaceInfo struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Age    string `json:"age"`
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
func (t *Task) Execute(ctx context.Context, _ json.RawMessage) (*task.Result, error) {
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
		result.Namespaces = append(result.Namespaces, NamespaceInfo{
			Name:   ns.Name,
			Status: string(ns.Status.Phase),
			Age:    formatAge(ns.CreationTimestamp.Time),
		})
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
