// Package list_pvcs provides PVC listing functionality.
package list_pvcs

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

const TaskName = "list_pvcs"

// Payload for list_pvcs task.
type Payload struct {
	Namespace     string `json:"namespace,omitempty"`
	LabelSelector string `json:"label_selector,omitempty"`
}

// PVCList contains the PVC listing.
type PVCList struct {
	Total int       `json:"total"`
	PVCs  []PVCInfo `json:"pvcs"`
}

// PVCInfo contains PVC details.
type PVCInfo struct {
	Name             string   `json:"name"`
	Namespace        string   `json:"namespace"`
	Status           string   `json:"status"`
	Capacity         string   `json:"capacity"`
	CapacityBytes    int64    `json:"capacity_bytes"`
	RequestedSize    string   `json:"requested_size"`
	StorageClass     string   `json:"storage_class,omitempty"`
	AccessModes      []string `json:"access_modes"`
	VolumeName       string   `json:"volume_name,omitempty"`
	VolumeMode       string   `json:"volume_mode,omitempty"`
	Age              string   `json:"age"`
	CreationTime     string   `json:"creation_time"`
}

// Task handles PVC listing.
type Task struct {
	clientset kubernetes.Interface
}

// New creates a new list PVCs task.
func New(clientset kubernetes.Interface) *Task {
	return &Task{clientset: clientset}
}

// Name returns the task type identifier.
func (t *Task) Name() string {
	return TaskName
}

// Execute lists PVCs in a namespace.
func (t *Task) Execute(ctx context.Context, rawPayload json.RawMessage) (*task.Result, error) {
	var payload Payload
	if len(rawPayload) > 0 && string(rawPayload) != "{}" {
		if err := json.Unmarshal(rawPayload, &payload); err != nil {
			return task.NewErrorResult(fmt.Sprintf("invalid payload: %v", err)), nil
		}
	}

	namespace := payload.Namespace
	if namespace == "" {
		namespace = metav1.NamespaceAll
	}

	listOpts := metav1.ListOptions{}
	if payload.LabelSelector != "" {
		listOpts.LabelSelector = payload.LabelSelector
	}

	pvcs, err := t.clientset.CoreV1().PersistentVolumeClaims(namespace).List(ctx, listOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to list PVCs: %w", err)
	}

	result := &PVCList{
		Total: len(pvcs.Items),
		PVCs:  make([]PVCInfo, 0, len(pvcs.Items)),
	}

	for i := range pvcs.Items {
		pvc := &pvcs.Items[i]
		result.PVCs = append(result.PVCs, t.buildPVCInfo(pvc))
	}

	// Sort by namespace, then name
	sort.Slice(result.PVCs, func(i, j int) bool {
		if result.PVCs[i].Namespace != result.PVCs[j].Namespace {
			return result.PVCs[i].Namespace < result.PVCs[j].Namespace
		}
		return result.PVCs[i].Name < result.PVCs[j].Name
	})

	msg := fmt.Sprintf("Found %d PVCs in namespace %s", result.Total, namespace)
	if namespace == metav1.NamespaceAll {
		msg = fmt.Sprintf("Found %d PVCs across all namespaces", result.Total)
	}
	return task.NewSuccessResultWithDetails(msg, result), nil
}

func (t *Task) buildPVCInfo(pvc *corev1.PersistentVolumeClaim) PVCInfo {
	info := PVCInfo{
		Name:         pvc.Name,
		Namespace:    pvc.Namespace,
		Status:       string(pvc.Status.Phase),
		Age:          formatAge(pvc.CreationTimestamp.Time),
		CreationTime: pvc.CreationTimestamp.Format(time.RFC3339),
	}

	// Storage class
	if pvc.Spec.StorageClassName != nil {
		info.StorageClass = *pvc.Spec.StorageClassName
	}

	// Access modes
	for _, mode := range pvc.Spec.AccessModes {
		info.AccessModes = append(info.AccessModes, string(mode))
	}

	// Volume mode
	if pvc.Spec.VolumeMode != nil {
		info.VolumeMode = string(*pvc.Spec.VolumeMode)
	}

	// Volume name (if bound)
	info.VolumeName = pvc.Spec.VolumeName

	// Requested size from spec
	if req, ok := pvc.Spec.Resources.Requests[corev1.ResourceStorage]; ok {
		info.RequestedSize = req.String()
	}

	// Actual capacity from status (available when bound)
	if capacity, ok := pvc.Status.Capacity[corev1.ResourceStorage]; ok {
		info.Capacity = capacity.String()
		info.CapacityBytes = capacity.Value()
	} else if info.RequestedSize != "" {
		// Fall back to requested size if capacity not yet set
		info.Capacity = info.RequestedSize
		if req, ok := pvc.Spec.Resources.Requests[corev1.ResourceStorage]; ok {
			info.CapacityBytes = req.Value()
		}
	}

	return info
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
