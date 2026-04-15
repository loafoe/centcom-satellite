// Package pv_resize_status provides PVC resize status checking functionality.
package pv_resize_status

import (
	"context"
	"encoding/json"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/loafoe/pico-agent/internal/task"
)

const TaskName = "pv_resize_status"

// Payload for pv_resize_status task.
type Payload struct {
	Namespace string `json:"namespace"`
	PVCName   string `json:"pvc_name"`
}

// ResizeStatus contains detailed status of a PVC resize operation.
type ResizeStatus struct {
	Namespace string `json:"namespace"`
	PVCName   string `json:"pvc_name"`
	PVName    string `json:"pv_name,omitempty"`

	// Phase indicates the current state of the resize
	Phase string `json:"phase"` // "ready", "resizing", "fs_expansion_pending", "error"

	// Sizes at different levels
	PVCSpecSize     string `json:"pvc_spec_size"`      // What the PVC requests
	PVCapacitySize  string `json:"pv_capacity_size"`   // What the PV reports
	PVCStatusSize   string `json:"pvc_status_size"`    // What the PVC status shows
	FilesystemSize  string `json:"filesystem_size"`    // Actual filesystem size from kubelet
	FilesystemUsed  string `json:"filesystem_used"`    // Bytes used
	FilesystemAvail string `json:"filesystem_avail"`   // Bytes available
	UsagePercent    float64 `json:"usage_percent"`     // Current usage percentage

	// Storage class info
	StorageClass       string `json:"storage_class,omitempty"`
	AllowsExpansion    bool   `json:"allows_expansion"`

	// Conditions
	Conditions []ConditionInfo `json:"conditions,omitempty"`

	// Human-readable message
	Message string `json:"message"`
}

// ConditionInfo contains PVC condition details.
type ConditionInfo struct {
	Type    string `json:"type"`
	Status  string `json:"status"`
	Reason  string `json:"reason,omitempty"`
	Message string `json:"message,omitempty"`
}

// KubeletStatsSummary for parsing kubelet stats.
type KubeletStatsSummary struct {
	Pods []PodStats `json:"pods"`
}

type PodStats struct {
	PodRef  PodReference  `json:"podRef"`
	Volume  []VolumeStats `json:"volume,omitempty"`
}

type PodReference struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
}

type VolumeStats struct {
	Name           string  `json:"name"`
	PVCRef         *PVCRef `json:"pvcRef,omitempty"`
	CapacityBytes  int64   `json:"capacityBytes"`
	UsedBytes      int64   `json:"usedBytes"`
	AvailableBytes int64   `json:"availableBytes"`
}

type PVCRef struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
}

// Task handles PVC resize status checks.
type Task struct {
	clientset kubernetes.Interface
}

// New creates a new pv_resize_status task.
func New(clientset kubernetes.Interface) *Task {
	return &Task{clientset: clientset}
}

// Name returns the task type identifier.
func (t *Task) Name() string {
	return TaskName
}

// Execute checks the resize status of a PVC.
func (t *Task) Execute(ctx context.Context, rawPayload json.RawMessage) (*task.Result, error) {
	var payload Payload
	if len(rawPayload) == 0 || string(rawPayload) == "{}" {
		return task.NewErrorResult("namespace and pvc_name are required"), nil
	}
	if err := json.Unmarshal(rawPayload, &payload); err != nil {
		return task.NewErrorResult(fmt.Sprintf("invalid payload: %v", err)), nil
	}
	if payload.Namespace == "" || payload.PVCName == "" {
		return task.NewErrorResult("namespace and pvc_name are required"), nil
	}

	status := &ResizeStatus{
		Namespace: payload.Namespace,
		PVCName:   payload.PVCName,
	}

	// Get the PVC
	pvc, err := t.clientset.CoreV1().PersistentVolumeClaims(payload.Namespace).Get(ctx, payload.PVCName, metav1.GetOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			return task.NewErrorResult(fmt.Sprintf("PVC not found: %s/%s", payload.Namespace, payload.PVCName)), nil
		}
		return nil, fmt.Errorf("failed to get PVC: %w", err)
	}

	// Get sizes from PVC
	if specSize, ok := pvc.Spec.Resources.Requests[corev1.ResourceStorage]; ok {
		status.PVCSpecSize = specSize.String()
	}
	if statusSize, ok := pvc.Status.Capacity[corev1.ResourceStorage]; ok {
		status.PVCStatusSize = statusSize.String()
	}

	// Get PV name and capacity
	if pvc.Spec.VolumeName != "" {
		status.PVName = pvc.Spec.VolumeName
		pv, err := t.clientset.CoreV1().PersistentVolumes().Get(ctx, pvc.Spec.VolumeName, metav1.GetOptions{})
		if err == nil {
			if cap, ok := pv.Spec.Capacity[corev1.ResourceStorage]; ok {
				status.PVCapacitySize = cap.String()
			}
		}
	}

	// Get storage class info
	if pvc.Spec.StorageClassName != nil && *pvc.Spec.StorageClassName != "" {
		status.StorageClass = *pvc.Spec.StorageClassName
		sc, err := t.clientset.StorageV1().StorageClasses().Get(ctx, *pvc.Spec.StorageClassName, metav1.GetOptions{})
		if err == nil && sc.AllowVolumeExpansion != nil {
			status.AllowsExpansion = *sc.AllowVolumeExpansion
		}
	}

	// Get conditions
	status.Phase = "ready"
	for _, cond := range pvc.Status.Conditions {
		status.Conditions = append(status.Conditions, ConditionInfo{
			Type:    string(cond.Type),
			Status:  string(cond.Status),
			Reason:  cond.Reason,
			Message: cond.Message,
		})

		// Determine phase from conditions
		if cond.Type == corev1.PersistentVolumeClaimResizing && cond.Status == corev1.ConditionTrue {
			status.Phase = "resizing"
		}
		if cond.Type == corev1.PersistentVolumeClaimFileSystemResizePending && cond.Status == corev1.ConditionTrue {
			status.Phase = "fs_expansion_pending"
		}
	}

	// Get filesystem size from kubelet stats
	fsSize, fsUsed, fsAvail := t.getFilesystemStats(ctx, payload.Namespace, payload.PVCName)
	if fsSize > 0 {
		status.FilesystemSize = formatBytes(fsSize)
		status.FilesystemUsed = formatBytes(fsUsed)
		status.FilesystemAvail = formatBytes(fsAvail)
		status.UsagePercent = float64(fsUsed) / float64(fsSize) * 100
	}

	// Build message
	status.Message = t.buildMessage(status)

	return task.NewSuccessResultWithDetails(status.Message, status), nil
}

// getFilesystemStats queries kubelet to get actual filesystem size for the PVC.
func (t *Task) getFilesystemStats(ctx context.Context, namespace, pvcName string) (capacity, used, available int64) {
	// Get all nodes and query their stats
	nodes, err := t.clientset.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return 0, 0, 0
	}

	for _, node := range nodes.Items {
		stats, err := t.getNodeStats(ctx, node.Name)
		if err != nil {
			continue
		}

		for _, pod := range stats.Pods {
			for _, vol := range pod.Volume {
				if vol.PVCRef != nil && vol.PVCRef.Namespace == namespace && vol.PVCRef.Name == pvcName {
					return vol.CapacityBytes, vol.UsedBytes, vol.AvailableBytes
				}
			}
		}
	}

	return 0, 0, 0
}

func (t *Task) getNodeStats(ctx context.Context, nodeName string) (*KubeletStatsSummary, error) {
	path := fmt.Sprintf("/api/v1/nodes/%s/proxy/stats/summary", nodeName)
	data, err := t.clientset.CoreV1().RESTClient().Get().AbsPath(path).DoRaw(ctx)
	if err != nil {
		return nil, err
	}

	var stats KubeletStatsSummary
	if err := json.Unmarshal(data, &stats); err != nil {
		return nil, err
	}
	return &stats, nil
}

func (t *Task) buildMessage(s *ResizeStatus) string {
	switch s.Phase {
	case "resizing":
		return fmt.Sprintf("PVC %s/%s is resizing: PVC spec=%s, PV capacity=%s, filesystem=%s",
			s.Namespace, s.PVCName, s.PVCSpecSize, s.PVCapacitySize, s.FilesystemSize)
	case "fs_expansion_pending":
		return fmt.Sprintf("PVC %s/%s volume resized, filesystem expansion pending: PVC spec=%s, PV capacity=%s, filesystem=%s (%.1f%% used). Pod restart may be required.",
			s.Namespace, s.PVCName, s.PVCSpecSize, s.PVCapacitySize, s.FilesystemSize, s.UsagePercent)
	default:
		if s.PVCSpecSize != s.FilesystemSize && s.FilesystemSize != "" {
			return fmt.Sprintf("PVC %s/%s has mismatched sizes: PVC spec=%s, filesystem=%s (%.1f%% used). Resize may be in progress.",
				s.Namespace, s.PVCName, s.PVCSpecSize, s.FilesystemSize, s.UsagePercent)
		}
		return fmt.Sprintf("PVC %s/%s is ready: size=%s, filesystem=%s (%.1f%% used)",
			s.Namespace, s.PVCName, s.PVCSpecSize, s.FilesystemSize, s.UsagePercent)
	}
}

func formatBytes(bytes int64) string {
	const (
		KB = 1024
		MB = KB * 1024
		GB = MB * 1024
	)
	switch {
	case bytes >= GB:
		return fmt.Sprintf("%.2fGi", float64(bytes)/float64(GB))
	case bytes >= MB:
		return fmt.Sprintf("%.2fMi", float64(bytes)/float64(MB))
	case bytes >= KB:
		return fmt.Sprintf("%.2fKi", float64(bytes)/float64(KB))
	default:
		return fmt.Sprintf("%d", bytes)
	}
}
