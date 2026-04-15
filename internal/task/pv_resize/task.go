// Package pv_resize provides PersistentVolumeClaim resize functionality.
package pv_resize

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/loafoe/pico-agent/internal/task"
)

const (
	TaskName = "pv_resize"

	// Default timeout for waiting on resize completion
	DefaultWaitTimeout = 5 * time.Minute

	// Poll interval when waiting for resize
	pollInterval = 2 * time.Second
)

var (
	ErrInvalidPayload       = errors.New("invalid payload")
	ErrMissingNamespace     = errors.New("namespace is required")
	ErrMissingPVCName       = errors.New("pvc_name is required")
	ErrMissingNewSize       = errors.New("new_size is required")
	ErrInvalidSize          = errors.New("invalid size format")
	ErrInvalidTimeout       = errors.New("invalid timeout format")
	ErrPVCNotFound          = errors.New("PVC not found")
	ErrExpansionNotAllowed  = errors.New("storage class does not allow volume expansion")
	ErrSizeMustIncrease     = errors.New("new size must be larger than current size")
	ErrStorageClassNotFound = errors.New("storage class not found")
	ErrResizeTimeout        = errors.New("timeout waiting for resize to complete")
	ErrResizeFailed         = errors.New("resize failed")
)

// Payload represents the input for a PV resize operation.
type Payload struct {
	Namespace string `json:"namespace"`
	PVCName   string `json:"pvc_name"`
	NewSize   string `json:"new_size"`
	// Wait indicates whether to wait for the resize to complete
	Wait bool `json:"wait,omitempty"`
	// Timeout is the maximum time to wait for resize (e.g., "5m", "300s")
	// Only used when Wait is true. Defaults to 5m.
	Timeout string `json:"timeout,omitempty"`
	// DryRun validates the resize without actually performing it
	DryRun bool `json:"dry_run,omitempty"`
}

// ResizeDetails contains additional information about the resize operation.
type ResizeDetails struct {
	Duration       string `json:"duration,omitempty"`
	FinalSize      string `json:"final_size,omitempty"`
	DryRun         bool   `json:"dry_run,omitempty"`
	CurrentSize    string `json:"current_size,omitempty"`
	RequestedSize  string `json:"requested_size,omitempty"`
	FilesystemSize string `json:"filesystem_size,omitempty"`
	StorageClass   string `json:"storage_class,omitempty"`
}

// Task handles PVC resize operations.
type Task struct {
	clientset kubernetes.Interface
}

// New creates a new PV resize task.
func New(clientset kubernetes.Interface) *Task {
	return &Task{clientset: clientset}
}

// Name returns the task type identifier.
func (t *Task) Name() string {
	return TaskName
}

// Execute performs the PVC resize operation.
func (t *Task) Execute(ctx context.Context, rawPayload json.RawMessage) (*task.Result, error) {
	startTime := time.Now()

	payload, err := t.parsePayload(rawPayload)
	if err != nil {
		return task.NewErrorResult(err.Error()), nil
	}

	if err := t.validatePayload(payload); err != nil {
		return task.NewErrorResult(err.Error()), nil
	}

	newSize, err := resource.ParseQuantity(payload.NewSize)
	if err != nil {
		return task.NewErrorResult(fmt.Sprintf("%s: %v", ErrInvalidSize, err)), nil
	}

	// Parse timeout if waiting
	timeout := DefaultWaitTimeout
	if payload.Wait && payload.Timeout != "" {
		timeout, err = time.ParseDuration(payload.Timeout)
		if err != nil {
			return task.NewErrorResult(fmt.Sprintf("%s: %v", ErrInvalidTimeout, err)), nil
		}
	}

	// Get the PVC
	pvc, err := t.clientset.CoreV1().PersistentVolumeClaims(payload.Namespace).Get(ctx, payload.PVCName, metav1.GetOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			return task.NewErrorResult(fmt.Sprintf("%s: %s/%s", ErrPVCNotFound, payload.Namespace, payload.PVCName)), nil
		}
		return nil, fmt.Errorf("failed to get PVC: %w", err)
	}

	// Check if expansion is allowed
	if err := t.checkExpansionAllowed(ctx, pvc); err != nil {
		return task.NewErrorResult(err.Error()), nil
	}

	// Verify new size is larger
	currentSize := pvc.Spec.Resources.Requests[corev1.ResourceStorage]

	// Get filesystem size for better error messages
	fsSize := t.getFilesystemSize(ctx, payload.Namespace, payload.PVCName)
	storageClassName := ""
	if pvc.Spec.StorageClassName != nil {
		storageClassName = *pvc.Spec.StorageClassName
	}

	if newSize.Cmp(currentSize) <= 0 {
		// Build helpful error message with filesystem info
		errMsg := fmt.Sprintf("%s: PVC spec=%s, requested=%s",
			ErrSizeMustIncrease, currentSize.String(), newSize.String())
		if fsSize != "" && fsSize != currentSize.String() {
			errMsg += fmt.Sprintf(". Note: filesystem is %s (expansion may be pending, pod restart might help)", fsSize)
		} else if fsSize != "" {
			errMsg += fmt.Sprintf(". Filesystem: %s", fsSize)
		}
		return task.NewErrorResult(errMsg), nil
	}

	// Handle dry-run mode
	if payload.DryRun {
		details := ResizeDetails{
			DryRun:         true,
			CurrentSize:    currentSize.String(),
			RequestedSize:  newSize.String(),
			FilesystemSize: fsSize,
			StorageClass:   storageClassName,
		}
		return task.NewSuccessResultWithDetails(
			fmt.Sprintf("[DRY-RUN] Would resize PVC %s/%s from %s to %s (storage class: %s, allows expansion: true)",
				payload.Namespace, payload.PVCName, currentSize.String(), newSize.String(), storageClassName),
			details,
		), nil
	}

	// Update the PVC
	pvc.Spec.Resources.Requests[corev1.ResourceStorage] = newSize

	_, err = t.clientset.CoreV1().PersistentVolumeClaims(payload.Namespace).Update(ctx, pvc, metav1.UpdateOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to update PVC: %w", err)
	}

	slog.Info("PVC resize initiated",
		"namespace", payload.Namespace,
		"pvc", payload.PVCName,
		"old_size", currentSize.String(),
		"new_size", newSize.String(),
		"wait", payload.Wait,
	)

	// If not waiting, return immediately
	if !payload.Wait {
		return task.NewSuccessResult(fmt.Sprintf("PVC %s/%s resize from %s to %s initiated",
			payload.Namespace, payload.PVCName, currentSize.String(), newSize.String())), nil
	}

	// Wait for resize to complete
	finalSize, err := t.waitForResize(ctx, payload.Namespace, payload.PVCName, newSize, timeout)
	if err != nil {
		return task.NewErrorResult(fmt.Sprintf("resize initiated but %v", err)), nil
	}

	duration := time.Since(startTime)

	slog.Info("PVC resize completed",
		"namespace", payload.Namespace,
		"pvc", payload.PVCName,
		"old_size", currentSize.String(),
		"new_size", finalSize.String(),
		"duration", duration.String(),
	)

	return task.NewSuccessResultWithDetails(
		fmt.Sprintf("PVC %s/%s resized from %s to %s",
			payload.Namespace, payload.PVCName, currentSize.String(), finalSize.String()),
		ResizeDetails{
			Duration:  duration.Round(time.Millisecond).String(),
			FinalSize: finalSize.String(),
		},
	), nil
}

// waitForResize polls the PVC until the resize completes or times out.
func (t *Task) waitForResize(ctx context.Context, namespace, name string, targetSize resource.Quantity, timeout time.Duration) (resource.Quantity, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return resource.Quantity{}, fmt.Errorf("%w: %v", ErrResizeTimeout, ctx.Err())
		case <-ticker.C:
			pvc, err := t.clientset.CoreV1().PersistentVolumeClaims(namespace).Get(ctx, name, metav1.GetOptions{})
			if err != nil {
				slog.Warn("failed to get PVC while waiting", "error", err)
				continue
			}

			// Check for resize failure conditions
			for _, condition := range pvc.Status.Conditions {
				if condition.Type == corev1.PersistentVolumeClaimFileSystemResizePending {
					// Filesystem resize pending - volume expanded but fs not yet
					slog.Debug("filesystem resize pending", "pvc", name)
				}
				if condition.Type == corev1.PersistentVolumeClaimResizing && condition.Status == corev1.ConditionFalse {
					// Check for failure
					if condition.Reason == "ResizeFailed" {
						return resource.Quantity{}, fmt.Errorf("%w: %s", ErrResizeFailed, condition.Message)
					}
				}
			}

			// Check if capacity has been updated to target size
			currentCapacity := pvc.Status.Capacity[corev1.ResourceStorage]
			if currentCapacity.Cmp(targetSize) >= 0 {
				return currentCapacity, nil
			}

			slog.Debug("waiting for resize",
				"pvc", name,
				"current_capacity", currentCapacity.String(),
				"target_size", targetSize.String(),
			)
		}
	}
}

func (t *Task) parsePayload(rawPayload json.RawMessage) (*Payload, error) {
	if len(rawPayload) == 0 {
		return nil, ErrInvalidPayload
	}

	var payload Payload
	if err := json.Unmarshal(rawPayload, &payload); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidPayload, err)
	}

	return &payload, nil
}

func (t *Task) validatePayload(p *Payload) error {
	if p.Namespace == "" {
		return ErrMissingNamespace
	}
	if p.PVCName == "" {
		return ErrMissingPVCName
	}
	if p.NewSize == "" {
		return ErrMissingNewSize
	}
	return nil
}

func (t *Task) checkExpansionAllowed(ctx context.Context, pvc *corev1.PersistentVolumeClaim) error {
	if pvc.Spec.StorageClassName == nil || *pvc.Spec.StorageClassName == "" {
		// No storage class specified - check if inline expansion is blocked
		// For simplicity, we allow expansion if no storage class is set
		return nil
	}

	sc, err := t.clientset.StorageV1().StorageClasses().Get(ctx, *pvc.Spec.StorageClassName, metav1.GetOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			return fmt.Errorf("%w: %s", ErrStorageClassNotFound, *pvc.Spec.StorageClassName)
		}
		return fmt.Errorf("failed to get storage class: %w", err)
	}

	if sc.AllowVolumeExpansion == nil || !*sc.AllowVolumeExpansion {
		return fmt.Errorf("%w: %s", ErrExpansionNotAllowed, *pvc.Spec.StorageClassName)
	}

	return nil
}

// getFilesystemSize queries kubelet to get actual filesystem size for the PVC.
func (t *Task) getFilesystemSize(ctx context.Context, namespace, pvcName string) string {
	nodes, err := t.clientset.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return ""
	}

	for _, node := range nodes.Items {
		stats, err := t.getNodeStats(ctx, node.Name)
		if err != nil {
			continue
		}

		for _, pod := range stats.Pods {
			for _, vol := range pod.Volume {
				if vol.PVCRef != nil && vol.PVCRef.Namespace == namespace && vol.PVCRef.Name == pvcName {
					return formatBytes(vol.CapacityBytes)
				}
			}
		}
	}

	return ""
}

func (t *Task) getNodeStats(ctx context.Context, nodeName string) (*kubeletStatsSummary, error) {
	path := fmt.Sprintf("/api/v1/nodes/%s/proxy/stats/summary", nodeName)
	data, err := t.clientset.CoreV1().RESTClient().Get().AbsPath(path).DoRaw(ctx)
	if err != nil {
		return nil, err
	}

	var stats kubeletStatsSummary
	if err := json.Unmarshal(data, &stats); err != nil {
		return nil, err
	}
	return &stats, nil
}

// kubelet stats types
type kubeletStatsSummary struct {
	Pods []podStats `json:"pods"`
}

type podStats struct {
	PodRef  podReference  `json:"podRef"`
	Volume  []volumeStats `json:"volume,omitempty"`
}

type podReference struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
}

type volumeStats struct {
	Name           string  `json:"name"`
	PVCRef         *pvcRef `json:"pvcRef,omitempty"`
	CapacityBytes  int64   `json:"capacityBytes"`
	UsedBytes      int64   `json:"usedBytes"`
	AvailableBytes int64   `json:"availableBytes"`
}

type pvcRef struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
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
