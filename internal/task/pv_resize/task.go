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
}

// ResizeDetails contains additional information about the resize operation.
type ResizeDetails struct {
	Duration  string `json:"duration,omitempty"`
	FinalSize string `json:"final_size,omitempty"`
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
	if newSize.Cmp(currentSize) <= 0 {
		return task.NewErrorResult(fmt.Sprintf("%s: current=%s, requested=%s",
			ErrSizeMustIncrease, currentSize.String(), newSize.String())), nil
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
