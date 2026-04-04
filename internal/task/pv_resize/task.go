// Package pv_resize provides PersistentVolumeClaim resize functionality.
package pv_resize

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/loafoe/pico-agent/internal/task"
)

const TaskName = "pv_resize"

var (
	ErrInvalidPayload       = errors.New("invalid payload")
	ErrMissingNamespace     = errors.New("namespace is required")
	ErrMissingPVCName       = errors.New("pvc_name is required")
	ErrMissingNewSize       = errors.New("new_size is required")
	ErrInvalidSize          = errors.New("invalid size format")
	ErrPVCNotFound          = errors.New("PVC not found")
	ErrExpansionNotAllowed  = errors.New("storage class does not allow volume expansion")
	ErrSizeMustIncrease     = errors.New("new size must be larger than current size")
	ErrStorageClassNotFound = errors.New("storage class not found")
)

// Payload represents the input for a PV resize operation.
type Payload struct {
	Namespace string `json:"namespace"`
	PVCName   string `json:"pvc_name"`
	NewSize   string `json:"new_size"`
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
	)

	return task.NewSuccessResult(fmt.Sprintf("PVC %s/%s resize from %s to %s initiated",
		payload.Namespace, payload.PVCName, currentSize.String(), newSize.String())), nil
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
