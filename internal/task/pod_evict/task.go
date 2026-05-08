package pod_evict

import (
	"context"
	"encoding/json"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/loafoe/pico-agent/internal/task"
)

const (
	TaskName          = "pod_evict"
	NoEvictAnnotation = "picoclaw.io/no-evict"
	DefaultGracePeriod = int64(30)
)

type Payload struct {
	Namespace          string `json:"namespace"`
	PodName            string `json:"pod_name"`
	GracePeriodSeconds *int64 `json:"grace_period_seconds"`
	Force              bool   `json:"force"`
	Immediate          bool   `json:"immediate"`
	DryRun             bool   `json:"dry_run"`
}

type EvictDetails struct {
	DryRun       bool   `json:"dry_run,omitempty"`
	Method       string `json:"method"`
	GracePeriod  int64  `json:"grace_period_seconds"`
	OwnerKind    string `json:"owner_kind,omitempty"`
	OwnerName    string `json:"owner_name,omitempty"`
	WillRecreate bool   `json:"will_recreate"`
	Warning      string `json:"warning,omitempty"`
}

type Task struct {
	clientset kubernetes.Interface
}

func New(clientset kubernetes.Interface) *Task {
	return &Task{
		clientset: clientset,
	}
}

func (t *Task) Name() string {
	return TaskName
}

func (t *Task) Execute(ctx context.Context, rawPayload json.RawMessage) (*task.Result, error) {
	var payload Payload
	if len(rawPayload) > 0 && string(rawPayload) != "{}" {
		if err := json.Unmarshal(rawPayload, &payload); err != nil {
			return task.NewErrorResult(fmt.Sprintf("invalid payload: %v", err)), nil
		}
	}

	if err := t.validatePayload(&payload); err != nil {
		return task.NewErrorResult(err.Error()), nil
	}

	// Check namespace annotation
	namespace, err := t.clientset.CoreV1().Namespaces().Get(ctx, payload.Namespace, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to get namespace: %w", err)
	}
	if namespace.Annotations != nil {
		if _, exists := namespace.Annotations[NoEvictAnnotation]; exists {
			return task.NewErrorResult(fmt.Sprintf("namespace %s has %s annotation, eviction not allowed", payload.Namespace, NoEvictAnnotation)), nil
		}
	}

	// Get pod
	pod, err := t.clientset.CoreV1().Pods(payload.Namespace).Get(ctx, payload.PodName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to get pod: %w", err)
	}

	// Check pod annotation
	if pod.Annotations != nil {
		if _, exists := pod.Annotations[NoEvictAnnotation]; exists {
			return task.NewErrorResult(fmt.Sprintf("pod %s/%s has %s annotation, eviction not allowed", payload.Namespace, payload.PodName, NoEvictAnnotation)), nil
		}
	}

	// Extract owner info
	ownerKind, ownerName, hasController := t.getOwnerInfo(pod)

	// Determine grace period
	gracePeriod := DefaultGracePeriod
	if payload.Immediate {
		gracePeriod = 0
	} else if payload.GracePeriodSeconds != nil {
		gracePeriod = *payload.GracePeriodSeconds
	}

	// Determine method
	method := "eviction"
	if payload.Force {
		method = "delete"
	}

	// Build result
	result := EvictDetails{
		DryRun:       payload.DryRun,
		Method:       method,
		GracePeriod:  gracePeriod,
		OwnerKind:    ownerKind,
		OwnerName:    ownerName,
		WillRecreate: hasController,
	}

	if !hasController {
		result.Warning = "Bare pod - will not be recreated after eviction"
	}

	// Handle dry-run
	if payload.DryRun {
		return task.NewSuccessResultWithDetails(fmt.Sprintf("Dry-run: would %s pod %s/%s with %ds grace period", result.Method, payload.Namespace, payload.PodName, result.GracePeriod), result), nil
	}

	// Execute eviction or deletion
	if payload.Force {
		if err := t.deletePod(ctx, payload.Namespace, payload.PodName, gracePeriod); err != nil {
			return nil, fmt.Errorf("failed to delete pod: %w", err)
		}
	} else {
		if err := t.evictPod(ctx, payload.Namespace, payload.PodName, gracePeriod); err != nil {
			return nil, fmt.Errorf("failed to evict pod: %w", err)
		}
	}

	message := fmt.Sprintf("Successfully %s pod %s/%s", result.Method+"ed", payload.Namespace, payload.PodName)
	if result.Warning != "" {
		message += " (Warning: " + result.Warning + ")"
	}

	return task.NewSuccessResultWithDetails(message, result), nil
}

func (t *Task) validatePayload(payload *Payload) error {
	if payload.Namespace == "" {
		return fmt.Errorf("namespace is required")
	}
	if payload.PodName == "" {
		return fmt.Errorf("pod_name is required")
	}
	if payload.GracePeriodSeconds != nil && *payload.GracePeriodSeconds < 0 {
		return fmt.Errorf("grace_period_seconds must be >= 0")
	}
	return nil
}

func (t *Task) evictPod(ctx context.Context, namespace, podName string, gracePeriod int64) error {
	eviction := &policyv1.Eviction{
		ObjectMeta: metav1.ObjectMeta{
			Name:      podName,
			Namespace: namespace,
		},
		DeleteOptions: &metav1.DeleteOptions{
			GracePeriodSeconds: &gracePeriod,
		},
	}
	return t.clientset.CoreV1().Pods(namespace).EvictV1(ctx, eviction)
}

func (t *Task) deletePod(ctx context.Context, namespace, podName string, gracePeriod int64) error {
	deleteOptions := metav1.DeleteOptions{
		GracePeriodSeconds: &gracePeriod,
	}
	return t.clientset.CoreV1().Pods(namespace).Delete(ctx, podName, deleteOptions)
}

func (t *Task) getOwnerInfo(pod *corev1.Pod) (kind, name string, hasController bool) {
	for _, ref := range pod.OwnerReferences {
		if ref.Controller != nil && *ref.Controller {
			return ref.Kind, ref.Name, true
		}
	}
	return "", "", false
}
