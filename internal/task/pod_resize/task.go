package pod_resize

import (
	"context"
	"encoding/json"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"

	"github.com/loafoe/pico-agent/internal/config"
	"github.com/loafoe/pico-agent/internal/task"
)

const TaskName = "pod_resize"

type Payload struct {
	Namespace string `json:"namespace"`
	Pod       string `json:"pod"`
	Container string `json:"container,omitempty"`
	Resources struct {
		Memory      string `json:"memory,omitempty"`
		MemoryLimit string `json:"memory_limit,omitempty"`
	} `json:"resources"`
	DryRun bool `json:"dry_run,omitempty"`
}

type Result struct {
	Success         bool   `json:"success"`
	Pod             string `json:"pod"`
	Container       string `json:"container"`
	PreviousMemory  string `json:"previous_memory"`
	NewMemory       string `json:"new_memory"`
	PreviousLimit   string `json:"previous_limit,omitempty"`
	NewLimit        string `json:"new_limit,omitempty"`
	LimitUpdated    bool   `json:"limit_updated,omitempty"`
	NodeCapacity    struct {
		Allocatable string `json:"allocatable"`
		Available   string `json:"available"`
	} `json:"node_capacity"`
	Warning string `json:"warning,omitempty"`
	DryRun  bool   `json:"dry_run"`
}

type Task struct {
	clientset kubernetes.Interface
	config    config.PodResizeConfig
}

func New(clientset kubernetes.Interface, cfg config.PodResizeConfig) *Task {
	return &Task{
		clientset: clientset,
		config:    cfg,
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

	// Get the pod
	pod, err := t.clientset.CoreV1().Pods(payload.Namespace).Get(ctx, payload.Pod, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to get pod: %w", err)
	}

	// Find container
	containerIdx, container := t.findContainer(pod, payload.Container)
	if container == nil {
		return task.NewErrorResult(fmt.Sprintf("container %q not found in pod", payload.Container)), nil
	}

	// Parse requested memory
	requestedMemory, err := resource.ParseQuantity(payload.Resources.Memory)
	if err != nil {
		return task.NewErrorResult(fmt.Sprintf("invalid memory value: %v", err)), nil
	}

	// Get current memory
	currentMemory := container.Resources.Requests.Memory()
	if currentMemory == nil || currentMemory.IsZero() {
		return task.NewErrorResult("container has no memory request set"), nil
	}

	// Validate safety rails
	if err := t.validateSafetyRails(pod, container, currentMemory, &requestedMemory); err != nil {
		return task.NewErrorResult(err.Error()), nil
	}

	// Check node capacity
	nodeCapacity, err := t.checkNodeCapacity(ctx, pod, currentMemory, &requestedMemory)
	if err != nil {
		return task.NewErrorResult(err.Error()), nil
	}

	// Determine memory limit to set
	currentLimit := container.Resources.Limits.Memory()
	var newLimit *resource.Quantity
	var limitUpdated bool
	var previousLimitStr, newLimitStr string

	if currentLimit != nil && !currentLimit.IsZero() {
		previousLimitStr = currentLimit.String()
	}

	if payload.Resources.MemoryLimit != "" {
		// Explicit limit requested
		parsedLimit, err := resource.ParseQuantity(payload.Resources.MemoryLimit)
		if err != nil {
			return task.NewErrorResult(fmt.Sprintf("invalid memory_limit value: %v", err)), nil
		}
		// Validate limit >= request
		if parsedLimit.Cmp(requestedMemory) < 0 {
			return task.NewErrorResult(fmt.Sprintf("memory_limit (%s) must be >= memory request (%s)",
				parsedLimit.String(), requestedMemory.String())), nil
		}
		newLimit = &parsedLimit
		limitUpdated = true
		newLimitStr = parsedLimit.String()
	} else if currentLimit != nil && !currentLimit.IsZero() && requestedMemory.Cmp(*currentLimit) > 0 {
		// Auto-update limit when request exceeds it
		newLimit = &requestedMemory
		limitUpdated = true
		newLimitStr = requestedMemory.String()
	}

	// Build warning message
	warning := "resize is ephemeral until pod restart"
	if limitUpdated {
		warning = "resize is ephemeral until pod restart; memory limit was also updated"
	}

	// Build result
	result := Result{
		Success:        true,
		Pod:            payload.Pod,
		Container:      container.Name,
		PreviousMemory: currentMemory.String(),
		NewMemory:      requestedMemory.String(),
		PreviousLimit:  previousLimitStr,
		NewLimit:       newLimitStr,
		LimitUpdated:   limitUpdated,
		NodeCapacity:   nodeCapacity,
		Warning:        warning,
		DryRun:         payload.DryRun,
	}

	if payload.DryRun {
		msg := fmt.Sprintf("Dry-run: would resize %s/%s container %s from %s to %s",
			payload.Namespace, payload.Pod, container.Name, currentMemory.String(), requestedMemory.String())
		if limitUpdated {
			msg += fmt.Sprintf(" (limit: %s -> %s)", previousLimitStr, newLimitStr)
		}
		return task.NewSuccessResultWithDetails(msg, result), nil
	}

	// Perform the resize
	if err := t.resizePod(ctx, payload.Namespace, payload.Pod, containerIdx, &requestedMemory, newLimit); err != nil {
		return nil, fmt.Errorf("failed to resize pod: %w", err)
	}

	msg := fmt.Sprintf("Resized %s/%s container %s from %s to %s (ephemeral until pod restart)",
		payload.Namespace, payload.Pod, container.Name, currentMemory.String(), requestedMemory.String())
	if limitUpdated {
		msg += fmt.Sprintf(" - limit: %s -> %s", previousLimitStr, newLimitStr)
	}
	return task.NewSuccessResultWithDetails(msg, result), nil
}

func (t *Task) validatePayload(payload *Payload) error {
	if payload.Namespace == "" {
		return fmt.Errorf("namespace is required")
	}
	if payload.Pod == "" {
		return fmt.Errorf("pod is required")
	}
	if payload.Resources.Memory == "" {
		return fmt.Errorf("resources.memory is required")
	}
	return nil
}

func (t *Task) findContainer(pod *corev1.Pod, name string) (int, *corev1.Container) {
	for i := range pod.Spec.Containers {
		c := &pod.Spec.Containers[i]
		if name == "" || c.Name == name {
			return i, c
		}
	}
	return -1, nil
}

func (t *Task) validateSafetyRails(pod *corev1.Pod, container *corev1.Container, current, requested *resource.Quantity) error {
	currentLimit := container.Resources.Limits.Memory()

	// Percentage cap only applies when going ABOVE the current limit.
	// If a limit exists and request is within it, the pod was already approved for that usage.
	// The cap prevents runaway increases beyond what's already sanctioned.
	if currentLimit == nil || currentLimit.IsZero() || requested.Cmp(*currentLimit) > 0 {
		maxAllowed := current.DeepCopy()
		maxAllowed.Add(*resource.NewQuantity(current.Value()*int64(t.config.PercentageCap)/100, resource.BinarySI))
		if requested.Cmp(maxAllowed) > 0 {
			return fmt.Errorf("exceeds percentage cap (%d%%): max %s, requested %s",
				t.config.PercentageCap, maxAllowed.String(), requested.String())
		}
	}

	// Check absolute cap (always applies)
	absoluteCap, err := resource.ParseQuantity(t.config.AbsoluteCap)
	if err != nil {
		return fmt.Errorf("invalid absolute cap config: %v", err)
	}
	if requested.Cmp(absoluteCap) > 0 {
		return fmt.Errorf("exceeds absolute cap: max %s, requested %s",
			absoluteCap.String(), requested.String())
	}

	// Check QoS preservation
	if t.isGuaranteed(pod) {
		memLimit := container.Resources.Limits.Memory()
		if memLimit != nil && !memLimit.IsZero() && requested.Cmp(*memLimit) != 0 {
			return fmt.Errorf("resize would change QoS class from Guaranteed to Burstable (request %s != limit %s)",
				requested.String(), memLimit.String())
		}
	}

	return nil
}

func (t *Task) isGuaranteed(pod *corev1.Pod) bool {
	for _, c := range pod.Spec.Containers {
		cpuReq := c.Resources.Requests.Cpu()
		cpuLim := c.Resources.Limits.Cpu()
		memReq := c.Resources.Requests.Memory()
		memLim := c.Resources.Limits.Memory()

		if cpuReq == nil || cpuLim == nil || cpuReq.Cmp(*cpuLim) != 0 {
			return false
		}
		if memReq == nil || memLim == nil || memReq.Cmp(*memLim) != 0 {
			return false
		}
	}
	return true
}

func (t *Task) checkNodeCapacity(ctx context.Context, pod *corev1.Pod, current, requested *resource.Quantity) (struct {
	Allocatable string `json:"allocatable"`
	Available   string `json:"available"`
}, error) {
	var result struct {
		Allocatable string `json:"allocatable"`
		Available   string `json:"available"`
	}

	if pod.Spec.NodeName == "" {
		return result, fmt.Errorf("pod is not scheduled to a node")
	}

	node, err := t.clientset.CoreV1().Nodes().Get(ctx, pod.Spec.NodeName, metav1.GetOptions{})
	if err != nil {
		return result, fmt.Errorf("failed to get node: %w", err)
	}

	allocatable := node.Status.Allocatable.Memory()
	if allocatable == nil {
		return result, fmt.Errorf("node has no allocatable memory")
	}

	// Sum memory requests of all pods on this node
	pods, err := t.clientset.CoreV1().Pods(metav1.NamespaceAll).List(ctx, metav1.ListOptions{
		FieldSelector: fmt.Sprintf("spec.nodeName=%s", pod.Spec.NodeName),
	})
	if err != nil {
		return result, fmt.Errorf("failed to list pods on node: %w", err)
	}

	var totalRequests int64
	for _, p := range pods.Items {
		if p.Status.Phase == corev1.PodSucceeded || p.Status.Phase == corev1.PodFailed {
			continue
		}
		for _, c := range p.Spec.Containers {
			if mem := c.Resources.Requests.Memory(); mem != nil {
				totalRequests += mem.Value()
			}
		}
	}

	delta := requested.Value() - current.Value()
	available := allocatable.Value() - totalRequests

	result.Allocatable = allocatable.String()
	result.Available = resource.NewQuantity(available, resource.BinarySI).String()

	if delta > available {
		return result, fmt.Errorf("node %s has insufficient capacity: %s available, %s needed",
			node.Name, result.Available, resource.NewQuantity(delta, resource.BinarySI).String())
	}

	return result, nil
}

func (t *Task) resizePod(ctx context.Context, namespace, podName string, containerIdx int, memory, memoryLimit *resource.Quantity) error {
	// Get the pod first to get the actual container name
	pod, err := t.clientset.CoreV1().Pods(namespace).Get(ctx, podName, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("failed to get pod for resize: %w", err)
	}

	if containerIdx < 0 || containerIdx >= len(pod.Spec.Containers) {
		return fmt.Errorf("container index %d out of range", containerIdx)
	}

	containerName := pod.Spec.Containers[containerIdx].Name

	var patchData string
	if memoryLimit != nil {
		// Update both request and limit
		patchData = fmt.Sprintf(`{"spec":{"containers":[{"name":"%s","resources":{"requests":{"memory":"%s"},"limits":{"memory":"%s"}}}]}}`,
			containerName, memory.String(), memoryLimit.String())
	} else {
		// Only update request
		patchData = fmt.Sprintf(`{"spec":{"containers":[{"name":"%s","resources":{"requests":{"memory":"%s"}}}]}}`,
			containerName, memory.String())
	}

	// Use the resize subresource (KEP-1287)
	_, err = t.clientset.CoreV1().Pods(namespace).Patch(ctx, podName, types.StrategicMergePatchType, []byte(patchData), metav1.PatchOptions{}, "resize")
	return err
}
