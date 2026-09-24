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

	"github.com/loafoe/centcom-satellite/internal/config"
	"github.com/loafoe/centcom-satellite/internal/task"
)

const TaskName = "pod_resize"

type Payload struct {
	Namespace string `json:"namespace"`
	Pod       string `json:"pod"`
	Container string `json:"container,omitempty"`
	Resources struct {
		Memory      string `json:"memory,omitempty"`
		MemoryLimit string `json:"memory_limit,omitempty"`
		CPU         string `json:"cpu,omitempty"`
		CPULimit    string `json:"cpu_limit,omitempty"`
	} `json:"resources"`
	DryRun bool `json:"dry_run,omitempty"`
}

type capacityInfo struct {
	Allocatable string `json:"allocatable"`
	Available   string `json:"available"`
}

type Result struct {
	Success            bool          `json:"success"`
	Pod                string        `json:"pod"`
	Container          string        `json:"container"`
	PreviousMemory     string        `json:"previous_memory,omitempty"`
	NewMemory          string        `json:"new_memory,omitempty"`
	PreviousLimit      string        `json:"previous_limit,omitempty"`
	NewLimit           string        `json:"new_limit,omitempty"`
	LimitUpdated       bool          `json:"limit_updated,omitempty"`
	LimitReduced       bool          `json:"limit_reduced,omitempty"`
	CurrentUsage       string        `json:"current_usage,omitempty"`
	NodeMemoryCapacity *capacityInfo `json:"node_memory_capacity,omitempty"`
	PreviousCPU        string        `json:"previous_cpu,omitempty"`
	NewCPU             string        `json:"new_cpu,omitempty"`
	PreviousCPULimit   string        `json:"previous_cpu_limit,omitempty"`
	NewCPULimit        string        `json:"new_cpu_limit,omitempty"`
	CPULimitUpdated    bool          `json:"cpu_limit_updated,omitempty"`
	NodeCPUCapacity    *capacityInfo `json:"node_cpu_capacity,omitempty"`
	Warning            string        `json:"warning,omitempty"`
	DryRun             bool          `json:"dry_run"`
}

// metricsContainer holds container metrics from metrics-server
type metricsContainer struct {
	Name  string `json:"name"`
	Usage struct {
		Memory string `json:"memory"`
	} `json:"usage"`
}

// metricsPod holds pod metrics from metrics-server
type metricsPod struct {
	Metadata struct {
		Name      string `json:"name"`
		Namespace string `json:"namespace"`
	} `json:"metadata"`
	Containers []metricsContainer `json:"containers"`
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

	result := Result{
		Success:   true,
		Pod:       payload.Pod,
		Container: container.Name,
		DryRun:    payload.DryRun,
	}
	var dryRunParts []string
	var appliedParts []string
	var warnings []string
	var newMemory, newMemoryLimit, newCPU, newCPULimit *resource.Quantity

	if payload.Resources.Memory != "" {
		requestedMemory, err := resource.ParseQuantity(payload.Resources.Memory)
		if err != nil {
			return task.NewErrorResult(fmt.Sprintf("invalid memory value: %v", err)), nil
		}

		currentMemory := container.Resources.Requests.Memory()
		if currentMemory == nil || currentMemory.IsZero() {
			return task.NewErrorResult("container has no memory request set"), nil
		}

		if err := t.validateAbsoluteCap(corev1.ResourceMemory, t.config.MemoryAbsoluteCap, &requestedMemory); err != nil {
			return task.NewErrorResult(err.Error()), nil
		}
		if err := t.validateQoSPreservation(pod, corev1.ResourceMemory, container.Resources.Limits.Memory(), &requestedMemory); err != nil {
			return task.NewErrorResult(err.Error()), nil
		}

		nodeCapacity, err := t.checkNodeResourceCapacity(ctx, pod, corev1.ResourceMemory, currentMemory, &requestedMemory)
		if err != nil {
			return task.NewErrorResult(err.Error()), nil
		}
		result.NodeMemoryCapacity = &nodeCapacity

		currentLimit := container.Resources.Limits.Memory()
		var limitUpdated, limitReduced bool
		var previousLimitStr, newLimitStr, currentUsageStr string

		if currentLimit != nil && !currentLimit.IsZero() {
			previousLimitStr = currentLimit.String()
		}

		if payload.Resources.MemoryLimit != "" {
			parsedLimit, err := resource.ParseQuantity(payload.Resources.MemoryLimit)
			if err != nil {
				return task.NewErrorResult(fmt.Sprintf("invalid memory_limit value: %v", err)), nil
			}
			if parsedLimit.Cmp(requestedMemory) < 0 {
				return task.NewErrorResult(fmt.Sprintf("memory_limit (%s) must be >= memory request (%s)",
					parsedLimit.String(), requestedMemory.String())), nil
			}
			if err := t.validateAbsoluteCap(corev1.ResourceMemory, t.config.MemoryAbsoluteCap, &parsedLimit); err != nil {
				return task.NewErrorResult(err.Error()), nil
			}

			if currentLimit != nil && !currentLimit.IsZero() && parsedLimit.Cmp(*currentLimit) < 0 {
				usage, err := t.validateLimitReduction(ctx, payload.Namespace, payload.Pod, container.Name, currentLimit, &parsedLimit)
				if err != nil {
					return task.NewErrorResult(err.Error()), nil
				}
				currentUsageStr = usage.String()
				limitReduced = true
			}

			newMemoryLimit = &parsedLimit
			limitUpdated = true
			newLimitStr = parsedLimit.String()
		} else if currentLimit != nil && !currentLimit.IsZero() && requestedMemory.Cmp(*currentLimit) > 0 {
			newMemoryLimit = &requestedMemory
			limitUpdated = true
			newLimitStr = requestedMemory.String()
		}

		newMemory = &requestedMemory
		result.PreviousMemory = currentMemory.String()
		result.NewMemory = requestedMemory.String()
		result.PreviousLimit = previousLimitStr
		result.NewLimit = newLimitStr
		result.LimitUpdated = limitUpdated
		result.LimitReduced = limitReduced
		result.CurrentUsage = currentUsageStr

		dryRunParts = append(dryRunParts, fmt.Sprintf("memory %s -> %s", currentMemory.String(), requestedMemory.String()))
		appliedParts = append(appliedParts, fmt.Sprintf("memory %s -> %s", currentMemory.String(), requestedMemory.String()))
		if limitReduced {
			warnings = append(warnings, "memory limit was REDUCED - monitor for OOM")
		} else if limitUpdated {
			dryRunParts[len(dryRunParts)-1] += fmt.Sprintf(" (limit: %s -> %s)", previousLimitStr, newLimitStr)
			appliedParts[len(appliedParts)-1] += fmt.Sprintf(" (limit: %s -> %s)", previousLimitStr, newLimitStr)
		}
	}

	if payload.Resources.CPU != "" {
		requestedCPU, err := resource.ParseQuantity(payload.Resources.CPU)
		if err != nil {
			return task.NewErrorResult(fmt.Sprintf("invalid cpu value: %v", err)), nil
		}

		currentCPU := container.Resources.Requests.Cpu()
		if currentCPU == nil || currentCPU.IsZero() {
			return task.NewErrorResult("container has no cpu request set"), nil
		}

		if err := t.validateAbsoluteCap(corev1.ResourceCPU, t.config.CPUAbsoluteCap, &requestedCPU); err != nil {
			return task.NewErrorResult(err.Error()), nil
		}
		if err := t.validateQoSPreservation(pod, corev1.ResourceCPU, container.Resources.Limits.Cpu(), &requestedCPU); err != nil {
			return task.NewErrorResult(err.Error()), nil
		}

		nodeCapacity, err := t.checkNodeResourceCapacity(ctx, pod, corev1.ResourceCPU, currentCPU, &requestedCPU)
		if err != nil {
			return task.NewErrorResult(err.Error()), nil
		}
		result.NodeCPUCapacity = &nodeCapacity

		currentLimit := container.Resources.Limits.Cpu()
		var limitUpdated bool
		var previousLimitStr, newLimitStr string

		if currentLimit != nil && !currentLimit.IsZero() {
			previousLimitStr = currentLimit.String()
		}

		if payload.Resources.CPULimit != "" {
			parsedLimit, err := resource.ParseQuantity(payload.Resources.CPULimit)
			if err != nil {
				return task.NewErrorResult(fmt.Sprintf("invalid cpu_limit value: %v", err)), nil
			}
			if parsedLimit.Cmp(requestedCPU) < 0 {
				return task.NewErrorResult(fmt.Sprintf("cpu_limit (%s) must be >= cpu request (%s)",
					parsedLimit.String(), requestedCPU.String())), nil
			}
			if err := t.validateAbsoluteCap(corev1.ResourceCPU, t.config.CPUAbsoluteCap, &parsedLimit); err != nil {
				return task.NewErrorResult(err.Error()), nil
			}

			newCPULimit = &parsedLimit
			limitUpdated = true
			newLimitStr = parsedLimit.String()
		} else if currentLimit != nil && !currentLimit.IsZero() && requestedCPU.Cmp(*currentLimit) > 0 {
			newCPULimit = &requestedCPU
			limitUpdated = true
			newLimitStr = requestedCPU.String()
		}

		newCPU = &requestedCPU
		result.PreviousCPU = currentCPU.String()
		result.NewCPU = requestedCPU.String()
		result.PreviousCPULimit = previousLimitStr
		result.NewCPULimit = newLimitStr
		result.CPULimitUpdated = limitUpdated

		part := fmt.Sprintf("cpu %s -> %s", currentCPU.String(), requestedCPU.String())
		if limitUpdated {
			part += fmt.Sprintf(" (limit: %s -> %s)", previousLimitStr, newLimitStr)
		}
		dryRunParts = append(dryRunParts, part)
		appliedParts = append(appliedParts, part)
	}

	warning := "resize is ephemeral until pod restart"
	for _, w := range warnings {
		warning += "; " + w
	}
	result.Warning = warning

	if payload.DryRun {
		msg := fmt.Sprintf("Dry-run: would resize %s/%s container %s: %s",
			payload.Namespace, payload.Pod, container.Name, joinParts(dryRunParts))
		return task.NewSuccessResultWithDetails(msg, result), nil
	}

	if err := t.resizePod(ctx, payload.Namespace, payload.Pod, containerIdx, newMemory, newMemoryLimit, newCPU, newCPULimit); err != nil {
		return nil, fmt.Errorf("failed to resize pod: %w", err)
	}

	msg := fmt.Sprintf("Resized %s/%s container %s: %s (ephemeral until pod restart)",
		payload.Namespace, payload.Pod, container.Name, joinParts(appliedParts))
	return task.NewSuccessResultWithDetails(msg, result), nil
}

func joinParts(parts []string) string {
	out := ""
	for i, p := range parts {
		if i > 0 {
			out += ", "
		}
		out += p
	}
	return out
}

func (t *Task) validatePayload(payload *Payload) error {
	if payload.Namespace == "" {
		return fmt.Errorf("namespace is required")
	}
	if payload.Pod == "" {
		return fmt.Errorf("pod is required")
	}
	if payload.Resources.Memory == "" && payload.Resources.CPU == "" {
		return fmt.Errorf("at least one of resources.memory or resources.cpu is required")
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

// validateAbsoluteCap enforces the hard ceiling for a resize request. There is no
// percentage-based cap on top of it - the absolute cap (20Gi memory / 2 CPU by
// default) is the only limit, regardless of the container's current size.
func (t *Task) validateAbsoluteCap(resourceName corev1.ResourceName, capValue string, requested *resource.Quantity) error {
	absoluteCap, err := resource.ParseQuantity(capValue)
	if err != nil {
		return fmt.Errorf("invalid absolute cap config for %s: %v", resourceName, err)
	}
	if requested.Cmp(absoluteCap) > 0 {
		return fmt.Errorf("exceeds absolute cap for %s: max %s, requested %s",
			resourceName, absoluteCap.String(), requested.String())
	}
	return nil
}

// validateQoSPreservation blocks a resize that would flip a Guaranteed pod to Burstable
// by making a container's request diverge from its limit for the given resource.
func (t *Task) validateQoSPreservation(pod *corev1.Pod, resourceName corev1.ResourceName, currentLimit, requested *resource.Quantity) error {
	if !t.isGuaranteed(pod) {
		return nil
	}
	if currentLimit != nil && !currentLimit.IsZero() && requested.Cmp(*currentLimit) != 0 {
		return fmt.Errorf("resize would change QoS class from Guaranteed to Burstable (%s request %s != limit %s)",
			resourceName, requested.String(), currentLimit.String())
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

// checkNodeResourceCapacity verifies the node has room for a resize delta in the given
// resource (memory or cpu), summing that resource's requests across all pods on the node.
func (t *Task) checkNodeResourceCapacity(ctx context.Context, pod *corev1.Pod, resourceName corev1.ResourceName, current, requested *resource.Quantity) (capacityInfo, error) {
	var result capacityInfo

	if pod.Spec.NodeName == "" {
		return result, fmt.Errorf("pod is not scheduled to a node")
	}

	node, err := t.clientset.CoreV1().Nodes().Get(ctx, pod.Spec.NodeName, metav1.GetOptions{})
	if err != nil {
		return result, fmt.Errorf("failed to get node: %w", err)
	}

	allocatable := node.Status.Allocatable[resourceName]
	if allocatable.IsZero() {
		return result, fmt.Errorf("node has no allocatable %s", resourceName)
	}

	// Sum requests of all pods on this node for this resource
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
			if q, ok := c.Resources.Requests[resourceName]; ok {
				totalRequests += q.Value()
			}
		}
	}

	delta := requested.Value() - current.Value()
	available := allocatable.Value() - totalRequests

	result.Allocatable = allocatable.String()
	result.Available = resource.NewQuantity(available, resource.BinarySI).String()

	if delta > available {
		return result, fmt.Errorf("node %s has insufficient %s capacity: %s available, %s needed",
			node.Name, resourceName, result.Available, resource.NewQuantity(delta, resource.BinarySI).String())
	}

	return result, nil
}

func (t *Task) resizePod(ctx context.Context, namespace, podName string, containerIdx int, memory, memoryLimit, cpu, cpuLimit *resource.Quantity) error {
	// Get the pod first to get the actual container name
	pod, err := t.clientset.CoreV1().Pods(namespace).Get(ctx, podName, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("failed to get pod for resize: %w", err)
	}

	if containerIdx < 0 || containerIdx >= len(pod.Spec.Containers) {
		return fmt.Errorf("container index %d out of range", containerIdx)
	}

	containerName := pod.Spec.Containers[containerIdx].Name

	requests := map[string]string{}
	limits := map[string]string{}
	if memory != nil {
		requests["memory"] = memory.String()
	}
	if memoryLimit != nil {
		limits["memory"] = memoryLimit.String()
	}
	if cpu != nil {
		requests["cpu"] = cpu.String()
	}
	if cpuLimit != nil {
		limits["cpu"] = cpuLimit.String()
	}

	resources := map[string]any{}
	if len(requests) > 0 {
		resources["requests"] = requests
	}
	if len(limits) > 0 {
		resources["limits"] = limits
	}
	patch := map[string]any{
		"spec": map[string]any{
			"containers": []map[string]any{
				{"name": containerName, "resources": resources},
			},
		},
	}
	patchData, err := json.Marshal(patch)
	if err != nil {
		return fmt.Errorf("failed to build resize patch: %w", err)
	}

	// Use the resize subresource (KEP-1287)
	_, err = t.clientset.CoreV1().Pods(namespace).Patch(ctx, podName, types.StrategicMergePatchType, patchData, metav1.PatchOptions{}, "resize")
	return err
}

// getContainerMemoryUsage fetches current memory usage for a container from metrics-server
func (t *Task) getContainerMemoryUsage(ctx context.Context, namespace, podName, containerName string) (*resource.Quantity, error) {
	path := fmt.Sprintf("/apis/metrics.k8s.io/v1beta1/namespaces/%s/pods/%s", namespace, podName)

	data, err := t.clientset.CoreV1().RESTClient().Get().
		AbsPath(path).
		DoRaw(ctx)
	if err != nil {
		return nil, fmt.Errorf("metrics API request failed (is metrics-server installed?): %w", err)
	}

	var metrics metricsPod
	if err := json.Unmarshal(data, &metrics); err != nil {
		return nil, fmt.Errorf("failed to parse metrics response: %w", err)
	}

	for _, c := range metrics.Containers {
		if c.Name == containerName {
			usage, err := resource.ParseQuantity(c.Usage.Memory)
			if err != nil {
				return nil, fmt.Errorf("failed to parse memory usage: %w", err)
			}
			return &usage, nil
		}
	}

	return nil, fmt.Errorf("container %q not found in metrics", containerName)
}

// validateLimitReduction checks if reducing the limit is safe based on actual usage
func (t *Task) validateLimitReduction(ctx context.Context, namespace, podName, containerName string, currentLimit, newLimit *resource.Quantity) (*resource.Quantity, error) {
	// Fetch current usage from metrics
	usage, err := t.getContainerMemoryUsage(ctx, namespace, podName, containerName)
	if err != nil {
		return nil, fmt.Errorf("cannot reduce limit without metrics: %w", err)
	}

	// Calculate minimum safe limit: usage + 20% buffer
	buffer := t.config.ShrinkBuffer
	if buffer == 0 {
		buffer = 20 // default 20%
	}
	minSafeLimit := usage.DeepCopy()
	minSafeLimit.Add(*resource.NewQuantity(usage.Value()*int64(buffer)/100, resource.BinarySI))

	if newLimit.Cmp(minSafeLimit) < 0 {
		return usage, fmt.Errorf("new limit %s is below safe minimum %s (current usage %s + %d%% buffer)",
			newLimit.String(), minSafeLimit.String(), usage.String(), buffer)
	}

	return usage, nil
}
