// Package resource_pressure provides cluster resource allocation analysis.
package resource_pressure

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/loafoe/pico-agent/internal/task"
)

const TaskName = "resource_pressure"

// Payload for resource_pressure task.
type Payload struct {
	// TopNamespaces limits the per-namespace breakdown (default: 10)
	TopNamespaces int `json:"top_namespaces,omitempty"`
}

// ResourceReport contains the resource allocation analysis.
type ResourceReport struct {
	Summary            string              `json:"summary"`
	ClusterCapacity    ResourceValues      `json:"cluster_capacity"`
	ClusterAllocatable ResourceValues      `json:"cluster_allocatable"`
	TotalRequests      ResourceValues      `json:"total_requests"`
	TotalLimits        ResourceValues      `json:"total_limits"`
	Utilization        UtilizationPercent  `json:"utilization_percent"`
	PerNamespace       []NamespaceResource `json:"per_namespace"`
	NodePressure       []NodePressure      `json:"node_pressure,omitempty"`
	PendingPods        []PendingPod        `json:"pending_pods,omitempty"`
}

// ResourceValues holds CPU and memory values.
type ResourceValues struct {
	CPU    string `json:"cpu"`
	Memory string `json:"memory"`
}

// UtilizationPercent shows allocation percentages.
type UtilizationPercent struct {
	CPURequests    float64 `json:"cpu_requests"`
	MemoryRequests float64 `json:"memory_requests"`
	CPULimits      float64 `json:"cpu_limits"`
	MemoryLimits   float64 `json:"memory_limits"`
}

// NamespaceResource shows per-namespace resource allocation.
type NamespaceResource struct {
	Namespace string         `json:"namespace"`
	PodCount  int            `json:"pod_count"`
	Requests  ResourceValues `json:"requests"`
	Limits    ResourceValues `json:"limits"`
}

// NodePressure shows nodes with high allocation.
type NodePressure struct {
	Name              string  `json:"name"`
	CPUAllocPercent   float64 `json:"cpu_alloc_percent"`
	MemAllocPercent   float64 `json:"mem_alloc_percent"`
	PodCount          int     `json:"pod_count"`
	PodCapacity       int64   `json:"pod_capacity"`
}

// PendingPod shows pods that can't be scheduled.
type PendingPod struct {
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
	Reason    string `json:"reason,omitempty"`
	Message   string `json:"message,omitempty"`
}

// Task handles resource pressure analysis.
type Task struct {
	clientset kubernetes.Interface
}

// New creates a new resource pressure task.
func New(clientset kubernetes.Interface) *Task {
	return &Task{clientset: clientset}
}

// Name returns the task type identifier.
func (t *Task) Name() string {
	return TaskName
}

// Execute performs the resource pressure analysis.
func (t *Task) Execute(ctx context.Context, rawPayload json.RawMessage) (*task.Result, error) {
	var payload Payload
	if len(rawPayload) > 0 && string(rawPayload) != "{}" {
		if err := json.Unmarshal(rawPayload, &payload); err != nil {
			return task.NewErrorResult(fmt.Sprintf("invalid payload: %v", err)), nil
		}
	}

	if payload.TopNamespaces == 0 {
		payload.TopNamespaces = 10
	}

	report := &ResourceReport{}

	// Get nodes for capacity
	nodes, err := t.clientset.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list nodes: %w", err)
	}

	// Calculate cluster capacity and allocatable
	var totalCapacityCPU, totalCapacityMem int64
	var totalAllocatableCPU, totalAllocatableMem int64
	nodeAllocatable := make(map[string]struct {
		cpu int64
		mem int64
		pods int64
	})

	for _, node := range nodes.Items {
		cpu := node.Status.Capacity.Cpu().MilliValue()
		mem := node.Status.Capacity.Memory().Value()
		totalCapacityCPU += cpu
		totalCapacityMem += mem

		allocCPU := node.Status.Allocatable.Cpu().MilliValue()
		allocMem := node.Status.Allocatable.Memory().Value()
		allocPods := node.Status.Allocatable.Pods().Value()
		totalAllocatableCPU += allocCPU
		totalAllocatableMem += allocMem

		nodeAllocatable[node.Name] = struct {
			cpu int64
			mem int64
			pods int64
		}{allocCPU, allocMem, allocPods}
	}

	report.ClusterCapacity = ResourceValues{
		CPU:    fmt.Sprintf("%dm", totalCapacityCPU),
		Memory: formatBytes(totalCapacityMem),
	}
	report.ClusterAllocatable = ResourceValues{
		CPU:    fmt.Sprintf("%dm", totalAllocatableCPU),
		Memory: formatBytes(totalAllocatableMem),
	}

	// Get all pods
	pods, err := t.clientset.CoreV1().Pods(metav1.NamespaceAll).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list pods: %w", err)
	}

	// Calculate totals and per-namespace
	var totalRequestsCPU, totalRequestsMem int64
	var totalLimitsCPU, totalLimitsMem int64
	nsResources := make(map[string]*struct {
		podCount    int
		requestsCPU int64
		requestsMem int64
		limitsCPU   int64
		limitsMem   int64
	})
	nodeRequests := make(map[string]struct {
		cpu      int64
		mem      int64
		podCount int
	})

	for _, pod := range pods.Items {
		// Skip completed/failed pods
		if pod.Status.Phase == corev1.PodSucceeded || pod.Status.Phase == corev1.PodFailed {
			continue
		}

		// Track pending pods
		if pod.Status.Phase == corev1.PodPending {
			pp := PendingPod{
				Namespace: pod.Namespace,
				Name:      pod.Name,
			}
			for _, cond := range pod.Status.Conditions {
				if cond.Type == corev1.PodScheduled && cond.Status == corev1.ConditionFalse {
					pp.Reason = cond.Reason
					pp.Message = cond.Message
					break
				}
			}
			report.PendingPods = append(report.PendingPods, pp)
		}

		// Initialize namespace tracking
		if nsResources[pod.Namespace] == nil {
			nsResources[pod.Namespace] = &struct {
				podCount    int
				requestsCPU int64
				requestsMem int64
				limitsCPU   int64
				limitsMem   int64
			}{}
		}
		nsResources[pod.Namespace].podCount++

		// Sum container resources
		for _, c := range pod.Spec.Containers {
			reqCPU := c.Resources.Requests.Cpu().MilliValue()
			reqMem := c.Resources.Requests.Memory().Value()
			limCPU := c.Resources.Limits.Cpu().MilliValue()
			limMem := c.Resources.Limits.Memory().Value()

			totalRequestsCPU += reqCPU
			totalRequestsMem += reqMem
			totalLimitsCPU += limCPU
			totalLimitsMem += limMem

			nsResources[pod.Namespace].requestsCPU += reqCPU
			nsResources[pod.Namespace].requestsMem += reqMem
			nsResources[pod.Namespace].limitsCPU += limCPU
			nsResources[pod.Namespace].limitsMem += limMem
		}

		// Track per-node allocation for running pods
		if pod.Spec.NodeName != "" && pod.Status.Phase == corev1.PodRunning {
			nr := nodeRequests[pod.Spec.NodeName]
			nr.podCount++
			for _, c := range pod.Spec.Containers {
				nr.cpu += c.Resources.Requests.Cpu().MilliValue()
				nr.mem += c.Resources.Requests.Memory().Value()
			}
			nodeRequests[pod.Spec.NodeName] = nr
		}
	}

	report.TotalRequests = ResourceValues{
		CPU:    fmt.Sprintf("%dm", totalRequestsCPU),
		Memory: formatBytes(totalRequestsMem),
	}
	report.TotalLimits = ResourceValues{
		CPU:    fmt.Sprintf("%dm", totalLimitsCPU),
		Memory: formatBytes(totalLimitsMem),
	}

	// Calculate utilization percentages
	if totalAllocatableCPU > 0 {
		report.Utilization.CPURequests = float64(totalRequestsCPU) / float64(totalAllocatableCPU) * 100
		report.Utilization.CPULimits = float64(totalLimitsCPU) / float64(totalAllocatableCPU) * 100
	}
	if totalAllocatableMem > 0 {
		report.Utilization.MemoryRequests = float64(totalRequestsMem) / float64(totalAllocatableMem) * 100
		report.Utilization.MemoryLimits = float64(totalLimitsMem) / float64(totalAllocatableMem) * 100
	}

	// Build per-namespace list sorted by CPU requests
	nsList := make([]NamespaceResource, 0, len(nsResources))
	for ns, res := range nsResources {
		nsList = append(nsList, NamespaceResource{
			Namespace: ns,
			PodCount:  res.podCount,
			Requests: ResourceValues{
				CPU:    fmt.Sprintf("%dm", res.requestsCPU),
				Memory: formatBytes(res.requestsMem),
			},
			Limits: ResourceValues{
				CPU:    fmt.Sprintf("%dm", res.limitsCPU),
				Memory: formatBytes(res.limitsMem),
			},
		})
	}
	sort.Slice(nsList, func(i, j int) bool {
		// Sort by CPU requests descending (parse back from string)
		var cpuI, cpuJ int64
		fmt.Sscanf(nsList[i].Requests.CPU, "%dm", &cpuI)
		fmt.Sscanf(nsList[j].Requests.CPU, "%dm", &cpuJ)
		return cpuI > cpuJ
	})
	if len(nsList) > payload.TopNamespaces {
		nsList = nsList[:payload.TopNamespaces]
	}
	report.PerNamespace = nsList

	// Calculate node pressure
	for nodeName, alloc := range nodeAllocatable {
		nr := nodeRequests[nodeName]
		var cpuPercent, memPercent float64
		if alloc.cpu > 0 {
			cpuPercent = float64(nr.cpu) / float64(alloc.cpu) * 100
		}
		if alloc.mem > 0 {
			memPercent = float64(nr.mem) / float64(alloc.mem) * 100
		}
		// Only report nodes with >70% allocation
		if cpuPercent > 70 || memPercent > 70 {
			report.NodePressure = append(report.NodePressure, NodePressure{
				Name:            nodeName,
				CPUAllocPercent: cpuPercent,
				MemAllocPercent: memPercent,
				PodCount:        nr.podCount,
				PodCapacity:     alloc.pods,
			})
		}
	}
	sort.Slice(report.NodePressure, func(i, j int) bool {
		return report.NodePressure[i].CPUAllocPercent > report.NodePressure[j].CPUAllocPercent
	})

	// Build summary
	report.Summary = fmt.Sprintf("Cluster allocation: CPU %.1f%%, Memory %.1f%% of allocatable",
		report.Utilization.CPURequests, report.Utilization.MemoryRequests)

	if len(report.PendingPods) > 0 {
		report.Summary += fmt.Sprintf("; %d pending pods", len(report.PendingPods))
	}
	if len(report.NodePressure) > 0 {
		report.Summary += fmt.Sprintf("; %d nodes under pressure", len(report.NodePressure))
	}

	return task.NewSuccessResultWithDetails(report.Summary, report), nil
}

func formatBytes(bytes int64) string {
	const (
		KB = 1024
		MB = KB * 1024
		GB = MB * 1024
		TB = GB * 1024
	)

	switch {
	case bytes >= TB:
		return fmt.Sprintf("%.2fTi", float64(bytes)/TB)
	case bytes >= GB:
		return fmt.Sprintf("%.2fGi", float64(bytes)/GB)
	case bytes >= MB:
		return fmt.Sprintf("%.2fMi", float64(bytes)/MB)
	case bytes >= KB:
		return fmt.Sprintf("%.2fKi", float64(bytes)/KB)
	default:
		return fmt.Sprintf("%dB", bytes)
	}
}
