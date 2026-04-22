// Package pod_resource_usage provides pod CPU/memory usage vs limits.
package pod_resource_usage

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/loafoe/pico-agent/internal/task"
)

const TaskName = "pod_resource_usage"

type Payload struct {
	Namespace        string `json:"namespace"`
	ThresholdPercent int    `json:"threshold_percent,omitempty"`
	Resource         string `json:"resource,omitempty"`
}

type UsageReport struct {
	Summary   string         `json:"summary"`
	Total     int            `json:"total"`
	HighUsage int            `json:"high_usage"`
	Pods      []PodUsageInfo `json:"pods"`
}

type PodUsageInfo struct {
	Namespace      string               `json:"namespace"`
	Pod            string               `json:"pod"`
	MemoryUsage    string               `json:"memory_usage"`
	MemoryLimit    string               `json:"memory_limit"`
	MemoryPercent  float64              `json:"memory_percent"`
	CPUUsage       string               `json:"cpu_usage"`
	CPULimit       string               `json:"cpu_limit"`
	CPUPercent     float64              `json:"cpu_percent"`
	Containers     []ContainerUsageInfo `json:"containers,omitempty"`
}

type ContainerUsageInfo struct {
	Name          string  `json:"name"`
	MemoryUsage   string  `json:"memory_usage"`
	MemoryLimit   string  `json:"memory_limit"`
	MemoryPercent float64 `json:"memory_percent"`
	CPUUsage      string  `json:"cpu_usage"`
	CPULimit      string  `json:"cpu_limit"`
	CPUPercent    float64 `json:"cpu_percent"`
}

type MetricsPodList struct {
	Items []MetricsPod `json:"items"`
}

type MetricsPod struct {
	Metadata   MetricsMeta        `json:"metadata"`
	Containers []MetricsContainer `json:"containers"`
}

type MetricsMeta struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
}

type MetricsContainer struct {
	Name  string `json:"name"`
	Usage struct {
		CPU    string `json:"cpu"`
		Memory string `json:"memory"`
	} `json:"usage"`
}

type Task struct {
	clientset kubernetes.Interface
}

func New(clientset kubernetes.Interface) *Task {
	return &Task{clientset: clientset}
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

	if payload.Namespace == "" {
		return task.NewErrorResult("namespace is required"), nil
	}

	if payload.Resource == "" {
		payload.Resource = "all"
	}

	metrics, err := t.getPodMetrics(ctx, payload.Namespace)
	if err != nil {
		return nil, fmt.Errorf("failed to get pod metrics: %w", err)
	}

	pods, err := t.clientset.CoreV1().Pods(payload.Namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list pods: %w", err)
	}

	type containerLimits struct {
		cpuLimit  resource.Quantity
		memLimit  resource.Quantity
		hasCPU    bool
		hasMemory bool
	}
	limitMap := make(map[string]*containerLimits)
	for i := range pods.Items {
		pod := &pods.Items[i]
		for j := range pod.Spec.Containers {
			c := &pod.Spec.Containers[j]
			key := pod.Namespace + "/" + pod.Name + "/" + c.Name
			cl := &containerLimits{}
			if cpuLim, ok := c.Resources.Limits[corev1.ResourceCPU]; ok {
				cl.cpuLimit = cpuLim
				cl.hasCPU = true
			}
			if memLim, ok := c.Resources.Limits[corev1.ResourceMemory]; ok {
				cl.memLimit = memLim
				cl.hasMemory = true
			}
			limitMap[key] = cl
		}
	}

	var podUsages []PodUsageInfo
	for _, mp := range metrics.Items {
		podInfo := PodUsageInfo{
			Namespace: mp.Metadata.Namespace,
			Pod:       mp.Metadata.Name,
		}

		var totalCPUUsage, totalCPULimit int64
		var totalMemUsage, totalMemLimit int64
		var hasCPULimit, hasMemLimit bool

		for _, mc := range mp.Containers {
			key := mp.Metadata.Namespace + "/" + mp.Metadata.Name + "/" + mc.Name

			cpuUsage := resource.MustParse(mc.Usage.CPU)
			memUsage := resource.MustParse(mc.Usage.Memory)

			ci := ContainerUsageInfo{
				Name:        mc.Name,
				CPUUsage:    formatCPU(cpuUsage),
				MemoryUsage: formatMemory(memUsage),
			}

			totalCPUUsage += cpuUsage.MilliValue()
			totalMemUsage += memUsage.Value()

			if cl, ok := limitMap[key]; ok {
				if cl.hasCPU {
					hasCPULimit = true
					ci.CPULimit = formatCPU(cl.cpuLimit)
					if cl.cpuLimit.MilliValue() > 0 {
						ci.CPUPercent = float64(cpuUsage.MilliValue()) / float64(cl.cpuLimit.MilliValue()) * 100
					}
					totalCPULimit += cl.cpuLimit.MilliValue()
				}
				if cl.hasMemory {
					hasMemLimit = true
					ci.MemoryLimit = formatMemory(cl.memLimit)
					if cl.memLimit.Value() > 0 {
						ci.MemoryPercent = float64(memUsage.Value()) / float64(cl.memLimit.Value()) * 100
					}
					totalMemLimit += cl.memLimit.Value()
				}
			}

			podInfo.Containers = append(podInfo.Containers, ci)
		}

		podInfo.CPUUsage = formatMilliCPU(totalCPUUsage)
		podInfo.MemoryUsage = formatBytes(totalMemUsage)
		if hasCPULimit && totalCPULimit > 0 {
			podInfo.CPULimit = formatMilliCPU(totalCPULimit)
			podInfo.CPUPercent = float64(totalCPUUsage) / float64(totalCPULimit) * 100
		}
		if hasMemLimit && totalMemLimit > 0 {
			podInfo.MemoryLimit = formatBytes(totalMemLimit)
			podInfo.MemoryPercent = float64(totalMemUsage) / float64(totalMemLimit) * 100
		}

		if payload.ThresholdPercent > 0 {
			threshold := float64(payload.ThresholdPercent)
			switch payload.Resource {
			case "memory":
				if podInfo.MemoryPercent < threshold {
					continue
				}
			case "cpu":
				if podInfo.CPUPercent < threshold {
					continue
				}
			default:
				if podInfo.MemoryPercent < threshold && podInfo.CPUPercent < threshold {
					continue
				}
			}
		}

		podUsages = append(podUsages, podInfo)
	}

	sort.Slice(podUsages, func(i, j int) bool {
		switch payload.Resource {
		case "cpu":
			return podUsages[i].CPUPercent > podUsages[j].CPUPercent
		case "memory":
			return podUsages[i].MemoryPercent > podUsages[j].MemoryPercent
		default:
			maxI := max(podUsages[i].CPUPercent, podUsages[i].MemoryPercent)
			maxJ := max(podUsages[j].CPUPercent, podUsages[j].MemoryPercent)
			return maxI > maxJ
		}
	})

	report := &UsageReport{
		Total: len(podUsages),
		Pods:  podUsages,
	}
	for _, p := range podUsages {
		if p.MemoryPercent >= 80 || p.CPUPercent >= 80 {
			report.HighUsage++
		}
	}

	if report.HighUsage > 0 {
		report.Summary = fmt.Sprintf("%d pods in namespace %s, %d at >=80%% resource usage",
			report.Total, payload.Namespace, report.HighUsage)
	} else {
		report.Summary = fmt.Sprintf("%d pods in namespace %s, all within limits",
			report.Total, payload.Namespace)
	}

	return task.NewSuccessResultWithDetails(report.Summary, report), nil
}

func (t *Task) getPodMetrics(ctx context.Context, namespace string) (*MetricsPodList, error) {
	path := fmt.Sprintf("/apis/metrics.k8s.io/v1beta1/namespaces/%s/pods", namespace)

	data, err := t.clientset.CoreV1().RESTClient().Get().
		AbsPath(path).
		DoRaw(ctx)
	if err != nil {
		return nil, fmt.Errorf("metrics API request failed (is metrics-server installed?): %w", err)
	}

	var metrics MetricsPodList
	if err := json.Unmarshal(data, &metrics); err != nil {
		return nil, fmt.Errorf("failed to parse metrics response: %w", err)
	}

	return &metrics, nil
}

func formatCPU(q resource.Quantity) string {
	return formatMilliCPU(q.MilliValue())
}

func formatMilliCPU(m int64) string {
	if m >= 1000 {
		return fmt.Sprintf("%.1f", float64(m)/1000)
	}
	return fmt.Sprintf("%dm", m)
}

func formatMemory(q resource.Quantity) string {
	return formatBytes(q.Value())
}

func formatBytes(b int64) string {
	const (
		gi = 1024 * 1024 * 1024
		mi = 1024 * 1024
	)
	switch {
	case b >= gi:
		return fmt.Sprintf("%.1fGi", float64(b)/float64(gi))
	case b >= mi:
		return fmt.Sprintf("%.0fMi", float64(b)/float64(mi))
	default:
		return fmt.Sprintf("%dKi", b/1024)
	}
}
