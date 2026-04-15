// Package pv_usage provides PVC disk usage metrics from kubelet stats.
package pv_usage

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/loafoe/pico-agent/internal/task"
)

const TaskName = "pv_usage"

// Payload for pv_usage task.
type Payload struct {
	// Namespace filters to a specific namespace (default: all namespaces)
	Namespace string `json:"namespace,omitempty"`
	// ThresholdPercent only returns PVCs above this usage percentage (default: 0)
	ThresholdPercent int `json:"threshold_percent,omitempty"`
}

// UsageReport contains the PVC usage summary.
type UsageReport struct {
	Summary      string      `json:"summary"`
	TotalPVCs    int         `json:"total_pvcs"`
	WithMetrics  int         `json:"with_metrics"`
	HighUsage    int         `json:"high_usage"`
	PVCUsages    []PVCUsage  `json:"pvc_usages"`
	NodesQueried int         `json:"nodes_queried"`
	NodeErrors   []NodeError `json:"node_errors,omitempty"`
}

// PVCUsage contains usage information for a single PVC.
type PVCUsage struct {
	Namespace      string  `json:"namespace"`
	Name           string  `json:"name"`
	CapacityBytes  int64   `json:"capacity_bytes"`
	UsedBytes      int64   `json:"used_bytes"`
	AvailableBytes int64   `json:"available_bytes"`
	UsagePercent   float64 `json:"usage_percent"`
	Inodes         int64   `json:"inodes,omitempty"`
	InodesUsed     int64   `json:"inodes_used,omitempty"`
	InodesFree     int64   `json:"inodes_free,omitempty"`
	InodesPercent  float64 `json:"inodes_percent,omitempty"`
	PodName        string  `json:"pod_name"`
	PodNamespace   string  `json:"pod_namespace"`
	VolumeName     string  `json:"volume_name"`
}

// NodeError contains error information for a node that couldn't be queried.
type NodeError struct {
	Node  string `json:"node"`
	Error string `json:"error"`
}

// KubeletStatsSummary represents the kubelet stats/summary response.
type KubeletStatsSummary struct {
	Pods []PodStats `json:"pods"`
}

// PodStats represents pod-level stats from kubelet.
type PodStats struct {
	PodRef  PodReference  `json:"podRef"`
	Volume  []VolumeStats `json:"volume,omitempty"`
}

// PodReference identifies a pod.
type PodReference struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
}

// VolumeStats represents volume stats from kubelet.
type VolumeStats struct {
	Name           string    `json:"name"`
	PVCRef         *PVCRef   `json:"pvcRef,omitempty"`
	CapacityBytes  int64     `json:"capacityBytes"`
	UsedBytes      int64     `json:"usedBytes"`
	AvailableBytes int64     `json:"availableBytes"`
	Inodes         int64     `json:"inodes"`
	InodesUsed     int64     `json:"inodesUsed"`
	InodesFree     int64     `json:"inodesFree"`
}

// PVCRef references a PVC.
type PVCRef struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
}

// Task handles PVC usage checks.
type Task struct {
	clientset kubernetes.Interface
}

// New creates a new pv_usage task.
func New(clientset kubernetes.Interface) *Task {
	return &Task{clientset: clientset}
}

// Name returns the task type identifier.
func (t *Task) Name() string {
	return TaskName
}

// Execute performs the PVC usage check.
func (t *Task) Execute(ctx context.Context, rawPayload json.RawMessage) (*task.Result, error) {
	var payload Payload
	if len(rawPayload) > 0 && string(rawPayload) != "{}" {
		if err := json.Unmarshal(rawPayload, &payload); err != nil {
			return task.NewErrorResult(fmt.Sprintf("invalid payload: %v", err)), nil
		}
	}

	report := &UsageReport{}

	// Get all nodes
	nodes, err := t.clientset.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list nodes: %w", err)
	}

	// Map to deduplicate PVCs (same PVC might be mounted on multiple pods)
	pvcUsageMap := make(map[string]*PVCUsage)

	// Query each node's kubelet stats
	for _, node := range nodes.Items {
		report.NodesQueried++

		stats, err := t.getNodeStats(ctx, node.Name)
		if err != nil {
			report.NodeErrors = append(report.NodeErrors, NodeError{
				Node:  node.Name,
				Error: err.Error(),
			})
			continue
		}

		// Extract PVC usage from pod volumes
		for _, pod := range stats.Pods {
			for _, vol := range pod.Volume {
				if vol.PVCRef == nil {
					continue
				}

				// Filter by namespace if specified
				if payload.Namespace != "" && vol.PVCRef.Namespace != payload.Namespace {
					continue
				}

				key := vol.PVCRef.Namespace + "/" + vol.PVCRef.Name

				// Calculate usage percentage
				var usagePercent float64
				if vol.CapacityBytes > 0 {
					usagePercent = float64(vol.UsedBytes) / float64(vol.CapacityBytes) * 100
				}

				// Calculate inode percentage
				var inodesPercent float64
				if vol.Inodes > 0 {
					inodesPercent = float64(vol.InodesUsed) / float64(vol.Inodes) * 100
				}

				// Only store if we haven't seen this PVC or if this has higher usage
				if existing, ok := pvcUsageMap[key]; !ok || usagePercent > existing.UsagePercent {
					pvcUsageMap[key] = &PVCUsage{
						Namespace:      vol.PVCRef.Namespace,
						Name:           vol.PVCRef.Name,
						CapacityBytes:  vol.CapacityBytes,
						UsedBytes:      vol.UsedBytes,
						AvailableBytes: vol.AvailableBytes,
						UsagePercent:   usagePercent,
						Inodes:         vol.Inodes,
						InodesUsed:     vol.InodesUsed,
						InodesFree:     vol.InodesFree,
						InodesPercent:  inodesPercent,
						PodName:        pod.PodRef.Name,
						PodNamespace:   pod.PodRef.Namespace,
						VolumeName:     vol.Name,
					}
				}
			}
		}
	}

	// Convert map to slice and filter by threshold
	for _, usage := range pvcUsageMap {
		if payload.ThresholdPercent > 0 && usage.UsagePercent < float64(payload.ThresholdPercent) {
			continue
		}
		report.PVCUsages = append(report.PVCUsages, *usage)
	}

	// Sort by usage percentage descending
	sort.Slice(report.PVCUsages, func(i, j int) bool {
		return report.PVCUsages[i].UsagePercent > report.PVCUsages[j].UsagePercent
	})

	// Count totals
	report.WithMetrics = len(pvcUsageMap)
	for _, usage := range report.PVCUsages {
		if usage.UsagePercent >= 80 {
			report.HighUsage++
		}
	}

	// Get total PVC count for reference
	pvcList, err := t.clientset.CoreV1().PersistentVolumeClaims(payload.Namespace).List(ctx, metav1.ListOptions{})
	if err == nil {
		report.TotalPVCs = len(pvcList.Items)
	}

	// Build summary
	report.Summary = t.buildSummary(report)

	return task.NewSuccessResultWithDetails(report.Summary, report), nil
}

// getNodeStats fetches the stats/summary from a node's kubelet via API server proxy.
func (t *Task) getNodeStats(ctx context.Context, nodeName string) (*KubeletStatsSummary, error) {
	// Use the API server proxy to reach the kubelet
	path := fmt.Sprintf("/api/v1/nodes/%s/proxy/stats/summary", nodeName)

	data, err := t.clientset.CoreV1().RESTClient().Get().
		AbsPath(path).
		DoRaw(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get stats from node %s: %w", nodeName, err)
	}

	var stats KubeletStatsSummary
	if err := json.Unmarshal(data, &stats); err != nil {
		return nil, fmt.Errorf("failed to parse stats from node %s: %w", nodeName, err)
	}

	return &stats, nil
}

func (t *Task) buildSummary(report *UsageReport) string {
	if report.HighUsage > 0 {
		return fmt.Sprintf("PVC usage: %d/%d PVCs with metrics, %d at >=80%% usage",
			report.WithMetrics, report.TotalPVCs, report.HighUsage)
	}
	return fmt.Sprintf("PVC usage: %d/%d PVCs with metrics, all healthy",
		report.WithMetrics, report.TotalPVCs)
}
