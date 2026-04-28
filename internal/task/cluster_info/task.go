// Package cluster_info provides cluster information retrieval functionality.
package cluster_info

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/kubernetes"

	"github.com/loafoe/pico-agent/internal/task"
)

const TaskName = "cluster_info"

// ClusterInfo contains the cluster details.
type ClusterInfo struct {
	Version    VersionInfo `json:"version"`
	Nodes      NodesInfo   `json:"nodes"`
	Capacity   Capacity    `json:"capacity"`
	Namespaces int         `json:"namespaces"`
}

// VersionInfo contains Kubernetes version details.
type VersionInfo struct {
	Server   string `json:"server"`
	Platform string `json:"platform"`
}

// NodesInfo contains node statistics.
type NodesInfo struct {
	Total    int        `json:"total"`
	Ready    int        `json:"ready"`
	NotReady int        `json:"not_ready"`
	Details  []NodeInfo `json:"details"`
}

// NodeInfo contains individual node details.
type NodeInfo struct {
	Name             string   `json:"name"`
	Roles            []string `json:"roles"`
	KubeletVersion   string   `json:"kubelet_version"`
	OS               string   `json:"os"`
	Architecture     string   `json:"architecture"`
	ContainerRuntime string   `json:"container_runtime"`
	Ready            bool     `json:"ready"`
	CPUCapacity      string   `json:"cpu_capacity"`
	MemoryCapacity   string   `json:"memory_capacity"`
	Age              string   `json:"age"`
}

// Capacity contains total cluster capacity.
type Capacity struct {
	CPU    string `json:"cpu"`
	Memory string `json:"memory"`
	Pods   string `json:"pods"`
}

// Task handles cluster info retrieval.
type Task struct {
	clientset       kubernetes.Interface
	discoveryClient discovery.DiscoveryInterface
}

// New creates a new cluster info task.
func New(clientset kubernetes.Interface) *Task {
	return &Task{
		clientset:       clientset,
		discoveryClient: clientset.Discovery(),
	}
}

// Name returns the task type identifier.
func (t *Task) Name() string {
	return TaskName
}

// Execute retrieves cluster information.
func (t *Task) Execute(ctx context.Context, _ json.RawMessage) (*task.Result, error) {
	info := &ClusterInfo{}

	// Get server version
	version, err := t.discoveryClient.ServerVersion()
	if err != nil {
		return nil, fmt.Errorf("failed to get server version: %w", err)
	}
	info.Version = VersionInfo{
		Server:   version.GitVersion,
		Platform: version.Platform,
	}

	// Get nodes
	nodes, err := t.clientset.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list nodes: %w", err)
	}

	info.Nodes = t.processNodes(nodes)
	info.Capacity = t.calculateCapacity(nodes)

	// Get namespace count
	namespaces, err := t.clientset.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list namespaces: %w", err)
	}
	info.Namespaces = len(namespaces.Items)

	return task.NewSuccessResultWithDetails(
		fmt.Sprintf("Cluster running Kubernetes %s with %d nodes (%d ready)",
			info.Version.Server, info.Nodes.Total, info.Nodes.Ready),
		info,
	), nil
}

func (t *Task) processNodes(nodes *corev1.NodeList) NodesInfo {
	ni := NodesInfo{
		Total:   len(nodes.Items),
		Details: make([]NodeInfo, 0, len(nodes.Items)),
	}

	for _, node := range nodes.Items {
		ready := isNodeReady(&node)
		if ready {
			ni.Ready++
		} else {
			ni.NotReady++
		}

		ni.Details = append(ni.Details, NodeInfo{
			Name:             node.Name,
			Roles:            getNodeRoles(&node),
			KubeletVersion:   node.Status.NodeInfo.KubeletVersion,
			OS:               node.Status.NodeInfo.OperatingSystem,
			Architecture:     node.Status.NodeInfo.Architecture,
			ContainerRuntime: node.Status.NodeInfo.ContainerRuntimeVersion,
			Ready:            ready,
			CPUCapacity:      node.Status.Capacity.Cpu().String(),
			MemoryCapacity:   node.Status.Capacity.Memory().String(),
			Age:              formatAge(node.CreationTimestamp.Time),
		})
	}

	return ni
}

func (t *Task) calculateCapacity(nodes *corev1.NodeList) Capacity {
	var totalCPU, totalMemory, totalPods int64

	for _, node := range nodes.Items {
		totalCPU += node.Status.Capacity.Cpu().MilliValue()
		totalMemory += node.Status.Capacity.Memory().Value()
		totalPods += node.Status.Capacity.Pods().Value()
	}

	return Capacity{
		CPU:    fmt.Sprintf("%dm", totalCPU),
		Memory: formatBytes(totalMemory),
		Pods:   fmt.Sprintf("%d", totalPods),
	}
}

func isNodeReady(node *corev1.Node) bool {
	for _, condition := range node.Status.Conditions {
		if condition.Type == corev1.NodeReady {
			return condition.Status == corev1.ConditionTrue
		}
	}
	return false
}

func getNodeRoles(node *corev1.Node) []string {
	roles := []string{}
	for label := range node.Labels {
		if len(label) > 24 && label[:24] == "node-role.kubernetes.io/" {
			roles = append(roles, label[24:])
		}
	}
	if len(roles) == 0 {
		roles = append(roles, "worker")
	}
	return roles
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

func formatAge(t time.Time) string {
	d := time.Since(t)
	switch {
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd", int(d.Hours()/24))
	}
}
