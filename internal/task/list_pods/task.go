// Package list_pods provides pod listing functionality.
package list_pods

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/loafoe/centcom-satellite/internal/task"
)

const TaskName = "list_pods"

// Payload for list_pods task.
type Payload struct {
	Namespace     string `json:"namespace"`
	LabelSelector string `json:"label_selector,omitempty"`
	FieldSelector string `json:"field_selector,omitempty"`
}

// PodList contains the pod listing.
type PodList struct {
	Total int       `json:"total"`
	Pods  []PodInfo `json:"pods"`
}

// PodInfo contains pod details.
type PodInfo struct {
	Name           string            `json:"name"`
	Namespace      string            `json:"namespace"`
	Status         string            `json:"status"`
	Node           string            `json:"node"`
	Restarts       int32             `json:"restarts"`
	Age            string            `json:"age"`
	MemoryUsage    string            `json:"memory_usage,omitempty"`
	MemoryRequest  string            `json:"memory_request,omitempty"`
	MemoryLimit    string            `json:"memory_limit,omitempty"`
	MemoryPercent  float64           `json:"memory_percent,omitempty"`
	Containers     []ContainerInfo   `json:"containers"`
	NodeSelector   map[string]string `json:"node_selector,omitempty"`
	Affinity       *AffinityInfo     `json:"affinity,omitempty"`
	Tolerations    []TolerationInfo  `json:"tolerations,omitempty"`
}

// AffinityInfo contains affinity scheduling constraints.
type AffinityInfo struct {
	NodeAffinity    *NodeAffinityInfo    `json:"node_affinity,omitempty"`
	PodAffinity     *PodAffinityInfo     `json:"pod_affinity,omitempty"`
	PodAntiAffinity *PodAntiAffinityInfo `json:"pod_anti_affinity,omitempty"`
}

// NodeAffinityInfo contains node affinity details.
type NodeAffinityInfo struct {
	RequiredDuringScheduling  []NodeSelectorTerm `json:"required,omitempty"`
	PreferredDuringScheduling []PreferredTerm    `json:"preferred,omitempty"`
}

// PodAffinityInfo contains pod affinity details.
type PodAffinityInfo struct {
	RequiredDuringScheduling  []PodAffinityTerm          `json:"required,omitempty"`
	PreferredDuringScheduling []PreferredPodAffinityTerm `json:"preferred,omitempty"`
}

// PodAntiAffinityInfo contains pod anti-affinity details.
type PodAntiAffinityInfo struct {
	RequiredDuringScheduling  []PodAffinityTerm          `json:"required,omitempty"`
	PreferredDuringScheduling []PreferredPodAffinityTerm `json:"preferred,omitempty"`
}

// NodeSelectorTerm contains node selector requirements.
type NodeSelectorTerm struct {
	MatchExpressions []SelectorRequirement `json:"match_expressions,omitempty"`
	MatchFields      []SelectorRequirement `json:"match_fields,omitempty"`
}

// PreferredTerm contains weighted node selector term.
type PreferredTerm struct {
	Weight     int32            `json:"weight"`
	Preference NodeSelectorTerm `json:"preference"`
}

// PodAffinityTerm contains pod affinity term.
type PodAffinityTerm struct {
	TopologyKey   string                `json:"topology_key"`
	LabelSelector []SelectorRequirement `json:"label_selector,omitempty"`
	Namespaces    []string              `json:"namespaces,omitempty"`
}

// PreferredPodAffinityTerm contains weighted pod affinity term.
type PreferredPodAffinityTerm struct {
	Weight int32           `json:"weight"`
	Term   PodAffinityTerm `json:"term"`
}

// SelectorRequirement contains a label selector requirement.
type SelectorRequirement struct {
	Key      string   `json:"key"`
	Operator string   `json:"operator"`
	Values   []string `json:"values,omitempty"`
}

// TolerationInfo contains pod toleration details.
type TolerationInfo struct {
	Key      string `json:"key,omitempty"`
	Operator string `json:"operator,omitempty"`
	Value    string `json:"value,omitempty"`
	Effect   string `json:"effect,omitempty"`
}

// ContainerInfo contains container details.
type ContainerInfo struct {
	Name     string            `json:"name"`
	Image    string            `json:"image"`
	State    string            `json:"state"`
	Ready    bool              `json:"ready"`
	Restarts int32             `json:"restarts"`
	Requests map[string]string `json:"requests,omitempty"`
	Limits   map[string]string `json:"limits,omitempty"`
}

// Task handles pod listing.
type Task struct {
	clientset kubernetes.Interface
}

// New creates a new list pods task.
func New(clientset kubernetes.Interface) *Task {
	return &Task{clientset: clientset}
}

// Name returns the task type identifier.
func (t *Task) Name() string {
	return TaskName
}

// Execute lists pods in a namespace.
func (t *Task) Execute(ctx context.Context, rawPayload json.RawMessage) (*task.Result, error) {
	var payload Payload
	if len(rawPayload) > 0 && string(rawPayload) != "{}" {
		if err := json.Unmarshal(rawPayload, &payload); err != nil {
			return task.NewErrorResult(fmt.Sprintf("invalid payload: %v", err)), nil
		}
	}

	// Empty namespace means all namespaces
	namespace := payload.Namespace
	if namespace == "" {
		namespace = metav1.NamespaceAll
	}

	listOpts := metav1.ListOptions{}
	if payload.LabelSelector != "" {
		listOpts.LabelSelector = payload.LabelSelector
	}
	if payload.FieldSelector != "" {
		listOpts.FieldSelector = payload.FieldSelector
	}

	pods, err := t.clientset.CoreV1().Pods(namespace).List(ctx, listOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to list pods: %w", err)
	}

	result := &PodList{
		Total: len(pods.Items),
		Pods:  make([]PodInfo, 0, len(pods.Items)),
	}

	// Fetch metrics (best-effort, don't fail if metrics-server unavailable)
	metricsMap := t.getPodMetricsMap(ctx, namespace)

	for i := range pods.Items {
		pod := &pods.Items[i]
		podInfo := t.buildPodInfo(pod)
		t.enrichWithMemory(pod, &podInfo, metricsMap)
		result.Pods = append(result.Pods, podInfo)
	}

	// Sort alphabetically by name
	sort.Slice(result.Pods, func(i, j int) bool {
		return result.Pods[i].Name < result.Pods[j].Name
	})

	msg := fmt.Sprintf("Found %d pods in namespace %s", result.Total, namespace)
	if namespace == metav1.NamespaceAll {
		msg = fmt.Sprintf("Found %d pods across all namespaces", result.Total)
	}
	return task.NewSuccessResultWithDetails(msg, result), nil
}

func (t *Task) buildPodInfo(pod *corev1.Pod) PodInfo {
	info := PodInfo{
		Name:       pod.Name,
		Namespace:  pod.Namespace,
		Status:     getPodStatus(pod),
		Node:       pod.Spec.NodeName,
		Age:        formatAge(pod.CreationTimestamp.Time),
		Containers: make([]ContainerInfo, 0, len(pod.Spec.Containers)),
	}

	// Build container status map for quick lookup
	containerStatusMap := make(map[string]corev1.ContainerStatus)
	for i := range pod.Status.ContainerStatuses {
		cs := &pod.Status.ContainerStatuses[i]
		containerStatusMap[cs.Name] = *cs
		info.Restarts += cs.RestartCount
	}

	// Build container info from spec and status
	for i := range pod.Spec.Containers {
		container := &pod.Spec.Containers[i]
		containerInfo := ContainerInfo{
			Name:  container.Name,
			Image: container.Image,
		}

		// Get resource requests
		if len(container.Resources.Requests) > 0 {
			containerInfo.Requests = make(map[string]string)
			for name, qty := range container.Resources.Requests {
				containerInfo.Requests[string(name)] = qty.String()
			}
		}

		// Get resource limits
		if len(container.Resources.Limits) > 0 {
			containerInfo.Limits = make(map[string]string)
			for name, qty := range container.Resources.Limits {
				containerInfo.Limits[string(name)] = qty.String()
			}
		}

		// Get container status if available
		if cs, ok := containerStatusMap[container.Name]; ok {
			containerInfo.Ready = cs.Ready
			containerInfo.Restarts = cs.RestartCount
			containerInfo.State = getContainerState(cs.State)
		} else {
			containerInfo.State = "Unknown"
		}

		info.Containers = append(info.Containers, containerInfo)
	}

	// Add scheduling constraints
	info.NodeSelector = extractNodeSelector(pod.Spec.NodeSelector)
	info.Affinity = extractAffinity(pod.Spec.Affinity)
	info.Tolerations = getPodTolerations(pod)

	return info
}

func getPodTolerations(pod *corev1.Pod) []TolerationInfo {
	if len(pod.Spec.Tolerations) == 0 {
		return nil
	}
	tolerations := make([]TolerationInfo, 0, len(pod.Spec.Tolerations))
	for _, t := range pod.Spec.Tolerations {
		// Skip default tolerations that K8s adds automatically
		if t.Key == "node.kubernetes.io/not-ready" || t.Key == "node.kubernetes.io/unreachable" {
			continue
		}
		tolerations = append(tolerations, TolerationInfo{
			Key:      t.Key,
			Operator: string(t.Operator),
			Value:    t.Value,
			Effect:   string(t.Effect),
		})
	}
	if len(tolerations) == 0 {
		return nil
	}
	return tolerations
}

func getPodStatus(pod *corev1.Pod) string {
	// Check for deletion
	if pod.DeletionTimestamp != nil {
		return "Terminating"
	}

	// Check container statuses for more specific reasons
	for _, cs := range pod.Status.ContainerStatuses {
		if cs.State.Waiting != nil && cs.State.Waiting.Reason != "" {
			return cs.State.Waiting.Reason
		}
		if cs.State.Terminated != nil && cs.State.Terminated.Reason != "" {
			return cs.State.Terminated.Reason
		}
	}

	// Fall back to pod phase
	return string(pod.Status.Phase)
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

func getContainerState(state corev1.ContainerState) string {
	if state.Running != nil {
		return "Running"
	}
	if state.Waiting != nil {
		if state.Waiting.Reason != "" {
			return fmt.Sprintf("Waiting: %s", state.Waiting.Reason)
		}
		return "Waiting"
	}
	if state.Terminated != nil {
		if state.Terminated.Reason != "" {
			return fmt.Sprintf("Terminated: %s", state.Terminated.Reason)
		}
		return "Terminated"
	}
	return "Unknown"
}

type metricsPodList struct {
	Items []metricsPod `json:"items"`
}

type metricsPod struct {
	Metadata struct {
		Name      string `json:"name"`
		Namespace string `json:"namespace"`
	} `json:"metadata"`
	Containers []struct {
		Name  string `json:"name"`
		Usage struct {
			Memory string `json:"memory"`
		} `json:"usage"`
	} `json:"containers"`
}

func (t *Task) getPodMetricsMap(ctx context.Context, namespace string) map[string]int64 {
	path := fmt.Sprintf("/apis/metrics.k8s.io/v1beta1/namespaces/%s/pods", namespace)
	if namespace == metav1.NamespaceAll {
		path = "/apis/metrics.k8s.io/v1beta1/pods"
	}

	data, err := t.clientset.CoreV1().RESTClient().Get().
		AbsPath(path).
		DoRaw(ctx)
	if err != nil {
		return nil
	}

	var metrics metricsPodList
	if err := json.Unmarshal(data, &metrics); err != nil {
		return nil
	}

	result := make(map[string]int64)
	for _, mp := range metrics.Items {
		key := mp.Metadata.Namespace + "/" + mp.Metadata.Name
		var total int64
		for _, c := range mp.Containers {
			if c.Usage.Memory != "" {
				q := resource.MustParse(c.Usage.Memory)
				total += q.Value()
			}
		}
		result[key] = total
	}
	return result
}

func (t *Task) enrichWithMemory(pod *corev1.Pod, info *PodInfo, metricsMap map[string]int64) {
	// Calculate total memory request and limit from spec
	var totalRequest, totalLimit int64
	var hasRequest, hasLimit bool
	for i := range pod.Spec.Containers {
		c := &pod.Spec.Containers[i]
		if req, ok := c.Resources.Requests[corev1.ResourceMemory]; ok {
			totalRequest += req.Value()
			hasRequest = true
		}
		if lim, ok := c.Resources.Limits[corev1.ResourceMemory]; ok {
			totalLimit += lim.Value()
			hasLimit = true
		}
	}

	if hasRequest {
		info.MemoryRequest = formatBytes(totalRequest)
	}
	if hasLimit {
		info.MemoryLimit = formatBytes(totalLimit)
	}

	// Add actual usage from metrics
	if metricsMap == nil {
		return
	}
	key := pod.Namespace + "/" + pod.Name
	usage, ok := metricsMap[key]
	if !ok {
		return
	}
	info.MemoryUsage = formatBytes(usage)
	if hasLimit && totalLimit > 0 {
		info.MemoryPercent = float64(usage) / float64(totalLimit) * 100
	} else if hasRequest && totalRequest > 0 {
		info.MemoryPercent = float64(usage) / float64(totalRequest) * 100
	}
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

func extractNodeSelector(nodeSelector map[string]string) map[string]string {
	if len(nodeSelector) == 0 {
		return nil
	}
	result := make(map[string]string, len(nodeSelector))
	for k, v := range nodeSelector {
		result[k] = v
	}
	return result
}

func extractAffinity(affinity *corev1.Affinity) *AffinityInfo {
	if affinity == nil {
		return nil
	}
	info := &AffinityInfo{}
	hasContent := false

	if affinity.NodeAffinity != nil {
		na := affinity.NodeAffinity
		nodeInfo := &NodeAffinityInfo{}
		if na.RequiredDuringSchedulingIgnoredDuringExecution != nil {
			for _, term := range na.RequiredDuringSchedulingIgnoredDuringExecution.NodeSelectorTerms {
				nodeInfo.RequiredDuringScheduling = append(nodeInfo.RequiredDuringScheduling, convertNodeSelectorTerm(term))
			}
		}
		for _, pref := range na.PreferredDuringSchedulingIgnoredDuringExecution {
			nodeInfo.PreferredDuringScheduling = append(nodeInfo.PreferredDuringScheduling, PreferredTerm{
				Weight:     pref.Weight,
				Preference: convertNodeSelectorTerm(pref.Preference),
			})
		}
		if len(nodeInfo.RequiredDuringScheduling) > 0 || len(nodeInfo.PreferredDuringScheduling) > 0 {
			info.NodeAffinity = nodeInfo
			hasContent = true
		}
	}

	if affinity.PodAffinity != nil {
		pa := affinity.PodAffinity
		podInfo := &PodAffinityInfo{}
		for _, term := range pa.RequiredDuringSchedulingIgnoredDuringExecution {
			podInfo.RequiredDuringScheduling = append(podInfo.RequiredDuringScheduling, convertPodAffinityTerm(term))
		}
		for _, pref := range pa.PreferredDuringSchedulingIgnoredDuringExecution {
			podInfo.PreferredDuringScheduling = append(podInfo.PreferredDuringScheduling, PreferredPodAffinityTerm{
				Weight: pref.Weight,
				Term:   convertPodAffinityTerm(pref.PodAffinityTerm),
			})
		}
		if len(podInfo.RequiredDuringScheduling) > 0 || len(podInfo.PreferredDuringScheduling) > 0 {
			info.PodAffinity = podInfo
			hasContent = true
		}
	}

	if affinity.PodAntiAffinity != nil {
		paa := affinity.PodAntiAffinity
		antiInfo := &PodAntiAffinityInfo{}
		for _, term := range paa.RequiredDuringSchedulingIgnoredDuringExecution {
			antiInfo.RequiredDuringScheduling = append(antiInfo.RequiredDuringScheduling, convertPodAffinityTerm(term))
		}
		for _, pref := range paa.PreferredDuringSchedulingIgnoredDuringExecution {
			antiInfo.PreferredDuringScheduling = append(antiInfo.PreferredDuringScheduling, PreferredPodAffinityTerm{
				Weight: pref.Weight,
				Term:   convertPodAffinityTerm(pref.PodAffinityTerm),
			})
		}
		if len(antiInfo.RequiredDuringScheduling) > 0 || len(antiInfo.PreferredDuringScheduling) > 0 {
			info.PodAntiAffinity = antiInfo
			hasContent = true
		}
	}

	if !hasContent {
		return nil
	}
	return info
}

func convertNodeSelectorTerm(term corev1.NodeSelectorTerm) NodeSelectorTerm {
	result := NodeSelectorTerm{}
	for _, expr := range term.MatchExpressions {
		result.MatchExpressions = append(result.MatchExpressions, SelectorRequirement{
			Key:      expr.Key,
			Operator: string(expr.Operator),
			Values:   expr.Values,
		})
	}
	for _, field := range term.MatchFields {
		result.MatchFields = append(result.MatchFields, SelectorRequirement{
			Key:      field.Key,
			Operator: string(field.Operator),
			Values:   field.Values,
		})
	}
	return result
}

func convertPodAffinityTerm(term corev1.PodAffinityTerm) PodAffinityTerm {
	result := PodAffinityTerm{
		TopologyKey: term.TopologyKey,
		Namespaces:  term.Namespaces,
	}
	if term.LabelSelector != nil {
		for _, expr := range term.LabelSelector.MatchExpressions {
			result.LabelSelector = append(result.LabelSelector, SelectorRequirement{
				Key:      expr.Key,
				Operator: string(expr.Operator),
				Values:   expr.Values,
			})
		}
		for k, v := range term.LabelSelector.MatchLabels {
			result.LabelSelector = append(result.LabelSelector, SelectorRequirement{
				Key:      k,
				Operator: "In",
				Values:   []string{v},
			})
		}
	}
	return result
}
