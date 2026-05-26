// Package list_workloads provides workload listing functionality.
package list_workloads

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	autoscalingv2 "k8s.io/api/autoscaling/v2"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/kubernetes"

	"github.com/loafoe/pico-agent/internal/task"
)

const TaskName = "list_workloads"

// Payload for list_workloads task.
type Payload struct {
	Namespace       string `json:"namespace"`               // required
	Kind            string `json:"kind,omitempty"`          // deployment/statefulset/daemonset/all (default: all)
	IncludeMetadata bool   `json:"include_metadata"`        // include labels and annotations
	IncludeHPAs     bool   `json:"include_hpas,omitempty"`  // include HorizontalPodAutoscaler info
}

// WorkloadList contains the workload listing.
type WorkloadList struct {
	Total          int            `json:"total"`
	Workloads      []WorkloadInfo `json:"workloads"`
	UnmatchedPDBs  []PDBInfo      `json:"unmatched_pdbs,omitempty"`
}

// WorkloadInfo contains workload details.
type WorkloadInfo struct {
	Name                       string                       `json:"name"`
	Namespace                  string                       `json:"namespace"`
	Kind                       string                       `json:"kind"`
	Replicas                   ReplicaStatus                `json:"replicas"`
	Images                     []string                     `json:"images"`
	Selector                   map[string]string            `json:"selector,omitempty"`
	Labels                     map[string]string            `json:"labels,omitempty"`
	Annotations                map[string]string            `json:"annotations,omitempty"`
	NodeSelector               map[string]string            `json:"node_selector,omitempty"`
	Affinity                   *AffinityInfo                `json:"affinity,omitempty"`
	TopologySpreadConstraints  []TopologySpreadConstraint   `json:"topology_spread_constraints,omitempty"`
	Tolerations                []TolerationInfo             `json:"tolerations,omitempty"`
	PDBs                       []PDBInfo                    `json:"pdbs,omitempty"`
	HPA                        *HPAInfo                     `json:"hpa,omitempty"`
	CreationTime               string                       `json:"creation_time"`
	Age                        string                       `json:"age"`
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
	RequiredDuringScheduling  []PodAffinityTerm         `json:"required,omitempty"`
	PreferredDuringScheduling []PreferredPodAffinityTerm `json:"preferred,omitempty"`
}

// PodAntiAffinityInfo contains pod anti-affinity details.
type PodAntiAffinityInfo struct {
	RequiredDuringScheduling  []PodAffinityTerm         `json:"required,omitempty"`
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

// TopologySpreadConstraint contains topology spread constraint details.
type TopologySpreadConstraint struct {
	MaxSkew           int32                 `json:"max_skew"`
	TopologyKey       string                `json:"topology_key"`
	WhenUnsatisfiable string                `json:"when_unsatisfiable"`
	LabelSelector     []SelectorRequirement `json:"label_selector,omitempty"`
}

// HPAInfo contains HorizontalPodAutoscaler details.
type HPAInfo struct {
	Name            string       `json:"name"`
	MinReplicas     int32        `json:"min_replicas"`
	MaxReplicas     int32        `json:"max_replicas"`
	CurrentReplicas int32        `json:"current_replicas"`
	DesiredReplicas int32        `json:"desired_replicas"`
	Metrics         []HPAMetric  `json:"metrics,omitempty"`
}

// HPAMetric contains HPA metric details.
type HPAMetric struct {
	Type    string `json:"type"`
	Name    string `json:"name,omitempty"`
	Current string `json:"current,omitempty"`
	Target  string `json:"target,omitempty"`
}

// PDBInfo contains PodDisruptionBudget details.
type PDBInfo struct {
	Name               string `json:"name"`
	Namespace          string `json:"namespace,omitempty"`
	MinAvailable       string `json:"min_available,omitempty"`
	MaxUnavailable     string `json:"max_unavailable,omitempty"`
	CurrentHealthy     int32  `json:"current_healthy"`
	DesiredHealthy     int32  `json:"desired_healthy"`
	DisruptionsAllowed int32  `json:"disruptions_allowed"`
}

// TolerationInfo contains toleration details.
type TolerationInfo struct {
	Key      string `json:"key,omitempty"`
	Operator string `json:"operator,omitempty"`
	Value    string `json:"value,omitempty"`
	Effect   string `json:"effect,omitempty"`
}

// ReplicaStatus contains replica information.
type ReplicaStatus struct {
	Desired int32 `json:"desired"`
	Ready   int32 `json:"ready"`
}

// Task handles workload listing.
type Task struct {
	clientset kubernetes.Interface
}

// New creates a new list workloads task.
func New(clientset kubernetes.Interface) *Task {
	return &Task{clientset: clientset}
}

// Name returns the task type identifier.
func (t *Task) Name() string {
	return TaskName
}

// Execute lists workloads in a namespace.
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

	// Default kind to "all" if empty
	if payload.Kind == "" {
		payload.Kind = "all"
	}

	var workloads []WorkloadInfo
	var podTemplateLabels []map[string]string

	// List Deployments
	if payload.Kind == "deployment" || payload.Kind == "all" {
		deployments, err := t.clientset.AppsV1().Deployments(namespace).List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, fmt.Errorf("failed to list deployments: %w", err)
		}
		for i := range deployments.Items {
			workloads = append(workloads, t.buildDeploymentInfo(&deployments.Items[i], payload.IncludeMetadata))
			podTemplateLabels = append(podTemplateLabels, deployments.Items[i].Spec.Template.Labels)
		}
	}

	// List StatefulSets
	if payload.Kind == "statefulset" || payload.Kind == "all" {
		statefulsets, err := t.clientset.AppsV1().StatefulSets(namespace).List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, fmt.Errorf("failed to list statefulsets: %w", err)
		}
		for i := range statefulsets.Items {
			workloads = append(workloads, t.buildStatefulSetInfo(&statefulsets.Items[i], payload.IncludeMetadata))
			podTemplateLabels = append(podTemplateLabels, statefulsets.Items[i].Spec.Template.Labels)
		}
	}

	// List DaemonSets
	if payload.Kind == "daemonset" || payload.Kind == "all" {
		daemonsets, err := t.clientset.AppsV1().DaemonSets(namespace).List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, fmt.Errorf("failed to list daemonsets: %w", err)
		}
		for i := range daemonsets.Items {
			workloads = append(workloads, t.buildDaemonSetInfo(&daemonsets.Items[i], payload.IncludeMetadata))
			podTemplateLabels = append(podTemplateLabels, daemonsets.Items[i].Spec.Template.Labels)
		}
	}

	// Fetch PDBs and match to workloads by pod template labels
	var unmatchedPDBs []PDBInfo
	pdbList, err := t.clientset.PolicyV1().PodDisruptionBudgets(namespace).List(ctx, metav1.ListOptions{})
	if err == nil && len(pdbList.Items) > 0 {
		unmatchedPDBs = t.matchPDBsToWorkloads(workloads, podTemplateLabels, pdbList.Items)
	}

	// Fetch HPAs and match to workloads by scaleTargetRef
	if payload.IncludeHPAs {
		hpaList, err := t.clientset.AutoscalingV2().HorizontalPodAutoscalers(namespace).List(ctx, metav1.ListOptions{})
		if err == nil && len(hpaList.Items) > 0 {
			t.matchHPAsToWorkloads(workloads, hpaList.Items)
		}
	}

	// Sort by Kind then Name
	sort.Slice(workloads, func(i, j int) bool {
		if workloads[i].Kind != workloads[j].Kind {
			return workloads[i].Kind < workloads[j].Kind
		}
		return workloads[i].Name < workloads[j].Name
	})

	result := &WorkloadList{
		Total:         len(workloads),
		Workloads:     workloads,
		UnmatchedPDBs: unmatchedPDBs,
	}

	return task.NewSuccessResultWithDetails(
		fmt.Sprintf("Found %d workloads in namespace %s", result.Total, namespace),
		result,
	), nil
}

func (t *Task) buildDeploymentInfo(deployment *appsv1.Deployment, includeMetadata bool) WorkloadInfo {
	images := extractImages(deployment.Spec.Template.Spec.Containers)
	var desired int32 = 1
	if deployment.Spec.Replicas != nil {
		desired = *deployment.Spec.Replicas
	}

	info := WorkloadInfo{
		Name:      deployment.Name,
		Namespace: deployment.Namespace,
		Kind:      "Deployment",
		Replicas: ReplicaStatus{
			Desired: desired,
			Ready:   deployment.Status.ReadyReplicas,
		},
		Images:                    images,
		Selector:                  extractSelector(deployment.Spec.Selector),
		NodeSelector:              extractNodeSelector(deployment.Spec.Template.Spec.NodeSelector),
		Affinity:                  extractAffinity(deployment.Spec.Template.Spec.Affinity),
		TopologySpreadConstraints: extractTopologySpreadConstraints(deployment.Spec.Template.Spec.TopologySpreadConstraints),
		Tolerations:               extractTolerations(deployment.Spec.Template.Spec.Tolerations),
		CreationTime:              deployment.CreationTimestamp.Format(time.RFC3339),
		Age:                       formatAge(deployment.CreationTimestamp.Time),
	}

	if includeMetadata {
		info.Labels = copyLabels(deployment.Labels)
		info.Annotations = filterAnnotations(deployment.Annotations)
	}

	return info
}

func (t *Task) buildStatefulSetInfo(statefulset *appsv1.StatefulSet, includeMetadata bool) WorkloadInfo {
	images := extractImages(statefulset.Spec.Template.Spec.Containers)
	var desired int32 = 1
	if statefulset.Spec.Replicas != nil {
		desired = *statefulset.Spec.Replicas
	}

	info := WorkloadInfo{
		Name:      statefulset.Name,
		Namespace: statefulset.Namespace,
		Kind:      "StatefulSet",
		Replicas: ReplicaStatus{
			Desired: desired,
			Ready:   statefulset.Status.ReadyReplicas,
		},
		Images:                    images,
		Selector:                  extractSelector(statefulset.Spec.Selector),
		NodeSelector:              extractNodeSelector(statefulset.Spec.Template.Spec.NodeSelector),
		Affinity:                  extractAffinity(statefulset.Spec.Template.Spec.Affinity),
		TopologySpreadConstraints: extractTopologySpreadConstraints(statefulset.Spec.Template.Spec.TopologySpreadConstraints),
		Tolerations:               extractTolerations(statefulset.Spec.Template.Spec.Tolerations),
		CreationTime:              statefulset.CreationTimestamp.Format(time.RFC3339),
		Age:                       formatAge(statefulset.CreationTimestamp.Time),
	}

	if includeMetadata {
		info.Labels = copyLabels(statefulset.Labels)
		info.Annotations = filterAnnotations(statefulset.Annotations)
	}

	return info
}

func (t *Task) buildDaemonSetInfo(daemonset *appsv1.DaemonSet, includeMetadata bool) WorkloadInfo {
	images := extractImages(daemonset.Spec.Template.Spec.Containers)

	info := WorkloadInfo{
		Name:      daemonset.Name,
		Namespace: daemonset.Namespace,
		Kind:      "DaemonSet",
		Replicas: ReplicaStatus{
			Desired: daemonset.Status.DesiredNumberScheduled,
			Ready:   daemonset.Status.NumberReady,
		},
		Images:                    images,
		Selector:                  extractSelector(daemonset.Spec.Selector),
		NodeSelector:              extractNodeSelector(daemonset.Spec.Template.Spec.NodeSelector),
		Affinity:                  extractAffinity(daemonset.Spec.Template.Spec.Affinity),
		TopologySpreadConstraints: extractTopologySpreadConstraints(daemonset.Spec.Template.Spec.TopologySpreadConstraints),
		Tolerations:               extractTolerations(daemonset.Spec.Template.Spec.Tolerations),
		CreationTime:              daemonset.CreationTimestamp.Format(time.RFC3339),
		Age:                       formatAge(daemonset.CreationTimestamp.Time),
	}

	if includeMetadata {
		info.Labels = copyLabels(daemonset.Labels)
		info.Annotations = filterAnnotations(daemonset.Annotations)
	}

	return info
}

func (t *Task) matchPDBsToWorkloads(workloads []WorkloadInfo, podTemplateLabels []map[string]string, pdbs []policyv1.PodDisruptionBudget) []PDBInfo {
	matched := make(map[string]bool)
	for i := range workloads {
		w := &workloads[i]
		ptLabels := podTemplateLabels[i]
		if ptLabels == nil {
			continue
		}
		for _, pdb := range pdbs {
			if pdb.Namespace != w.Namespace {
				continue
			}
			if pdb.Spec.Selector == nil {
				continue
			}
			selector, err := metav1.LabelSelectorAsSelector(pdb.Spec.Selector)
			if err != nil {
				continue
			}
			if selector.Matches(labels.Set(ptLabels)) {
				key := pdb.Namespace + "/" + pdb.Name
				matched[key] = true
				info := PDBInfo{
					Name:               pdb.Name,
					Namespace:          pdb.Namespace,
					CurrentHealthy:     pdb.Status.CurrentHealthy,
					DesiredHealthy:     pdb.Status.DesiredHealthy,
					DisruptionsAllowed: pdb.Status.DisruptionsAllowed,
				}
				if pdb.Spec.MinAvailable != nil {
					info.MinAvailable = pdb.Spec.MinAvailable.String()
				}
				if pdb.Spec.MaxUnavailable != nil {
					info.MaxUnavailable = pdb.Spec.MaxUnavailable.String()
				}
				w.PDBs = append(w.PDBs, info)
			}
		}
	}

	var unmatched []PDBInfo
	for _, pdb := range pdbs {
		key := pdb.Namespace + "/" + pdb.Name
		if matched[key] {
			continue
		}
		info := PDBInfo{
			Name:               pdb.Name,
			Namespace:          pdb.Namespace,
			CurrentHealthy:     pdb.Status.CurrentHealthy,
			DesiredHealthy:     pdb.Status.DesiredHealthy,
			DisruptionsAllowed: pdb.Status.DisruptionsAllowed,
		}
		if pdb.Spec.MinAvailable != nil {
			info.MinAvailable = pdb.Spec.MinAvailable.String()
		}
		if pdb.Spec.MaxUnavailable != nil {
			info.MaxUnavailable = pdb.Spec.MaxUnavailable.String()
		}
		unmatched = append(unmatched, info)
	}
	return unmatched
}

func extractImages(containers []corev1.Container) []string {
	images := make([]string, 0, len(containers))
	for _, c := range containers {
		images = append(images, c.Image)
	}
	return images
}

func extractTolerations(tolerations []corev1.Toleration) []TolerationInfo {
	if len(tolerations) == 0 {
		return nil
	}
	result := make([]TolerationInfo, 0, len(tolerations))
	for _, t := range tolerations {
		// Skip default tolerations that K8s adds automatically
		if t.Key == "node.kubernetes.io/not-ready" || t.Key == "node.kubernetes.io/unreachable" {
			continue
		}
		result = append(result, TolerationInfo{
			Key:      t.Key,
			Operator: string(t.Operator),
			Value:    t.Value,
			Effect:   string(t.Effect),
		})
	}
	if len(result) == 0 {
		return nil
	}
	return result
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

// copyLabels returns a copy of the labels map, or empty map if nil.
func copyLabels(labels map[string]string) map[string]string {
	if labels == nil {
		return map[string]string{}
	}
	result := make(map[string]string, len(labels))
	for k, v := range labels {
		result[k] = v
	}
	return result
}

// filterAnnotations returns annotations with noisy keys filtered out.
func filterAnnotations(annotations map[string]string) map[string]string {
	if annotations == nil {
		return map[string]string{}
	}
	result := make(map[string]string)
	for k, v := range annotations {
		if shouldExcludeAnnotation(k) {
			continue
		}
		result[k] = v
	}
	return result
}

// shouldExcludeAnnotation returns true for annotations that bloat responses.
func shouldExcludeAnnotation(key string) bool {
	switch key {
	case "kubectl.kubernetes.io/last-applied-configuration",
		"deployment.kubernetes.io/revision":
		return true
	}
	return false
}

func (t *Task) matchHPAsToWorkloads(workloads []WorkloadInfo, hpas []autoscalingv2.HorizontalPodAutoscaler) {
	for i := range workloads {
		w := &workloads[i]
		for _, hpa := range hpas {
			if hpa.Namespace != w.Namespace {
				continue
			}
			ref := hpa.Spec.ScaleTargetRef
			if ref.Name != w.Name {
				continue
			}
			if ref.Kind != w.Kind {
				continue
			}
			info := &HPAInfo{
				Name:            hpa.Name,
				MaxReplicas:     hpa.Spec.MaxReplicas,
				CurrentReplicas: hpa.Status.CurrentReplicas,
				DesiredReplicas: hpa.Status.DesiredReplicas,
			}
			if hpa.Spec.MinReplicas != nil {
				info.MinReplicas = *hpa.Spec.MinReplicas
			} else {
				info.MinReplicas = 1
			}
			// Extract metrics
			for _, metric := range hpa.Spec.Metrics {
				m := HPAMetric{Type: string(metric.Type)}
				switch metric.Type {
				case autoscalingv2.ResourceMetricSourceType:
					if metric.Resource != nil {
						m.Name = string(metric.Resource.Name)
						if metric.Resource.Target.AverageUtilization != nil {
							m.Target = fmt.Sprintf("%d%%", *metric.Resource.Target.AverageUtilization)
						} else if metric.Resource.Target.AverageValue != nil {
							m.Target = metric.Resource.Target.AverageValue.String()
						}
					}
				case autoscalingv2.PodsMetricSourceType:
					if metric.Pods != nil {
						m.Name = metric.Pods.Metric.Name
						m.Target = metric.Pods.Target.AverageValue.String()
					}
				case autoscalingv2.ObjectMetricSourceType:
					if metric.Object != nil {
						m.Name = metric.Object.Metric.Name
					}
				case autoscalingv2.ExternalMetricSourceType:
					if metric.External != nil {
						m.Name = metric.External.Metric.Name
					}
				}
				info.Metrics = append(info.Metrics, m)
			}
			// Add current metric values from status
			for j, status := range hpa.Status.CurrentMetrics {
				if j >= len(info.Metrics) {
					break
				}
				switch status.Type {
				case autoscalingv2.ResourceMetricSourceType:
					if status.Resource != nil && status.Resource.Current.AverageUtilization != nil {
						info.Metrics[j].Current = fmt.Sprintf("%d%%", *status.Resource.Current.AverageUtilization)
					} else if status.Resource != nil && status.Resource.Current.AverageValue != nil {
						info.Metrics[j].Current = status.Resource.Current.AverageValue.String()
					}
				case autoscalingv2.PodsMetricSourceType:
					if status.Pods != nil {
						info.Metrics[j].Current = status.Pods.Current.AverageValue.String()
					}
				}
			}
			w.HPA = info
			break
		}
	}
}

func extractSelector(selector *metav1.LabelSelector) map[string]string {
	if selector == nil || len(selector.MatchLabels) == 0 {
		return nil
	}
	result := make(map[string]string, len(selector.MatchLabels))
	for k, v := range selector.MatchLabels {
		result[k] = v
	}
	return result
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

func extractTopologySpreadConstraints(constraints []corev1.TopologySpreadConstraint) []TopologySpreadConstraint {
	if len(constraints) == 0 {
		return nil
	}
	result := make([]TopologySpreadConstraint, 0, len(constraints))
	for _, c := range constraints {
		tsc := TopologySpreadConstraint{
			MaxSkew:           c.MaxSkew,
			TopologyKey:       c.TopologyKey,
			WhenUnsatisfiable: string(c.WhenUnsatisfiable),
		}
		if c.LabelSelector != nil {
			for _, expr := range c.LabelSelector.MatchExpressions {
				tsc.LabelSelector = append(tsc.LabelSelector, SelectorRequirement{
					Key:      expr.Key,
					Operator: string(expr.Operator),
					Values:   expr.Values,
				})
			}
			for k, v := range c.LabelSelector.MatchLabels {
				tsc.LabelSelector = append(tsc.LabelSelector, SelectorRequirement{
					Key:      k,
					Operator: "In",
					Values:   []string{v},
				})
			}
		}
		result = append(result, tsc)
	}
	return result
}
