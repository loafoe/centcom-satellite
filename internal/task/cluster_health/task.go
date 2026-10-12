// Package cluster_health provides cluster health check functionality.
package cluster_health

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/loafoe/centcom-satellite/internal/task"
)

const TaskName = "cluster_health"

// Payload for cluster_health task.
type Payload struct {
	// EventsMinutes is how far back to look for warning events (default: 30)
	EventsMinutes int `json:"events_minutes,omitempty"`
	// RestartWindowMinutes is how far back a container restart must have
	// occurred to flag a pod for high restart count (default: 180)
	RestartWindowMinutes int `json:"restart_window_minutes,omitempty"`
	// Namespace filters to a specific namespace (default: all namespaces)
	Namespace string `json:"namespace,omitempty"`
	// IncludeProbeWarnings includes startup/liveness/readiness probe
	// failure events (Warning events with Reason "Unhealthy") in
	// RecentEvents. Default false: these are excluded, since they're
	// frequently transient (node churn/rebalancing, brief network jitter —
	// see the aws-load-balancer-controller and centcom probe-timeout
	// investigations in AGENT.md for the same class of noise) and were
	// making buildSummary report "Cluster has issues" purely from
	// len(RecentEvents) > 0 even when nothing else was actually wrong.
	IncludeProbeWarnings bool `json:"include_probe_warnings,omitempty"`
	// NodeGracePeriodMinutes suppresses the NotReady condition on a node
	// younger than this (default: 5). A Karpenter-provisioned node is
	// legitimately NotReady for the first ~1-3 minutes while it boots and
	// the kubelet/CNI finish registering — flagging that as a cluster
	// health issue is a false positive, not a real problem. Only
	// NotReady is grace-perioded: MemoryPressure/DiskPressure/
	// PIDPressure/NetworkUnavailable on a brand-new node would still be
	// worth surfacing.
	NodeGracePeriodMinutes int `json:"node_grace_period_minutes,omitempty"`
}

// HealthReport contains the cluster health summary.
type HealthReport struct {
	Healthy       bool           `json:"healthy"`
	Summary       string         `json:"summary"`
	UnhealthyPods []UnhealthyPod `json:"unhealthy_pods,omitempty"`
	Workloads     WorkloadStatus `json:"workloads"`
	NodeIssues    []NodeIssue    `json:"node_issues,omitempty"`
	RecentEvents  []WarningEvent `json:"recent_events,omitempty"`
}

// UnhealthyPod represents a pod in a problematic state.
type UnhealthyPod struct {
	Namespace          string       `json:"namespace"`
	Name               string       `json:"name"`
	Phase              string       `json:"phase"`
	Reason             string       `json:"reason,omitempty"`
	Message            string       `json:"message,omitempty"`
	RestartCount       int32        `json:"restart_count,omitempty"`
	ContainerName      string       `json:"container_name,omitempty"`
	LastRestartTime    *metav1.Time `json:"last_restart_time,omitempty"`
	LastRestartReason  string       `json:"last_restart_reason,omitempty"`
	LastRestartMessage string       `json:"last_restart_message,omitempty"`
	// OwnerKind/OwnerName identify the workload that owns this pod — the
	// FINAL controller, not an intermediate ReplicaSet, so a Deployment's
	// own replica churn always resolves to the Deployment itself. Empty
	// when the pod has no controller owner reference (bare pods).
	OwnerKind string `json:"owner_kind,omitempty"`
	OwnerName string `json:"owner_name,omitempty"`
}

// WorkloadStatus summarizes deployment/statefulset/daemonset health.
type WorkloadStatus struct {
	Deployments  WorkloadSummary `json:"deployments"`
	StatefulSets WorkloadSummary `json:"statefulsets"`
	DaemonSets   WorkloadSummary `json:"daemonsets"`
}

// WorkloadSummary contains counts for a workload type.
type WorkloadSummary struct {
	Total     int            `json:"total"`
	Healthy   int            `json:"healthy"`
	Unhealthy int            `json:"unhealthy"`
	Degraded  []DegradedItem `json:"degraded,omitempty"`
}

// DegradedItem represents a workload not at desired state.
type DegradedItem struct {
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
	Ready     int32  `json:"ready"`
	Desired   int32  `json:"desired"`
}

// NodeIssue represents a node with problematic conditions.
type NodeIssue struct {
	Name       string   `json:"name"`
	Conditions []string `json:"conditions"`
}

// WarningEvent represents a warning event.
type WarningEvent struct {
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
	Kind      string `json:"kind"`
	Reason    string `json:"reason"`
	Message   string `json:"message"`
	Count     int32  `json:"count"`
	Age       string `json:"age"`
}

// Task handles cluster health checks.
type Task struct {
	clientset kubernetes.Interface
}

// New creates a new cluster health task.
func New(clientset kubernetes.Interface) *Task {
	return &Task{clientset: clientset}
}

// Name returns the task type identifier.
func (t *Task) Name() string {
	return TaskName
}

// Execute performs the cluster health check.
func (t *Task) Execute(ctx context.Context, rawPayload json.RawMessage) (*task.Result, error) {
	var payload Payload
	if len(rawPayload) > 0 && string(rawPayload) != "{}" {
		if err := json.Unmarshal(rawPayload, &payload); err != nil {
			return task.NewErrorResult(fmt.Sprintf("invalid payload: %v", err)), nil
		}
	}

	if payload.EventsMinutes == 0 {
		payload.EventsMinutes = 30
	}
	if payload.RestartWindowMinutes == 0 {
		payload.RestartWindowMinutes = 180
	}
	if payload.NodeGracePeriodMinutes == 0 {
		payload.NodeGracePeriodMinutes = 5
	}

	report := &HealthReport{
		Healthy: true,
	}

	namespace := payload.Namespace
	if namespace == "" {
		namespace = metav1.NamespaceAll
	}

	// Check pods
	unhealthyPods, err := t.checkPods(ctx, namespace, payload.RestartWindowMinutes)
	if err != nil {
		return nil, fmt.Errorf("failed to check pods: %w", err)
	}
	report.UnhealthyPods = unhealthyPods
	if len(unhealthyPods) > 0 {
		report.Healthy = false
	}

	// Check workloads
	workloads, err := t.checkWorkloads(ctx, namespace)
	if err != nil {
		return nil, fmt.Errorf("failed to check workloads: %w", err)
	}
	report.Workloads = workloads
	if workloads.Deployments.Unhealthy > 0 || workloads.StatefulSets.Unhealthy > 0 || workloads.DaemonSets.Unhealthy > 0 {
		report.Healthy = false
	}

	// Check node conditions (only for cluster-wide queries)
	if payload.Namespace == "" {
		nodeIssues, err := t.checkNodes(ctx, payload.NodeGracePeriodMinutes)
		if err != nil {
			return nil, fmt.Errorf("failed to check nodes: %w", err)
		}
		report.NodeIssues = nodeIssues
		if len(nodeIssues) > 0 {
			report.Healthy = false
		}
	}

	// Get recent warning events
	events, err := t.getWarningEvents(ctx, namespace, payload.EventsMinutes, payload.IncludeProbeWarnings)
	if err != nil {
		return nil, fmt.Errorf("failed to get events: %w", err)
	}
	report.RecentEvents = events

	// Build summary
	report.Summary = t.buildSummary(report)

	return task.NewSuccessResultWithDetails(report.Summary, report), nil
}

// resolveReplicaSetOwners maps ReplicaSet name -> its own controller
// owner's Kind/Name (normally the Deployment that created it), so a pod's
// OwnerReferences chain can be resolved to the FINAL workload in one extra
// List() call rather than per-pod API round trips. A ReplicaSet with no
// controller owner (standalone, not Deployment-managed) is simply absent
// from the map — callers fall back to reporting "ReplicaSet"/its own name.
func (t *Task) resolveReplicaSetOwners(ctx context.Context, namespace string) (map[string]metav1.OwnerReference, error) {
	rsList, err := t.clientset.AppsV1().ReplicaSets(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	owners := make(map[string]metav1.OwnerReference, len(rsList.Items))
	for _, rs := range rsList.Items {
		for _, ref := range rs.OwnerReferences {
			if ref.Controller != nil && *ref.Controller {
				owners[rs.Name] = ref
				break
			}
		}
	}
	return owners, nil
}

// resolvePodOwner returns the FINAL controller workload for pod: its own
// controller owner reference, with a ReplicaSet owner further resolved to
// the Deployment that owns the ReplicaSet (via rsOwners). Returns empty
// strings for a bare pod with no controller owner.
func resolvePodOwner(pod *corev1.Pod, rsOwners map[string]metav1.OwnerReference) (kind, name string) {
	for _, ref := range pod.OwnerReferences {
		if ref.Controller == nil || !*ref.Controller {
			continue
		}
		if ref.Kind == "ReplicaSet" {
			if owner, ok := rsOwners[ref.Name]; ok {
				return owner.Kind, owner.Name
			}
		}
		return ref.Kind, ref.Name
	}
	return "", ""
}

func (t *Task) checkPods(ctx context.Context, namespace string, restartWindowMinutes int) ([]UnhealthyPod, error) {
	restartWindow := time.Duration(restartWindowMinutes) * time.Minute
	pods, err := t.clientset.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	rsOwners, err := t.resolveReplicaSetOwners(ctx, namespace)
	if err != nil {
		return nil, err
	}

	var unhealthy []UnhealthyPod
	for _, pod := range pods.Items {
		ownerKind, ownerName := resolvePodOwner(&pod, rsOwners)
		// Skip completed pods
		if pod.Status.Phase == corev1.PodSucceeded {
			continue
		}

		// Check for non-running pods
		if pod.Status.Phase != corev1.PodRunning {
			up := UnhealthyPod{
				Namespace: pod.Namespace,
				Name:      pod.Name,
				Phase:     string(pod.Status.Phase),
				OwnerKind: ownerKind,
				OwnerName: ownerName,
			}
			if pod.Status.Reason != "" {
				up.Reason = pod.Status.Reason
			}
			if pod.Status.Message != "" {
				up.Message = pod.Status.Message
			}
			unhealthy = append(unhealthy, up)
			continue
		}

		// Check container statuses for running pods
		for _, cs := range pod.Status.ContainerStatuses {
			if cs.State.Waiting != nil {
				up := UnhealthyPod{
					Namespace:     pod.Namespace,
					Name:          pod.Name,
					Phase:         "Waiting",
					Reason:        cs.State.Waiting.Reason,
					Message:       cs.State.Waiting.Message,
					ContainerName: cs.Name,
					RestartCount:  cs.RestartCount,
					OwnerKind:     ownerKind,
					OwnerName:     ownerName,
				}
				if cs.LastTerminationState.Terminated != nil {
					tTerm := cs.LastTerminationState.Terminated
					if !tTerm.FinishedAt.IsZero() {
						up.LastRestartTime = &tTerm.FinishedAt
					}
					up.LastRestartReason = tTerm.Reason
					up.LastRestartMessage = tTerm.Message
				}
				unhealthy = append(unhealthy, up)
			} else if cs.RestartCount > 5 {
				// Flag pods with high restart counts only if a restart occurred within the last 3 hours
				lastRestart := getLastRestartTime(cs)
				var shouldFlag bool
				if !lastRestart.IsZero() {
					shouldFlag = time.Since(lastRestart) <= restartWindow
				} else {
					shouldFlag = time.Since(pod.CreationTimestamp.Time) <= restartWindow
				}

				if shouldFlag {
					up := UnhealthyPod{
						Namespace:     pod.Namespace,
						Name:          pod.Name,
						Phase:         "HighRestarts",
						Reason:        fmt.Sprintf("%d restarts", cs.RestartCount),
						ContainerName: cs.Name,
						RestartCount:  cs.RestartCount,
						OwnerKind:     ownerKind,
						OwnerName:     ownerName,
					}
					if cs.LastTerminationState.Terminated != nil {
						tTerm := cs.LastTerminationState.Terminated
						if !tTerm.FinishedAt.IsZero() {
							up.LastRestartTime = &tTerm.FinishedAt
						}
						up.LastRestartReason = tTerm.Reason
						up.LastRestartMessage = tTerm.Message
					}
					unhealthy = append(unhealthy, up)
				}
			}
		}
	}

	return unhealthy, nil
}

func (t *Task) checkWorkloads(ctx context.Context, namespace string) (WorkloadStatus, error) {
	status := WorkloadStatus{}

	// Deployments
	deployments, err := t.clientset.AppsV1().Deployments(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return status, err
	}
	status.Deployments = t.summarizeDeployments(deployments)

	// StatefulSets
	statefulsets, err := t.clientset.AppsV1().StatefulSets(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return status, err
	}
	status.StatefulSets = t.summarizeStatefulSets(statefulsets)

	// DaemonSets
	daemonsets, err := t.clientset.AppsV1().DaemonSets(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return status, err
	}
	status.DaemonSets = t.summarizeDaemonSets(daemonsets)

	return status, nil
}

func (t *Task) summarizeDeployments(list *appsv1.DeploymentList) WorkloadSummary {
	summary := WorkloadSummary{Total: len(list.Items)}
	for _, d := range list.Items {
		desired := int32(1)
		if d.Spec.Replicas != nil {
			desired = *d.Spec.Replicas
		}
		if d.Status.ReadyReplicas >= desired {
			summary.Healthy++
		} else {
			summary.Unhealthy++
			summary.Degraded = append(summary.Degraded, DegradedItem{
				Namespace: d.Namespace,
				Name:      d.Name,
				Ready:     d.Status.ReadyReplicas,
				Desired:   desired,
			})
		}
	}
	return summary
}

func (t *Task) summarizeStatefulSets(list *appsv1.StatefulSetList) WorkloadSummary {
	summary := WorkloadSummary{Total: len(list.Items)}
	for _, s := range list.Items {
		desired := int32(1)
		if s.Spec.Replicas != nil {
			desired = *s.Spec.Replicas
		}
		if s.Status.ReadyReplicas >= desired {
			summary.Healthy++
		} else {
			summary.Unhealthy++
			summary.Degraded = append(summary.Degraded, DegradedItem{
				Namespace: s.Namespace,
				Name:      s.Name,
				Ready:     s.Status.ReadyReplicas,
				Desired:   desired,
			})
		}
	}
	return summary
}

func (t *Task) summarizeDaemonSets(list *appsv1.DaemonSetList) WorkloadSummary {
	summary := WorkloadSummary{Total: len(list.Items)}
	for _, d := range list.Items {
		if d.Status.NumberReady >= d.Status.DesiredNumberScheduled {
			summary.Healthy++
		} else {
			summary.Unhealthy++
			summary.Degraded = append(summary.Degraded, DegradedItem{
				Namespace: d.Namespace,
				Name:      d.Name,
				Ready:     d.Status.NumberReady,
				Desired:   d.Status.DesiredNumberScheduled,
			})
		}
	}
	return summary
}

func (t *Task) checkNodes(ctx context.Context, gracePeriodMinutes int) ([]NodeIssue, error) {
	nodes, err := t.clientset.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	gracePeriod := time.Duration(gracePeriodMinutes) * time.Minute
	now := time.Now()

	var issues []NodeIssue
	for _, node := range nodes.Items {
		withinGracePeriod := now.Sub(node.CreationTimestamp.Time) < gracePeriod
		var conditions []string
		for _, cond := range node.Status.Conditions {
			switch cond.Type {
			case corev1.NodeReady:
				// A node still inside its grace period is routinely
				// NotReady for its first ~1-3 minutes while kubelet/CNI
				// finish registering (e.g. a Karpenter node spinning up)
				// - that's expected, not a cluster health issue.
				if cond.Status != corev1.ConditionTrue && !withinGracePeriod {
					conditions = append(conditions, "NotReady")
				}
			case corev1.NodeMemoryPressure:
				if cond.Status == corev1.ConditionTrue {
					conditions = append(conditions, "MemoryPressure")
				}
			case corev1.NodeDiskPressure:
				if cond.Status == corev1.ConditionTrue {
					conditions = append(conditions, "DiskPressure")
				}
			case corev1.NodePIDPressure:
				if cond.Status == corev1.ConditionTrue {
					conditions = append(conditions, "PIDPressure")
				}
			case corev1.NodeNetworkUnavailable:
				if cond.Status == corev1.ConditionTrue {
					conditions = append(conditions, "NetworkUnavailable")
				}
			}
		}
		if len(conditions) > 0 {
			issues = append(issues, NodeIssue{
				Name:       node.Name,
				Conditions: conditions,
			})
		}
	}

	return issues, nil
}

// probeWarningReason is the Reason Kubernetes' kubelet uses for all three
// probe types (startup, liveness, readiness) on failure.
const probeWarningReason = "Unhealthy"

func (t *Task) getWarningEvents(ctx context.Context, namespace string, minutes int, includeProbeWarnings bool) ([]WarningEvent, error) {
	events, err := t.clientset.CoreV1().Events(namespace).List(ctx, metav1.ListOptions{
		FieldSelector: "type=Warning",
	})
	if err != nil {
		return nil, err
	}

	cutoff := time.Now().Add(-time.Duration(minutes) * time.Minute)
	var warnings []WarningEvent

	for _, e := range events.Items {
		if !includeProbeWarnings && e.Reason == probeWarningReason {
			continue
		}

		eventTime := e.LastTimestamp.Time
		if eventTime.IsZero() {
			eventTime = e.EventTime.Time
		}
		if eventTime.IsZero() {
			eventTime = e.CreationTimestamp.Time
		}

		if eventTime.After(cutoff) {
			warnings = append(warnings, WarningEvent{
				Namespace: e.Namespace,
				Name:      e.InvolvedObject.Name,
				Kind:      e.InvolvedObject.Kind,
				Reason:    e.Reason,
				Message:   e.Message,
				Count:     e.Count,
				Age:       time.Since(eventTime).Round(time.Second).String(),
			})
		}
	}

	return warnings, nil
}

func (t *Task) buildSummary(report *HealthReport) string {
	if report.Healthy && len(report.RecentEvents) == 0 {
		return "Cluster is healthy - all workloads running, no node issues, no recent warnings"
	}

	var issues []string
	if len(report.UnhealthyPods) > 0 {
		issues = append(issues, fmt.Sprintf("%d unhealthy pods", len(report.UnhealthyPods)))
	}
	if report.Workloads.Deployments.Unhealthy > 0 {
		issues = append(issues, fmt.Sprintf("%d degraded deployments", report.Workloads.Deployments.Unhealthy))
	}
	if report.Workloads.StatefulSets.Unhealthy > 0 {
		issues = append(issues, fmt.Sprintf("%d degraded statefulsets", report.Workloads.StatefulSets.Unhealthy))
	}
	if report.Workloads.DaemonSets.Unhealthy > 0 {
		issues = append(issues, fmt.Sprintf("%d degraded daemonsets", report.Workloads.DaemonSets.Unhealthy))
	}
	if len(report.NodeIssues) > 0 {
		issues = append(issues, fmt.Sprintf("%d nodes with issues", len(report.NodeIssues)))
	}
	if len(report.RecentEvents) > 0 {
		issues = append(issues, fmt.Sprintf("%d warning events", len(report.RecentEvents)))
	}

	if len(issues) == 0 {
		return "Cluster is healthy"
	}

	return fmt.Sprintf("Cluster has issues: %v", issues)
}

func getLastRestartTime(cs corev1.ContainerStatus) time.Time {
	var lastTime time.Time
	if cs.LastTerminationState.Terminated != nil && !cs.LastTerminationState.Terminated.FinishedAt.IsZero() {
		lastTime = cs.LastTerminationState.Terminated.FinishedAt.Time
	}
	if cs.State.Running != nil && !cs.State.Running.StartedAt.IsZero() {
		runningTime := cs.State.Running.StartedAt.Time
		if runningTime.After(lastTime) {
			lastTime = runningTime
		}
	}
	return lastTime
}
