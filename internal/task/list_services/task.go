// Package list_services provides service listing functionality.
package list_services

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/kubernetes"

	"github.com/loafoe/pico-agent/internal/task"
)

const TaskName = "list_services"

// Payload for list_services task.
type Payload struct {
	Namespace       string `json:"namespace,omitempty"`
	LabelSelector   string `json:"label_selector,omitempty"`
	IncludePodCount bool   `json:"include_pod_count,omitempty"`
}

// ServiceList contains the service listing.
type ServiceList struct {
	Total    int           `json:"total"`
	Services []ServiceInfo `json:"services"`
}

// ServiceInfo contains service details.
type ServiceInfo struct {
	Name         string            `json:"name"`
	Namespace    string            `json:"namespace"`
	Type         string            `json:"type"`
	ClusterIP    string            `json:"cluster_ip"`
	ExternalIPs  []string          `json:"external_ips,omitempty"`
	ExternalName string            `json:"external_name,omitempty"`
	Ports        []PortInfo        `json:"ports"`
	Selector     map[string]string `json:"selector,omitempty"`
	PodCount     int               `json:"pod_count"`
	Age          string            `json:"age"`
}

// PortInfo contains port details.
type PortInfo struct {
	Name       string `json:"name,omitempty"`
	Port       int32  `json:"port"`
	TargetPort string `json:"target_port"`
	NodePort   int32  `json:"node_port,omitempty"`
	Protocol   string `json:"protocol"`
}

// Task handles service listing.
type Task struct {
	clientset kubernetes.Interface
}

// New creates a new list services task.
func New(clientset kubernetes.Interface) *Task {
	return &Task{clientset: clientset}
}

// Name returns the task type identifier.
func (t *Task) Name() string {
	return TaskName
}

// Execute lists services in a namespace.
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

	services, err := t.clientset.CoreV1().Services(namespace).List(ctx, listOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to list services: %w", err)
	}

	// Build pod index only if pod counts are requested (avoids N+1 queries)
	var podIndex map[string][]corev1.Pod
	if payload.IncludePodCount {
		podIndex, err = t.buildPodIndex(ctx, namespace)
		if err != nil {
			// Non-fatal: continue without pod counts
			podIndex = nil
		}
	}

	result := &ServiceList{
		Total:    len(services.Items),
		Services: make([]ServiceInfo, 0, len(services.Items)),
	}

	for i := range services.Items {
		svc := &services.Items[i]
		svcInfo := t.buildServiceInfo(svc, podIndex)
		result.Services = append(result.Services, svcInfo)
	}

	// Sort by namespace then name
	sort.Slice(result.Services, func(i, j int) bool {
		if result.Services[i].Namespace != result.Services[j].Namespace {
			return result.Services[i].Namespace < result.Services[j].Namespace
		}
		return result.Services[i].Name < result.Services[j].Name
	})

	msg := fmt.Sprintf("Found %d services in namespace %s", result.Total, namespace)
	if namespace == metav1.NamespaceAll {
		msg = fmt.Sprintf("Found %d services across all namespaces", result.Total)
	}
	return task.NewSuccessResultWithDetails(msg, result), nil
}

func (t *Task) buildServiceInfo(svc *corev1.Service, podIndex map[string][]corev1.Pod) ServiceInfo {
	info := ServiceInfo{
		Name:      svc.Name,
		Namespace: svc.Namespace,
		Type:      string(svc.Spec.Type),
		ClusterIP: svc.Spec.ClusterIP,
		Selector:  svc.Spec.Selector,
		Age:       formatAge(svc.CreationTimestamp.Time),
		Ports:     make([]PortInfo, 0, len(svc.Spec.Ports)),
	}

	// Build port info
	for _, port := range svc.Spec.Ports {
		portInfo := PortInfo{
			Name:       port.Name,
			Port:       port.Port,
			TargetPort: port.TargetPort.String(),
			Protocol:   string(port.Protocol),
		}
		if port.NodePort > 0 {
			portInfo.NodePort = port.NodePort
		}
		info.Ports = append(info.Ports, portInfo)
	}

	// Extract external IPs from LoadBalancer status
	if svc.Spec.Type == corev1.ServiceTypeLoadBalancer {
		for _, ingress := range svc.Status.LoadBalancer.Ingress {
			if ingress.IP != "" {
				info.ExternalIPs = append(info.ExternalIPs, ingress.IP)
			}
		}
	}

	// Include external name for ExternalName-type services
	if svc.Spec.Type == corev1.ServiceTypeExternalName {
		info.ExternalName = svc.Spec.ExternalName
	}

	// Count matching pods using pre-built index (if available)
	if podIndex != nil {
		info.PodCount = t.countMatchingPodsFromIndex(svc, podIndex)
	}

	return info
}

// buildPodIndex fetches all pods and indexes them by namespace for efficient matching.
func (t *Task) buildPodIndex(ctx context.Context, namespace string) (map[string][]corev1.Pod, error) {
	pods, err := t.clientset.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list pods: %w", err)
	}

	index := make(map[string][]corev1.Pod)
	for i := range pods.Items {
		pod := &pods.Items[i]
		index[pod.Namespace] = append(index[pod.Namespace], *pod)
	}
	return index, nil
}

// countMatchingPodsFromIndex counts pods matching the service selector using the pre-built index.
func (t *Task) countMatchingPodsFromIndex(svc *corev1.Service, podIndex map[string][]corev1.Pod) int {
	if len(svc.Spec.Selector) == 0 {
		return 0
	}

	selector := labels.SelectorFromSet(svc.Spec.Selector)
	count := 0

	for _, pod := range podIndex[svc.Namespace] {
		if selector.Matches(labels.Set(pod.Labels)) {
			count++
		}
	}
	return count
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
