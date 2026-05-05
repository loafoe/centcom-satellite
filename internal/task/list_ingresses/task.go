// Package list_ingresses provides ingress listing functionality.
package list_ingresses

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"time"

	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/loafoe/pico-agent/internal/task"
)

const TaskName = "list_ingresses"

// Payload for list_ingresses task.
type Payload struct {
	Namespace     string `json:"namespace,omitempty"`
	LabelSelector string `json:"label_selector,omitempty"`
}

// IngressList contains the ingress listing.
type IngressList struct {
	Total     int           `json:"total"`
	Ingresses []IngressInfo `json:"ingresses"`
}

// IngressInfo contains ingress details.
type IngressInfo struct {
	Name            string        `json:"name"`
	Namespace       string        `json:"namespace"`
	IngressClass    string        `json:"ingress_class,omitempty"`
	Rules           []IngressRule `json:"rules"`
	TLS             []IngressTLS  `json:"tls,omitempty"`
	LoadBalancerIPs []string      `json:"load_balancer_ips,omitempty"`
	Age             string        `json:"age"`
}

// IngressRule represents a rule in an Ingress.
type IngressRule struct {
	Host  string        `json:"host,omitempty"`
	Paths []IngressPath `json:"paths"`
}

// IngressPath represents a path in an Ingress rule.
type IngressPath struct {
	Path        string `json:"path"`
	PathType    string `json:"path_type"`
	ServiceName string `json:"service_name"`
	ServicePort string `json:"service_port"`
}

// IngressTLS represents TLS configuration.
type IngressTLS struct {
	Hosts      []string `json:"hosts"`
	SecretName string   `json:"secret_name,omitempty"`
}

// Task handles ingress listing.
type Task struct {
	clientset kubernetes.Interface
}

// New creates a new list ingresses task.
func New(clientset kubernetes.Interface) *Task {
	return &Task{clientset: clientset}
}

// Name returns the task type identifier.
func (t *Task) Name() string {
	return TaskName
}

// Execute lists ingresses in a namespace.
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

	ingresses, err := t.clientset.NetworkingV1().Ingresses(namespace).List(ctx, listOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to list ingresses: %w", err)
	}

	result := &IngressList{
		Total:     len(ingresses.Items),
		Ingresses: make([]IngressInfo, 0, len(ingresses.Items)),
	}

	for i := range ingresses.Items {
		ing := &ingresses.Items[i]
		ingInfo := t.buildIngressInfo(ing)
		result.Ingresses = append(result.Ingresses, ingInfo)
	}

	// Sort by namespace then name
	sort.Slice(result.Ingresses, func(i, j int) bool {
		if result.Ingresses[i].Namespace != result.Ingresses[j].Namespace {
			return result.Ingresses[i].Namespace < result.Ingresses[j].Namespace
		}
		return result.Ingresses[i].Name < result.Ingresses[j].Name
	})

	msg := fmt.Sprintf("Found %d ingresses in namespace %s", result.Total, namespace)
	if namespace == metav1.NamespaceAll {
		msg = fmt.Sprintf("Found %d ingresses across all namespaces", result.Total)
	}
	return task.NewSuccessResultWithDetails(msg, result), nil
}

func (t *Task) buildIngressInfo(ing *networkingv1.Ingress) IngressInfo {
	info := IngressInfo{
		Name:      ing.Name,
		Namespace: ing.Namespace,
		Age:       formatAge(ing.CreationTimestamp.Time),
		Rules:     make([]IngressRule, 0, len(ing.Spec.Rules)),
		TLS:       make([]IngressTLS, 0, len(ing.Spec.TLS)),
	}

	// Extract IngressClass (it's a pointer, so check for nil)
	if ing.Spec.IngressClassName != nil {
		info.IngressClass = *ing.Spec.IngressClassName
	}

	// Extract LoadBalancer IPs
	for _, ingress := range ing.Status.LoadBalancer.Ingress {
		if ingress.IP != "" {
			info.LoadBalancerIPs = append(info.LoadBalancerIPs, ingress.IP)
		}
	}

	// Build rules
	for _, rule := range ing.Spec.Rules {
		ingressRule := IngressRule{
			Host:  rule.Host,
			Paths: make([]IngressPath, 0),
		}

		if rule.HTTP != nil {
			for _, path := range rule.HTTP.Paths {
				ingressPath := IngressPath{
					Path: path.Path,
				}

				// PathType is a pointer
				if path.PathType != nil {
					ingressPath.PathType = string(*path.PathType)
				}

				// Extract service backend
				if path.Backend.Service != nil {
					ingressPath.ServiceName = path.Backend.Service.Name

					// Service port can be Name or Number
					if path.Backend.Service.Port.Name != "" {
						ingressPath.ServicePort = path.Backend.Service.Port.Name
					} else {
						ingressPath.ServicePort = strconv.FormatInt(int64(path.Backend.Service.Port.Number), 10)
					}
				}

				ingressRule.Paths = append(ingressRule.Paths, ingressPath)
			}
		}

		info.Rules = append(info.Rules, ingressRule)
	}

	// Build TLS configuration
	for _, tls := range ing.Spec.TLS {
		ingressTLS := IngressTLS{
			Hosts:      tls.Hosts,
			SecretName: tls.SecretName,
		}
		info.TLS = append(info.TLS, ingressTLS)
	}

	return info
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
