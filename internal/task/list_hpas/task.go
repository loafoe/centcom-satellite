// Package list_hpas provides HorizontalPodAutoscaler listing functionality.
package list_hpas

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	autoscalingv2 "k8s.io/api/autoscaling/v2"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	k8sclient "github.com/loafoe/centcom-satellite/internal/k8s"
	"github.com/loafoe/centcom-satellite/internal/task"
)

const TaskName = "list_hpas"

// Payload for list_hpas task.
type Payload struct {
	Namespace string `json:"namespace"` // required, or empty for all
}

// HPAList contains the HPA listing.
type HPAList struct {
	Total int       `json:"total"`
	HPAs  []HPAInfo `json:"hpas"`
}

// HPAInfo contains HorizontalPodAutoscaler details, including which
// workload it targets - unlike list_workloads' own HPAInfo (which is
// already attached to the workload it matched, so doesn't need to repeat
// the target), a standalone listing needs to say what each HPA is for.
type HPAInfo struct {
	Name            string      `json:"name"`
	Namespace       string      `json:"namespace"`
	TargetRef       TargetRef   `json:"target_ref"`
	MinReplicas     int32       `json:"min_replicas"`
	MaxReplicas     int32       `json:"max_replicas"`
	CurrentReplicas int32       `json:"current_replicas"`
	DesiredReplicas int32       `json:"desired_replicas"`
	Metrics         []HPAMetric `json:"metrics,omitempty"`
	Age             string      `json:"age"`
}

// TargetRef identifies the workload an HPA targets.
type TargetRef struct {
	Kind string `json:"kind"`
	Name string `json:"name"`
}

// HPAMetric contains HPA metric details.
type HPAMetric struct {
	Type    string `json:"type"`
	Name    string `json:"name,omitempty"`
	Current string `json:"current,omitempty"`
	Target  string `json:"target,omitempty"`
}

// Task handles HPA listing.
type Task struct {
	clientset kubernetes.Interface
}

// New creates a new list HPAs task.
func New(clientset kubernetes.Interface) *Task {
	return &Task{clientset: clientset}
}

// Name returns the task type identifier.
func (t *Task) Name() string {
	return TaskName
}

// Execute lists HPAs in a namespace (or all namespaces).
func (t *Task) Execute(ctx context.Context, rawPayload json.RawMessage) (*task.Result, error) {
	var payload Payload
	if len(rawPayload) > 0 && string(rawPayload) != "{}" {
		if err := json.Unmarshal(rawPayload, &payload); err != nil {
			return task.NewErrorResult(fmt.Sprintf("invalid payload: %v", err)), nil
		}
	}

	namespace := payload.Namespace
	if namespace == "" {
		namespace = metav1.NamespaceAll
	}

	hpas, err := t.clientset.AutoscalingV2().HorizontalPodAutoscalers(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return k8sclient.WrapError("failed to list HPAs", err)
	}

	infos := make([]HPAInfo, 0, len(hpas.Items))
	for i := range hpas.Items {
		infos = append(infos, buildHPAInfo(&hpas.Items[i]))
	}

	sort.Slice(infos, func(i, j int) bool {
		if infos[i].Namespace != infos[j].Namespace {
			return infos[i].Namespace < infos[j].Namespace
		}
		return infos[i].Name < infos[j].Name
	})

	result := &HPAList{Total: len(infos), HPAs: infos}

	msg := fmt.Sprintf("Found %d HPAs in namespace %s", result.Total, namespace)
	if namespace == metav1.NamespaceAll {
		msg = fmt.Sprintf("Found %d HPAs across all namespaces", result.Total)
	}
	return task.NewSuccessResultWithDetails(msg, result), nil
}

func buildHPAInfo(hpa *autoscalingv2.HorizontalPodAutoscaler) HPAInfo {
	info := HPAInfo{
		Name:            hpa.Name,
		Namespace:       hpa.Namespace,
		TargetRef:       TargetRef{Kind: hpa.Spec.ScaleTargetRef.Kind, Name: hpa.Spec.ScaleTargetRef.Name},
		MaxReplicas:     hpa.Spec.MaxReplicas,
		CurrentReplicas: hpa.Status.CurrentReplicas,
		DesiredReplicas: hpa.Status.DesiredReplicas,
		Age:             formatAge(hpa.CreationTimestamp.Time),
	}
	if hpa.Spec.MinReplicas != nil {
		info.MinReplicas = *hpa.Spec.MinReplicas
	} else {
		info.MinReplicas = 1
	}

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
