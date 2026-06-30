// Package list_vpas provides VerticalPodAutoscaler listing functionality.
package list_vpas

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"

	"github.com/loafoe/centcom-satellite/internal/task"
)

const TaskName = "list_vpas"

var vpaGVR = schema.GroupVersionResource{
	Group:    "autoscaling.k8s.io",
	Version:  "v1",
	Resource: "verticalpodautoscalers",
}

// Payload for list_vpas task.
type Payload struct {
	Namespace string `json:"namespace"` // required, or empty for all
}

// VPAList contains the VPA listing.
type VPAList struct {
	Total        int       `json:"total"`
	VPAs         []VPAInfo `json:"vpas"`
	VPAInstalled bool      `json:"vpa_installed"`
}

// VPAInfo contains VerticalPodAutoscaler details.
type VPAInfo struct {
	Name           string                `json:"name"`
	Namespace      string                `json:"namespace"`
	TargetRef      TargetRef             `json:"target_ref"`
	UpdateMode     string                `json:"update_mode"`
	Containers     []ContainerVPAInfo    `json:"containers,omitempty"`
	Recommendations []ContainerRecommend `json:"recommendations,omitempty"`
	Age            string                `json:"age"`
}

// TargetRef identifies the workload a VPA targets.
type TargetRef struct {
	Kind string `json:"kind"`
	Name string `json:"name"`
}

// ContainerVPAInfo contains per-container VPA policy.
type ContainerVPAInfo struct {
	Name      string `json:"name"`
	Mode      string `json:"mode,omitempty"`
	MinCPU    string `json:"min_cpu,omitempty"`
	MaxCPU    string `json:"max_cpu,omitempty"`
	MinMemory string `json:"min_memory,omitempty"`
	MaxMemory string `json:"max_memory,omitempty"`
}

// ContainerRecommend contains VPA recommendations for a container.
type ContainerRecommend struct {
	Name           string `json:"name"`
	LowerCPU       string `json:"lower_cpu,omitempty"`
	TargetCPU      string `json:"target_cpu,omitempty"`
	UpperCPU       string `json:"upper_cpu,omitempty"`
	LowerMemory    string `json:"lower_memory,omitempty"`
	TargetMemory   string `json:"target_memory,omitempty"`
	UpperMemory    string `json:"upper_memory,omitempty"`
}

// Task handles VPA listing.
type Task struct {
	clientset     kubernetes.Interface
	dynamicClient dynamic.Interface
}

// New creates a new list VPAs task.
func New(clientset kubernetes.Interface, dynamicClient dynamic.Interface) *Task {
	return &Task{clientset: clientset, dynamicClient: dynamicClient}
}

// Name returns the task type identifier.
func (t *Task) Name() string {
	return TaskName
}

// Execute lists VPAs in a namespace.
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

	var list *unstructured.UnstructuredList
	var err error
	if namespace == metav1.NamespaceAll {
		list, err = t.dynamicClient.Resource(vpaGVR).List(ctx, metav1.ListOptions{})
	} else {
		list, err = t.dynamicClient.Resource(vpaGVR).Namespace(namespace).List(ctx, metav1.ListOptions{})
	}
	if err != nil {
		// Gracefully handle missing CRD - return empty list with vpa_installed=false
		result := &VPAList{
			Total:        0,
			VPAs:         []VPAInfo{},
			VPAInstalled: false,
		}
		return task.NewSuccessResultWithDetails("VPA CRD not installed", result), nil
	}

	vpas := make([]VPAInfo, 0, len(list.Items))
	for _, item := range list.Items {
		info := t.buildVPAInfo(&item)
		vpas = append(vpas, info)
	}

	sort.Slice(vpas, func(i, j int) bool {
		if vpas[i].Namespace != vpas[j].Namespace {
			return vpas[i].Namespace < vpas[j].Namespace
		}
		return vpas[i].Name < vpas[j].Name
	})

	result := &VPAList{
		Total:        len(vpas),
		VPAs:         vpas,
		VPAInstalled: true,
	}

	return task.NewSuccessResultWithDetails(
		fmt.Sprintf("Found %d VPAs", result.Total),
		result,
	), nil
}

func (t *Task) buildVPAInfo(obj *unstructured.Unstructured) VPAInfo {
	info := VPAInfo{
		Name:      obj.GetName(),
		Namespace: obj.GetNamespace(),
		Age:       formatAge(obj.GetCreationTimestamp().Time),
	}

	// Extract spec.targetRef
	if spec, ok := obj.Object["spec"].(map[string]interface{}); ok {
		if targetRef, ok := spec["targetRef"].(map[string]interface{}); ok {
			info.TargetRef.Kind, _ = targetRef["kind"].(string)
			info.TargetRef.Name, _ = targetRef["name"].(string)
		}
		// Extract updatePolicy.updateMode
		if updatePolicy, ok := spec["updatePolicy"].(map[string]interface{}); ok {
			if mode, ok := updatePolicy["updateMode"].(string); ok {
				info.UpdateMode = mode
			}
		}
		if info.UpdateMode == "" {
			info.UpdateMode = "Auto" // default
		}
		// Extract resourcePolicy.containerPolicies
		if resourcePolicy, ok := spec["resourcePolicy"].(map[string]interface{}); ok {
			if containerPolicies, ok := resourcePolicy["containerPolicies"].([]interface{}); ok {
				for _, cp := range containerPolicies {
					if policy, ok := cp.(map[string]interface{}); ok {
						ci := ContainerVPAInfo{}
						ci.Name, _ = policy["containerName"].(string)
						if mode, ok := policy["mode"].(string); ok {
							ci.Mode = mode
						}
						if minAllowed, ok := policy["minAllowed"].(map[string]interface{}); ok {
							ci.MinCPU, _ = minAllowed["cpu"].(string)
							ci.MinMemory, _ = minAllowed["memory"].(string)
						}
						if maxAllowed, ok := policy["maxAllowed"].(map[string]interface{}); ok {
							ci.MaxCPU, _ = maxAllowed["cpu"].(string)
							ci.MaxMemory, _ = maxAllowed["memory"].(string)
						}
						info.Containers = append(info.Containers, ci)
					}
				}
			}
		}
	}

	// Extract status.recommendation.containerRecommendations
	if status, ok := obj.Object["status"].(map[string]interface{}); ok {
		if rec, ok := status["recommendation"].(map[string]interface{}); ok {
			if containerRecs, ok := rec["containerRecommendations"].([]interface{}); ok {
				for _, cr := range containerRecs {
					if recMap, ok := cr.(map[string]interface{}); ok {
						recommend := ContainerRecommend{}
						recommend.Name, _ = recMap["containerName"].(string)
						if lowerBound, ok := recMap["lowerBound"].(map[string]interface{}); ok {
							recommend.LowerCPU, _ = lowerBound["cpu"].(string)
							recommend.LowerMemory, _ = lowerBound["memory"].(string)
						}
						if target, ok := recMap["target"].(map[string]interface{}); ok {
							recommend.TargetCPU, _ = target["cpu"].(string)
							recommend.TargetMemory, _ = target["memory"].(string)
						}
						if upperBound, ok := recMap["upperBound"].(map[string]interface{}); ok {
							recommend.UpperCPU, _ = upperBound["cpu"].(string)
							recommend.UpperMemory, _ = upperBound["memory"].(string)
						}
						info.Recommendations = append(info.Recommendations, recommend)
					}
				}
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
