package get_resource

import (
	"fmt"
	"time"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// Summary is the LLM-optimized output format.
type Summary struct {
	APIVersion  string            `json:"apiVersion"`
	Kind        string            `json:"kind"`
	Name        string            `json:"name"`
	Namespace   string            `json:"namespace"`
	Scope       string            `json:"scope"`
	Age         string            `json:"age"`
	CreatedAt   string            `json:"createdAt"`
	Generation  int64             `json:"generation"`
	Labels      map[string]string `json:"labels,omitempty"`
	Annotations []string          `json:"annotations,omitempty"`
	Conditions  []Condition       `json:"conditions,omitempty"`
	Status      map[string]any    `json:"status,omitempty"`
}

// Condition represents a resource condition.
type Condition struct {
	Type               string `json:"type"`
	Status             string `json:"status"`
	Reason             string `json:"reason,omitempty"`
	Message            string `json:"message,omitempty"`
	LastTransitionTime string `json:"lastTransitionTime,omitempty"`
	Age                string `json:"age,omitempty"`
}

// ExtractSummary extracts a Summary from an unstructured resource.
func ExtractSummary(obj *unstructured.Unstructured, isNamespaced bool) *Summary {
	now := time.Now()

	summary := &Summary{
		APIVersion: obj.GetAPIVersion(),
		Kind:       obj.GetKind(),
		Name:       obj.GetName(),
		Namespace:  obj.GetNamespace(),
		Scope:      "cluster",
		Generation: obj.GetGeneration(),
		Labels:     obj.GetLabels(),
	}

	if isNamespaced {
		summary.Scope = "namespaced"
	}

	// Created timestamp and age
	createdAt := obj.GetCreationTimestamp()
	if !createdAt.IsZero() {
		summary.CreatedAt = createdAt.Format(time.RFC3339)
		summary.Age = formatDuration(now.Sub(createdAt.Time))
	}

	// Annotation keys only (values often too large)
	annotations := obj.GetAnnotations()
	if len(annotations) > 0 {
		keys := make([]string, 0, len(annotations))
		for k := range annotations {
			keys = append(keys, k)
		}
		summary.Annotations = keys
	}

	// Extract status fields
	status, found, _ := unstructured.NestedMap(obj.Object, "status")
	if found {
		summary.Conditions = extractConditions(status, now)
		summary.Status = extractStatusFields(status)
	}

	return summary
}

func extractConditions(status map[string]any, now time.Time) []Condition {
	conditionsRaw, found, _ := unstructured.NestedSlice(status, "conditions")
	if !found {
		return nil
	}

	conditions := make([]Condition, 0, len(conditionsRaw))
	for _, c := range conditionsRaw {
		condMap, ok := c.(map[string]any)
		if !ok {
			continue
		}

		cond := Condition{
			Type:    getString(condMap, "type"),
			Status:  getString(condMap, "status"),
			Reason:  getString(condMap, "reason"),
			Message: getString(condMap, "message"),
		}

		if lastTransition := getString(condMap, "lastTransitionTime"); lastTransition != "" {
			cond.LastTransitionTime = lastTransition
			if t, err := time.Parse(time.RFC3339, lastTransition); err == nil {
				cond.Age = formatDuration(now.Sub(t))
			}
		}

		conditions = append(conditions, cond)
	}

	return conditions
}

func extractStatusFields(status map[string]any) map[string]any {
	fields := make(map[string]any)

	// Phase (common in many resources)
	if phase, ok := status["phase"].(string); ok {
		fields["phase"] = phase
	}

	// Observed generation (staleness indicator)
	if og, ok := status["observedGeneration"]; ok {
		fields["observedGeneration"] = og
	}

	// Replica counts (workload-like resources)
	for _, key := range []string{"replicas", "readyReplicas", "availableReplicas", "updatedReplicas"} {
		if val, ok := status[key]; ok {
			fields[key] = val
		}
	}

	if len(fields) == 0 {
		return nil
	}
	return fields
}

func getString(m map[string]any, key string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}

func formatDuration(d time.Duration) string {
	if d < time.Minute {
		return "just now"
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm", int(d.Minutes()))
	}
	if d < 24*time.Hour {
		return fmt.Sprintf("%dh%dm", int(d.Hours()), int(d.Minutes())%60)
	}
	days := int(d.Hours() / 24)
	hours := int(d.Hours()) % 24
	return fmt.Sprintf("%dd%dh", days, hours)
}
