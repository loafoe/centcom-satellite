// Package list_nodepools provides NodePool listing functionality for Karpenter.
package list_nodepools

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"

	"github.com/loafoe/centcom-satellite/internal/task"
)

const TaskName = "list_nodepools"

var nodePoolGVR = schema.GroupVersionResource{
	Group:    "karpenter.sh",
	Version:  "v1",
	Resource: "nodepools",
}

// Payload for list_nodepools task.
type Payload struct {
	Name string `json:"name,omitempty"` // Filter by specific nodepool name
}

// NodePoolList contains the listing result.
type NodePoolList struct {
	Total            int            `json:"total"`
	NodePools        []NodePoolInfo `json:"nodepools"`
	KarpenterInstalled bool         `json:"karpenter_installed"`
}

// NodePoolInfo contains NodePool details.
type NodePoolInfo struct {
	Name        string `json:"name"`
	Status      string `json:"status"`
	Age         string `json:"age"`
	NodeCount   int64  `json:"node_count"`
	NodeClassRef NodeClassRef `json:"node_class_ref"`

	// Resource limits
	Limits ResourceLimits `json:"limits,omitempty"`

	// Current resource usage from status
	Resources ResourceStatus `json:"resources,omitempty"`

	// Disruption settings
	Disruption DisruptionConfig `json:"disruption,omitempty"`

	// Node requirements
	Requirements []Requirement `json:"requirements,omitempty"`

	// Template settings
	ExpireAfter            string `json:"expire_after,omitempty"`
	TerminationGracePeriod string `json:"termination_grace_period,omitempty"`
}

// NodeClassRef identifies the EC2NodeClass or similar
type NodeClassRef struct {
	Group string `json:"group,omitempty"`
	Kind  string `json:"kind,omitempty"`
	Name  string `json:"name"`
}

// ResourceLimits contains the configured limits
type ResourceLimits struct {
	CPU    string `json:"cpu,omitempty"`
	Memory string `json:"memory,omitempty"`
	GPU    string `json:"gpu,omitempty"`
}

// ResourceStatus contains current allocated resources
type ResourceStatus struct {
	CPU              string `json:"cpu,omitempty"`
	Memory           string `json:"memory,omitempty"`
	EphemeralStorage string `json:"ephemeral_storage,omitempty"`
	Pods             string `json:"pods,omitempty"`
}

// DisruptionConfig contains disruption policy settings
type DisruptionConfig struct {
	ConsolidationPolicy string `json:"consolidation_policy,omitempty"`
	ConsolidateAfter    string `json:"consolidate_after,omitempty"`
	BudgetNodes         string `json:"budget_nodes,omitempty"`
}

// Requirement represents a node requirement
type Requirement struct {
	Key      string   `json:"key"`
	Operator string   `json:"operator"`
	Values   []string `json:"values,omitempty"`
}

// Task handles NodePool listing.
type Task struct {
	dynamicClient dynamic.Interface
}

// New creates a new list_nodepools task.
func New(dynamicClient dynamic.Interface) *Task {
	return &Task{dynamicClient: dynamicClient}
}

// Name returns the task type identifier.
func (t *Task) Name() string {
	return TaskName
}

// Execute lists NodePools in the cluster.
func (t *Task) Execute(ctx context.Context, rawPayload json.RawMessage) (*task.Result, error) {
	var payload Payload
	if len(rawPayload) > 0 && string(rawPayload) != "{}" {
		if err := json.Unmarshal(rawPayload, &payload); err != nil {
			return task.NewErrorResult(fmt.Sprintf("invalid payload: %v", err)), nil
		}
	}

	nodePools, err := t.dynamicClient.Resource(nodePoolGVR).List(ctx, metav1.ListOptions{})
	if err != nil {
		if isCRDNotInstalled(err) {
			return task.NewSuccessResultWithDetails(
				"Karpenter NodePools CRD not installed in this cluster",
				&NodePoolList{Total: 0, NodePools: []NodePoolInfo{}, KarpenterInstalled: false},
			), nil
		}
		return nil, fmt.Errorf("failed to list nodepools: %w", err)
	}

	result := &NodePoolList{
		NodePools:        make([]NodePoolInfo, 0, len(nodePools.Items)),
		KarpenterInstalled: true,
	}

	for i := range nodePools.Items {
		np := &nodePools.Items[i]

		// Filter by name if specified
		if payload.Name != "" && np.GetName() != payload.Name {
			continue
		}

		info := t.buildNodePoolInfo(np)
		result.NodePools = append(result.NodePools, info)
	}

	result.Total = len(result.NodePools)

	// Sort by name
	sort.Slice(result.NodePools, func(i, j int) bool {
		return result.NodePools[i].Name < result.NodePools[j].Name
	})

	msg := fmt.Sprintf("Found %d NodePools", result.Total)
	if payload.Name != "" {
		if result.Total == 0 {
			msg = fmt.Sprintf("NodePool %s not found", payload.Name)
		} else {
			msg = fmt.Sprintf("Found NodePool %s", payload.Name)
		}
	}
	return task.NewSuccessResultWithDetails(msg, result), nil
}

func (t *Task) buildNodePoolInfo(np *unstructured.Unstructured) NodePoolInfo {
	info := NodePoolInfo{
		Name:   np.GetName(),
		Status: getNodePoolStatus(np),
		Age:    formatAge(np.GetCreationTimestamp().Time),
	}

	// Extract node count from status
	if nodes, found, err := unstructured.NestedInt64(np.Object, "status", "nodes"); err == nil && found {
		info.NodeCount = nodes
	}

	// Extract nodeClassRef
	if ref, found, err := unstructured.NestedMap(np.Object, "spec", "template", "spec", "nodeClassRef"); err == nil && found {
		info.NodeClassRef.Name, _ = ref["name"].(string)
		info.NodeClassRef.Kind, _ = ref["kind"].(string)
		info.NodeClassRef.Group, _ = ref["group"].(string)
	}

	// Extract limits
	if limits, found, err := unstructured.NestedMap(np.Object, "spec", "limits"); err == nil && found {
		if cpu, ok := limits["cpu"]; ok {
			info.Limits.CPU = fmt.Sprintf("%v", cpu)
		}
		if mem, ok := limits["memory"]; ok {
			info.Limits.Memory = fmt.Sprintf("%v", mem)
		}
		// Check for GPU limits
		if gpu, ok := limits["nvidia.com/gpu"]; ok {
			info.Limits.GPU = fmt.Sprintf("%v", gpu)
		}
	}

	// Extract current resource usage from status
	if resources, found, err := unstructured.NestedMap(np.Object, "status", "resources"); err == nil && found {
		if cpu, ok := resources["cpu"]; ok {
			info.Resources.CPU = fmt.Sprintf("%v", cpu)
		}
		if mem, ok := resources["memory"]; ok {
			info.Resources.Memory = fmt.Sprintf("%v", mem)
		}
		if storage, ok := resources["ephemeral-storage"]; ok {
			info.Resources.EphemeralStorage = fmt.Sprintf("%v", storage)
		}
		if pods, ok := resources["pods"]; ok {
			info.Resources.Pods = fmt.Sprintf("%v", pods)
		}
	}

	// Extract disruption config
	if disruption, found, err := unstructured.NestedMap(np.Object, "spec", "disruption"); err == nil && found {
		if policy, ok := disruption["consolidationPolicy"].(string); ok {
			info.Disruption.ConsolidationPolicy = policy
		}
		if after, ok := disruption["consolidateAfter"].(string); ok {
			info.Disruption.ConsolidateAfter = after
		}
		// Extract budget
		if budgets, ok := disruption["budgets"].([]interface{}); ok && len(budgets) > 0 {
			if budget, ok := budgets[0].(map[string]interface{}); ok {
				if nodes, ok := budget["nodes"]; ok {
					info.Disruption.BudgetNodes = fmt.Sprintf("%v", nodes)
				}
			}
		}
	}

	// Extract requirements
	if reqs, found, err := unstructured.NestedSlice(np.Object, "spec", "template", "spec", "requirements"); err == nil && found {
		for _, r := range reqs {
			req, ok := r.(map[string]interface{})
			if !ok {
				continue
			}
			requirement := Requirement{
				Key:      getString(req, "key"),
				Operator: getString(req, "operator"),
			}
			if values, ok := req["values"].([]interface{}); ok {
				for _, v := range values {
					if s, ok := v.(string); ok {
						requirement.Values = append(requirement.Values, s)
					}
				}
			}
			info.Requirements = append(info.Requirements, requirement)
		}
	}

	// Extract template settings
	if expireAfter, found, err := unstructured.NestedString(np.Object, "spec", "template", "spec", "expireAfter"); err == nil && found {
		info.ExpireAfter = expireAfter
	}
	if termGrace, found, err := unstructured.NestedString(np.Object, "spec", "template", "spec", "terminationGracePeriod"); err == nil && found {
		info.TerminationGracePeriod = termGrace
	}

	return info
}

func getString(m map[string]interface{}, key string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}

func getNodePoolStatus(np *unstructured.Unstructured) string {
	conditions, found, err := unstructured.NestedSlice(np.Object, "status", "conditions")
	if err != nil || !found {
		return "Unknown"
	}

	// Check conditions
	conditionMap := make(map[string]string)
	for _, c := range conditions {
		cond, ok := c.(map[string]interface{})
		if !ok {
			continue
		}
		condType, _ := cond["type"].(string)
		status, _ := cond["status"].(string)
		conditionMap[condType] = status
	}

	if conditionMap["Ready"] == "True" {
		return "Ready"
	}
	if conditionMap["ValidationSucceeded"] == "False" {
		return "Invalid"
	}
	if conditionMap["NodeClassReady"] == "False" {
		return "NodeClassNotReady"
	}

	return "NotReady"
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

func isCRDNotInstalled(err error) bool {
	errStr := err.Error()
	return strings.Contains(errStr, "the server could not find the requested resource") ||
		strings.Contains(errStr, "no matches for kind")
}
