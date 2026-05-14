// Package list_nodeclaims provides NodeClaim listing functionality for Karpenter.
package list_nodeclaims

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

	"github.com/loafoe/pico-agent/internal/task"
)

const (
	TaskName      = "list_nodeclaims"
	NodePoolLabel = "karpenter.sh/nodepool"
)

var nodeClaimGVR = schema.GroupVersionResource{
	Group:    "karpenter.sh",
	Version:  "v1",
	Resource: "nodeclaims",
}

// Payload for list_nodeclaims task.
type Payload struct {
	NodePool string `json:"nodepool,omitempty"`
}

// NodeClaimList contains the listing result.
type NodeClaimList struct {
	Total      int             `json:"total"`
	NodeClaims []NodeClaimInfo `json:"nodeclaims"`
}

// NodeClaimInfo contains NodeClaim details.
type NodeClaimInfo struct {
	Name         string `json:"name"`
	NodeName     string `json:"node_name,omitempty"`
	InstanceType string `json:"instance_type,omitempty"`
	NodePool     string `json:"nodepool,omitempty"`
	Zone         string `json:"zone,omitempty"`
	Capacity     string `json:"capacity,omitempty"`
	Status       string `json:"status"`
	Age          string `json:"age"`
	DoNotDisrupt bool   `json:"do_not_disrupt,omitempty"`
}

// Task handles NodeClaim listing.
type Task struct {
	dynamicClient dynamic.Interface
}

// New creates a new list_nodeclaims task.
func New(dynamicClient dynamic.Interface) *Task {
	return &Task{dynamicClient: dynamicClient}
}

// Name returns the task type identifier.
func (t *Task) Name() string {
	return TaskName
}

// Execute lists NodeClaims in the cluster.
func (t *Task) Execute(ctx context.Context, rawPayload json.RawMessage) (*task.Result, error) {
	var payload Payload
	if len(rawPayload) > 0 && string(rawPayload) != "{}" {
		if err := json.Unmarshal(rawPayload, &payload); err != nil {
			return task.NewErrorResult(fmt.Sprintf("invalid payload: %v", err)), nil
		}
	}

	listOpts := metav1.ListOptions{}
	if payload.NodePool != "" {
		listOpts.LabelSelector = fmt.Sprintf("%s=%s", NodePoolLabel, payload.NodePool)
	}

	nodeClaims, err := t.dynamicClient.Resource(nodeClaimGVR).List(ctx, listOpts)
	if err != nil {
		if isCRDNotInstalled(err) {
			return task.NewSuccessResultWithDetails(
				"Karpenter NodeClaims CRD not installed in this cluster",
				&NodeClaimList{Total: 0, NodeClaims: []NodeClaimInfo{}},
			), nil
		}
		return nil, fmt.Errorf("failed to list nodeclaims: %w", err)
	}

	result := &NodeClaimList{
		Total:      len(nodeClaims.Items),
		NodeClaims: make([]NodeClaimInfo, 0, len(nodeClaims.Items)),
	}

	for i := range nodeClaims.Items {
		nc := &nodeClaims.Items[i]
		info := t.buildNodeClaimInfo(nc)
		result.NodeClaims = append(result.NodeClaims, info)
	}

	// Sort by name
	sort.Slice(result.NodeClaims, func(i, j int) bool {
		return result.NodeClaims[i].Name < result.NodeClaims[j].Name
	})

	msg := fmt.Sprintf("Found %d NodeClaims", result.Total)
	if payload.NodePool != "" {
		msg = fmt.Sprintf("Found %d NodeClaims in nodepool %s", result.Total, payload.NodePool)
	}
	return task.NewSuccessResultWithDetails(msg, result), nil
}

func (t *Task) buildNodeClaimInfo(nc *unstructured.Unstructured) NodeClaimInfo {
	info := NodeClaimInfo{
		Name:   nc.GetName(),
		Status: getNodeClaimStatus(nc),
		Age:    formatAge(nc.GetCreationTimestamp().Time),
	}

	// Extract node name from status.nodeName
	if nodeName, found, err := unstructured.NestedString(nc.Object, "status", "nodeName"); err == nil && found {
		info.NodeName = nodeName
	}

	// Extract instance type from status.instanceType
	if instanceType, found, err := unstructured.NestedString(nc.Object, "status", "instanceType"); err == nil && found {
		info.InstanceType = instanceType
	}

	// Extract capacity type from status.capacity (on-demand vs spot)
	if capacityType, found, err := unstructured.NestedString(nc.Object, "status", "capacity", "karpenter.sh/capacity-type"); err == nil && found {
		info.Capacity = capacityType
	}

	// Extract zone from status.zone or labels
	if zone, found, err := unstructured.NestedString(nc.Object, "status", "zone"); err == nil && found {
		info.Zone = zone
	} else {
		labels := nc.GetLabels()
		if zone, ok := labels["topology.kubernetes.io/zone"]; ok {
			info.Zone = zone
		}
	}

	// Extract nodepool from labels
	labels := nc.GetLabels()
	if nodePool, ok := labels[NodePoolLabel]; ok {
		info.NodePool = nodePool
	}

	// Check do-not-disrupt annotation
	annotations := nc.GetAnnotations()
	if annotations["karpenter.sh/do-not-disrupt"] == "true" {
		info.DoNotDisrupt = true
	}

	return info
}

func getNodeClaimStatus(nc *unstructured.Unstructured) string {
	conditions, found, err := unstructured.NestedSlice(nc.Object, "status", "conditions")
	if err != nil || !found {
		return "Unknown"
	}

	// Check conditions in priority order
	conditionMap := make(map[string]string)
	for _, c := range conditions {
		cond, ok := c.(map[string]any)
		if !ok {
			continue
		}
		condType, _ := cond["type"].(string)
		status, _ := cond["status"].(string)
		conditionMap[condType] = status
	}

	// Ready is the most important condition
	if conditionMap["Ready"] == "True" {
		return "Ready"
	}
	if conditionMap["Launched"] == "True" && conditionMap["Registered"] != "True" {
		return "Launching"
	}
	if conditionMap["Initialized"] == "True" && conditionMap["Ready"] != "True" {
		return "Initializing"
	}

	return "Pending"
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
