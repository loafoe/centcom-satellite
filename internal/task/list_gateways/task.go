// Package list_gateways provides Gateway API gateway listing functionality.
package list_gateways

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"

	"github.com/loafoe/centcom-satellite/internal/task"
)

const TaskName = "list_gateways"

var gatewayGVR = schema.GroupVersionResource{
	Group:    "gateway.networking.k8s.io",
	Version:  "v1",
	Resource: "gateways",
}

// Payload for list_gateways task.
type Payload struct {
	Namespace     string `json:"namespace,omitempty"`
	LabelSelector string `json:"label_selector,omitempty"`
}

// GatewayList contains the gateway listing.
type GatewayList struct {
	GatewayAPIInstalled bool          `json:"gateway_api_installed"`
	Total               int           `json:"total"`
	Gateways            []GatewayInfo `json:"gateways"`
}

// GatewayInfo contains gateway details.
type GatewayInfo struct {
	Name           string          `json:"name"`
	Namespace      string          `json:"namespace"`
	GatewayClass   string          `json:"gateway_class"`
	Listeners      []ListenerInfo  `json:"listeners"`
	Addresses      []string        `json:"addresses,omitempty"`
	Conditions     []ConditionInfo `json:"conditions"`
	AttachedRoutes int             `json:"attached_routes"`
	Age            string          `json:"age"`
}

// ListenerInfo represents a listener in a Gateway.
type ListenerInfo struct {
	Name     string `json:"name"`
	Port     int32  `json:"port"`
	Protocol string `json:"protocol"`
	Hostname string `json:"hostname,omitempty"`
}

// ConditionInfo represents a condition status.
type ConditionInfo struct {
	Type   string `json:"type"`
	Status string `json:"status"`
	Reason string `json:"reason,omitempty"`
}

// Task handles gateway listing.
type Task struct {
	dynamicClient dynamic.Interface
}

// New creates a new list gateways task.
func New(dynamicClient dynamic.Interface) *Task {
	return &Task{dynamicClient: dynamicClient}
}

// Name returns the task type identifier.
func (t *Task) Name() string {
	return TaskName
}

// Execute lists gateways in a namespace.
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

	// List gateways using dynamic client
	gateways, err := t.dynamicClient.Resource(gatewayGVR).Namespace(namespace).List(ctx, listOpts)
	if err != nil {
		// Check if Gateway API CRDs are not installed
		if isNotFoundOrNoKind(err) {
			result := &GatewayList{
				GatewayAPIInstalled: false,
				Total:               0,
				Gateways:            []GatewayInfo{},
			}
			return task.NewSuccessResultWithDetails(
				"Gateway API is not installed in this cluster",
				result,
			), nil
		}
		return nil, fmt.Errorf("failed to list gateways: %w", err)
	}

	result := &GatewayList{
		GatewayAPIInstalled: true,
		Total:               len(gateways.Items),
		Gateways:            make([]GatewayInfo, 0, len(gateways.Items)),
	}

	for i := range gateways.Items {
		gw := &gateways.Items[i]
		gwInfo, err := t.buildGatewayInfo(gw)
		if err != nil {
			// Log error but continue processing other gateways
			continue
		}
		result.Gateways = append(result.Gateways, gwInfo)
	}

	// Sort by namespace then name
	sort.Slice(result.Gateways, func(i, j int) bool {
		if result.Gateways[i].Namespace != result.Gateways[j].Namespace {
			return result.Gateways[i].Namespace < result.Gateways[j].Namespace
		}
		return result.Gateways[i].Name < result.Gateways[j].Name
	})

	msg := fmt.Sprintf("Found %d gateways in namespace %s", result.Total, namespace)
	if namespace == metav1.NamespaceAll {
		msg = fmt.Sprintf("Found %d gateways across all namespaces", result.Total)
	}
	return task.NewSuccessResultWithDetails(msg, result), nil
}

func (t *Task) buildGatewayInfo(gw *unstructured.Unstructured) (GatewayInfo, error) {
	info := GatewayInfo{
		Name:       gw.GetName(),
		Namespace:  gw.GetNamespace(),
		Listeners:  []ListenerInfo{},
		Addresses:  []string{},
		Conditions: []ConditionInfo{},
	}

	// Extract creation timestamp for age calculation
	creationTime := gw.GetCreationTimestamp()
	info.Age = formatAge(creationTime.Time)

	// Extract spec.gatewayClassName
	gatewayClassName, _, err := unstructured.NestedString(gw.Object, "spec", "gatewayClassName")
	if err == nil {
		info.GatewayClass = gatewayClassName
	}

	// Extract spec.listeners
	listeners, found, err := unstructured.NestedSlice(gw.Object, "spec", "listeners")
	if err == nil && found {
		for _, l := range listeners {
			listenerMap, ok := l.(map[string]interface{})
			if !ok {
				continue
			}

			listener := ListenerInfo{}

			if name, ok := listenerMap["name"].(string); ok {
				listener.Name = name
			}

			// Port can be int64 or float64 depending on unmarshaling
			if port, ok := listenerMap["port"].(int64); ok {
				listener.Port = int32(port)
			} else if port, ok := listenerMap["port"].(float64); ok {
				listener.Port = int32(port)
			}

			if protocol, ok := listenerMap["protocol"].(string); ok {
				listener.Protocol = protocol
			}

			if hostname, ok := listenerMap["hostname"].(string); ok {
				listener.Hostname = hostname
			}

			info.Listeners = append(info.Listeners, listener)
		}
	}

	// Extract status.addresses
	addresses, found, err := unstructured.NestedSlice(gw.Object, "status", "addresses")
	if err == nil && found {
		for _, a := range addresses {
			addrMap, ok := a.(map[string]interface{})
			if !ok {
				continue
			}
			if value, ok := addrMap["value"].(string); ok {
				info.Addresses = append(info.Addresses, value)
			}
		}
	}

	// Extract status.conditions
	conditions, found, err := unstructured.NestedSlice(gw.Object, "status", "conditions")
	if err == nil && found {
		for _, c := range conditions {
			condMap, ok := c.(map[string]interface{})
			if !ok {
				continue
			}

			condition := ConditionInfo{}
			if condType, ok := condMap["type"].(string); ok {
				condition.Type = condType
			}
			if status, ok := condMap["status"].(string); ok {
				condition.Status = status
			}
			if reason, ok := condMap["reason"].(string); ok {
				condition.Reason = reason
			}

			info.Conditions = append(info.Conditions, condition)
		}
	}

	// Extract attached routes count (if available)
	// This is typically in status.listeners[].attachedRoutes
	// For simplicity, we'll sum all attachedRoutes from all listeners
	statusListeners, found, err := unstructured.NestedSlice(gw.Object, "status", "listeners")
	if err == nil && found {
		totalAttached := 0
		for _, sl := range statusListeners {
			slMap, ok := sl.(map[string]interface{})
			if !ok {
				continue
			}
			if attachedRoutes, ok := slMap["attachedRoutes"].(int64); ok {
				totalAttached += int(attachedRoutes)
			} else if attachedRoutes, ok := slMap["attachedRoutes"].(float64); ok {
				totalAttached += int(attachedRoutes)
			}
		}
		info.AttachedRoutes = totalAttached
	}

	return info, nil
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

func isNotFoundOrNoKind(err error) bool {
	// Check if it's a NotFound API error (CRD not installed)
	if apierrors.IsNotFound(err) {
		return true
	}
	// Also check for discovery errors (alternative error messages)
	errStr := err.Error()
	return strings.Contains(errStr, "the server could not find the requested resource") ||
		strings.Contains(errStr, "no matches for kind")
}
