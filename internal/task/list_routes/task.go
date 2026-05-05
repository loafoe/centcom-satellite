// Package list_routes provides Gateway API route listing functionality.
package list_routes

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

	"github.com/loafoe/pico-agent/internal/task"
)

const TaskName = "list_routes"

var routeGVRs = map[string]schema.GroupVersionResource{
	"httproute": {Group: "gateway.networking.k8s.io", Version: "v1", Resource: "httproutes"},
	"tlsroute":  {Group: "gateway.networking.k8s.io", Version: "v1alpha2", Resource: "tlsroutes"},
	"grpcroute": {Group: "gateway.networking.k8s.io", Version: "v1", Resource: "grpcroutes"},
	"tcproute":  {Group: "gateway.networking.k8s.io", Version: "v1alpha2", Resource: "tcproutes"},
	"udproute":  {Group: "gateway.networking.k8s.io", Version: "v1alpha2", Resource: "udproutes"},
}

// Payload for list_routes task.
type Payload struct {
	Namespace     string `json:"namespace,omitempty"`
	LabelSelector string `json:"label_selector,omitempty"`
	Kind          string `json:"kind,omitempty"` // httproute, tlsroute, etc., or "all"
}

// RouteList contains the route listing.
type RouteList struct {
	GatewayAPIInstalled bool        `json:"gateway_api_installed"`
	Total               int         `json:"total"`
	Routes              []RouteInfo `json:"routes"`
}

// RouteInfo contains route details.
type RouteInfo struct {
	Name        string           `json:"name"`
	Namespace   string           `json:"namespace"`
	Kind        string           `json:"kind"` // HTTPRoute, TLSRoute, etc.
	ParentRefs  []ParentRefInfo  `json:"parent_refs"`
	Hostnames   []string         `json:"hostnames,omitempty"`
	BackendRefs []BackendRefInfo `json:"backend_refs"`
	Conditions  []ConditionInfo  `json:"conditions"`
	Age         string           `json:"age"`
}

// ParentRefInfo represents a parent reference.
type ParentRefInfo struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace,omitempty"`
	Kind      string `json:"kind,omitempty"`
	Attached  bool   `json:"attached"`
}

// BackendRefInfo represents a backend reference.
type BackendRefInfo struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace,omitempty"`
	Kind      string `json:"kind,omitempty"`
	Port      int32  `json:"port,omitempty"`
}

// ConditionInfo represents a condition status.
type ConditionInfo struct {
	Type   string `json:"type"`
	Status string `json:"status"`
	Reason string `json:"reason,omitempty"`
}

// Task handles route listing.
type Task struct {
	dynamicClient dynamic.Interface
}

// New creates a new list routes task.
func New(dynamicClient dynamic.Interface) *Task {
	return &Task{dynamicClient: dynamicClient}
}

// Name returns the task type identifier.
func (t *Task) Name() string {
	return TaskName
}

// Execute lists routes in a namespace.
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

	// Determine which GVRs to query
	kind := strings.ToLower(payload.Kind)
	if kind == "" {
		kind = "all"
	}

	var gvrsToQuery map[string]schema.GroupVersionResource
	if kind == "all" {
		gvrsToQuery = routeGVRs
	} else {
		if gvr, ok := routeGVRs[kind]; ok {
			gvrsToQuery = map[string]schema.GroupVersionResource{kind: gvr}
		} else {
			return task.NewErrorResult(fmt.Sprintf("invalid kind: %s (valid: httproute, tlsroute, grpcroute, tcproute, udproute, all)", kind)), nil
		}
	}

	listOpts := metav1.ListOptions{}
	if payload.LabelSelector != "" {
		listOpts.LabelSelector = payload.LabelSelector
	}

	result := &RouteList{
		GatewayAPIInstalled: false,
		Total:               0,
		Routes:              []RouteInfo{},
	}

	// Query each route type
	for routeKind, gvr := range gvrsToQuery {
		routes, err := t.dynamicClient.Resource(gvr).Namespace(namespace).List(ctx, listOpts)
		if err != nil {
			// Check if Gateway API CRDs are not installed - silently skip
			if isNotFoundOrNoKind(err) {
				continue
			}
			return nil, fmt.Errorf("failed to list %s: %w", routeKind, err)
		}

		// If we successfully listed any route type, Gateway API is installed
		result.GatewayAPIInstalled = true

		for i := range routes.Items {
			route := &routes.Items[i]
			routeInfo, err := t.buildRouteInfo(route)
			if err != nil {
				// Log error but continue processing other routes
				continue
			}
			result.Routes = append(result.Routes, routeInfo)
		}
	}

	result.Total = len(result.Routes)

	// If Gateway API is not installed, return early
	if !result.GatewayAPIInstalled {
		return task.NewSuccessResultWithDetails(
			"Gateway API is not installed in this cluster",
			result,
		), nil
	}

	// Sort by Kind, then Namespace, then Name
	sort.Slice(result.Routes, func(i, j int) bool {
		if result.Routes[i].Kind != result.Routes[j].Kind {
			return result.Routes[i].Kind < result.Routes[j].Kind
		}
		if result.Routes[i].Namespace != result.Routes[j].Namespace {
			return result.Routes[i].Namespace < result.Routes[j].Namespace
		}
		return result.Routes[i].Name < result.Routes[j].Name
	})

	msg := fmt.Sprintf("Found %d routes in namespace %s", result.Total, namespace)
	if namespace == metav1.NamespaceAll {
		msg = fmt.Sprintf("Found %d routes across all namespaces", result.Total)
	}
	if kind != "all" {
		msg = fmt.Sprintf("Found %d %s routes", result.Total, kind)
		if namespace != metav1.NamespaceAll {
			msg = fmt.Sprintf("Found %d %s routes in namespace %s", result.Total, kind, namespace)
		}
	}

	return task.NewSuccessResultWithDetails(msg, result), nil
}

func (t *Task) buildRouteInfo(route *unstructured.Unstructured) (RouteInfo, error) {
	info := RouteInfo{
		Name:        route.GetName(),
		Namespace:   route.GetNamespace(),
		Kind:        route.GetKind(),
		ParentRefs:  []ParentRefInfo{},
		Hostnames:   []string{},
		BackendRefs: []BackendRefInfo{},
		Conditions:  []ConditionInfo{},
	}

	// Extract creation timestamp for age calculation
	creationTime := route.GetCreationTimestamp()
	info.Age = formatAge(creationTime.Time)

	// Extract spec.parentRefs
	parentRefs, found, err := unstructured.NestedSlice(route.Object, "spec", "parentRefs")
	if err == nil && found {
		for _, pr := range parentRefs {
			prMap, ok := pr.(map[string]interface{})
			if !ok {
				continue
			}

			parentRef := ParentRefInfo{}

			if name, ok := prMap["name"].(string); ok {
				parentRef.Name = name
			}

			if ns, ok := prMap["namespace"].(string); ok {
				parentRef.Namespace = ns
			}

			if kind, ok := prMap["kind"].(string); ok {
				parentRef.Kind = kind
			}

			// Check if this parent is in the status.parents (attached)
			parentRef.Attached = t.isParentAttached(route, parentRef.Name, parentRef.Namespace)

			info.ParentRefs = append(info.ParentRefs, parentRef)
		}
	}

	// Extract spec.hostnames (for HTTPRoute and TLSRoute)
	hostnames, found, err := unstructured.NestedSlice(route.Object, "spec", "hostnames")
	if err == nil && found {
		for _, h := range hostnames {
			if hostname, ok := h.(string); ok {
				info.Hostnames = append(info.Hostnames, hostname)
			}
		}
	}

	// Extract backendRefs from spec.rules (for HTTPRoute/GRPCRoute)
	// or spec.rules[].backendRefs (for TLS/TCP/UDP routes)
	info.BackendRefs = t.extractBackendRefs(route)

	// Extract conditions from status.parents[].conditions
	info.Conditions = t.extractConditions(route)

	return info, nil
}

func (t *Task) isParentAttached(route *unstructured.Unstructured, parentName, parentNamespace string) bool {
	parents, found, err := unstructured.NestedSlice(route.Object, "status", "parents")
	if err != nil || !found {
		return false
	}

	for _, p := range parents {
		pMap, ok := p.(map[string]interface{})
		if !ok {
			continue
		}

		parentRef, found, err := unstructured.NestedMap(pMap, "parentRef")
		if err != nil || !found {
			continue
		}

		name, _ := parentRef["name"].(string)
		namespace, _ := parentRef["namespace"].(string)

		if name == parentName && (parentNamespace == "" || namespace == parentNamespace) {
			// Check conditions for Accepted=True
			conditions, found, err := unstructured.NestedSlice(pMap, "conditions")
			if err != nil || !found {
				continue
			}

			for _, c := range conditions {
				cMap, ok := c.(map[string]interface{})
				if !ok {
					continue
				}

				condType, _ := cMap["type"].(string)
				status, _ := cMap["status"].(string)

				if condType == "Accepted" && status == "True" {
					return true
				}
			}
		}
	}

	return false
}

func (t *Task) extractBackendRefs(route *unstructured.Unstructured) []BackendRefInfo {
	var backendRefs []BackendRefInfo

	// For HTTPRoute and GRPCRoute: spec.rules[].backendRefs
	rules, found, err := unstructured.NestedSlice(route.Object, "spec", "rules")
	if err == nil && found {
		for _, r := range rules {
			rMap, ok := r.(map[string]interface{})
			if !ok {
				continue
			}

			backends, found, err := unstructured.NestedSlice(rMap, "backendRefs")
			if err != nil || !found {
				continue
			}

			for _, b := range backends {
				bMap, ok := b.(map[string]interface{})
				if !ok {
					continue
				}

				backend := BackendRefInfo{}

				if name, ok := bMap["name"].(string); ok {
					backend.Name = name
				}

				if ns, ok := bMap["namespace"].(string); ok {
					backend.Namespace = ns
				}

				if kind, ok := bMap["kind"].(string); ok {
					backend.Kind = kind
				}

				// Port can be int64 or float64
				if port, ok := bMap["port"].(int64); ok {
					backend.Port = int32(port)
				} else if port, ok := bMap["port"].(float64); ok {
					backend.Port = int32(port)
				}

				backendRefs = append(backendRefs, backend)
			}
		}
	}

	// For TLSRoute, TCPRoute, UDPRoute: spec.rules[].backendRefs directly
	// (already handled above)

	return backendRefs
}

func (t *Task) extractConditions(route *unstructured.Unstructured) []ConditionInfo {
	var conditions []ConditionInfo

	parents, found, err := unstructured.NestedSlice(route.Object, "status", "parents")
	if err != nil || !found {
		return conditions
	}

	// Collect all unique conditions from all parents
	seenConditions := make(map[string]bool)

	for _, p := range parents {
		pMap, ok := p.(map[string]interface{})
		if !ok {
			continue
		}

		conds, found, err := unstructured.NestedSlice(pMap, "conditions")
		if err != nil || !found {
			continue
		}

		for _, c := range conds {
			cMap, ok := c.(map[string]interface{})
			if !ok {
				continue
			}

			condition := ConditionInfo{}
			if condType, ok := cMap["type"].(string); ok {
				condition.Type = condType
			}
			if status, ok := cMap["status"].(string); ok {
				condition.Status = status
			}
			if reason, ok := cMap["reason"].(string); ok {
				condition.Reason = reason
			}

			// Use a key to deduplicate conditions
			key := fmt.Sprintf("%s:%s:%s", condition.Type, condition.Status, condition.Reason)
			if !seenConditions[key] {
				seenConditions[key] = true
				conditions = append(conditions, condition)
			}
		}
	}

	return conditions
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

func toTitle(s string) string {
	if len(s) == 0 {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}
