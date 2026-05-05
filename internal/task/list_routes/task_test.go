package list_routes

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	k8stesting "k8s.io/client-go/testing"
)

func TestTask_Name(t *testing.T) {
	task := New(nil)
	assert.Equal(t, "list_routes", task.Name())
}

func TestTask_Execute_GatewayAPINotInstalled(t *testing.T) {
	// Create a fake dynamic client that returns "not found" for all route resources
	scheme := runtime.NewScheme()
	client := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(
		scheme,
		map[schema.GroupVersionResource]string{
			routeGVRs["httproute"]: "HTTPRouteList",
			routeGVRs["tlsroute"]:  "TLSRouteList",
			routeGVRs["grpcroute"]: "GRPCRouteList",
			routeGVRs["tcproute"]:  "TCPRouteList",
			routeGVRs["udproute"]:  "UDPRouteList",
		},
	)

	// Add a reactor that returns NotFound error for all route list requests
	client.PrependReactor("list", "*", func(action k8stesting.Action) (handled bool, ret runtime.Object, err error) {
		return true, nil, apierrors.NewNotFound(
			schema.GroupResource{Group: "gateway.networking.k8s.io", Resource: "routes"},
			"",
		)
	})

	task := New(client)

	result, err := task.Execute(context.Background(), json.RawMessage(`{}`))
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.Success, "should succeed even when Gateway API is not installed")

	// Check details
	details, ok := result.Details.(*RouteList)
	require.True(t, ok, "expected RouteList in Details")
	assert.False(t, details.GatewayAPIInstalled, "should indicate Gateway API is not installed")
	assert.Equal(t, 0, details.Total)
	assert.Empty(t, details.Routes)
}

func TestTask_Execute_WithHTTPRoutes(t *testing.T) {
	scheme := runtime.NewScheme()
	// Register all route types since Execute defaults to "all"
	client := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(
		scheme,
		map[schema.GroupVersionResource]string{
			routeGVRs["httproute"]: "HTTPRouteList",
			routeGVRs["tlsroute"]:  "TLSRouteList",
			routeGVRs["grpcroute"]: "GRPCRouteList",
			routeGVRs["tcproute"]:  "TCPRouteList",
			routeGVRs["udproute"]:  "UDPRouteList",
		},
	)

	httpRoute := &unstructured.Unstructured{}
	httpRoute.SetGroupVersionKind(schema.GroupVersionKind{
		Group:   "gateway.networking.k8s.io",
		Version: "v1",
		Kind:    "HTTPRoute",
	})
	httpRoute.SetName("test-http-route")
	httpRoute.SetNamespace("default")
	httpRoute.SetCreationTimestamp(metav1.Now())

	_ = unstructured.SetNestedSlice(httpRoute.Object, []interface{}{
		map[string]interface{}{
			"name":      "test-gateway",
			"namespace": "default",
			"kind":      "Gateway",
		},
	}, "spec", "parentRefs")

	_ = unstructured.SetNestedSlice(httpRoute.Object, []interface{}{
		"example.com",
		"www.example.com",
	}, "spec", "hostnames")

	_ = unstructured.SetNestedSlice(httpRoute.Object, []interface{}{
		map[string]interface{}{
			"backendRefs": []interface{}{
				map[string]interface{}{
					"name":      "backend-svc",
					"namespace": "default",
					"kind":      "Service",
					"port":      float64(8080),
				},
			},
		},
	}, "spec", "rules")

	_ = unstructured.SetNestedSlice(httpRoute.Object, []interface{}{
		map[string]interface{}{
			"parentRef": map[string]interface{}{
				"name":      "test-gateway",
				"namespace": "default",
				"kind":      "Gateway",
			},
			"conditions": []interface{}{
				map[string]interface{}{
					"type":   "Accepted",
					"status": "True",
					"reason": "Accepted",
				},
			},
		},
	}, "status", "parents")

	// Create the route in the fake client
	_, err := client.Resource(routeGVRs["httproute"]).Namespace("default").Create(context.Background(), httpRoute, metav1.CreateOptions{})
	require.NoError(t, err)

	task := New(client)
	result, err := task.Execute(context.Background(), json.RawMessage(`{}`))
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.Success)

	// Check details
	details, ok := result.Details.(*RouteList)
	require.True(t, ok, "expected RouteList in Details")
	assert.True(t, details.GatewayAPIInstalled)
	assert.Equal(t, 1, details.Total)
	require.Len(t, details.Routes, 1)

	route := details.Routes[0]
	assert.Equal(t, "test-http-route", route.Name)
	assert.Equal(t, "default", route.Namespace)
	assert.Equal(t, "HTTPRoute", route.Kind)

	require.Len(t, route.ParentRefs, 1)
	assert.Equal(t, "test-gateway", route.ParentRefs[0].Name)
	assert.Equal(t, "default", route.ParentRefs[0].Namespace)
	assert.Equal(t, "Gateway", route.ParentRefs[0].Kind)
	assert.True(t, route.ParentRefs[0].Attached)

	require.Len(t, route.Hostnames, 2)
	assert.Equal(t, "example.com", route.Hostnames[0])
	assert.Equal(t, "www.example.com", route.Hostnames[1])

	require.Len(t, route.BackendRefs, 1)
	assert.Equal(t, "backend-svc", route.BackendRefs[0].Name)
	assert.Equal(t, "default", route.BackendRefs[0].Namespace)
	assert.Equal(t, "Service", route.BackendRefs[0].Kind)
	assert.Equal(t, int32(8080), route.BackendRefs[0].Port)

	require.Len(t, route.Conditions, 1)
	assert.Equal(t, "Accepted", route.Conditions[0].Type)
	assert.Equal(t, "True", route.Conditions[0].Status)
	assert.Equal(t, "Accepted", route.Conditions[0].Reason)
}

func TestTask_Execute_KindFilter(t *testing.T) {
	t.Run("filter by httproute", func(t *testing.T) {
		scheme := runtime.NewScheme()
		client := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(
			scheme,
			map[schema.GroupVersionResource]string{
				routeGVRs["httproute"]: "HTTPRouteList",
			},
		)

		httpRoute := &unstructured.Unstructured{}
		httpRoute.SetGroupVersionKind(schema.GroupVersionKind{
			Group:   "gateway.networking.k8s.io",
			Version: "v1",
			Kind:    "HTTPRoute",
		})
		httpRoute.SetName("test-http-route")
		httpRoute.SetNamespace("default")
		httpRoute.SetCreationTimestamp(metav1.Now())

		_ = unstructured.SetNestedSlice(httpRoute.Object, []interface{}{
			map[string]interface{}{
				"name": "test-gateway",
			},
		}, "spec", "parentRefs")

		_ = unstructured.SetNestedSlice(httpRoute.Object, []interface{}{}, "status", "parents")

		// Create the route in the fake client
		_, err := client.Resource(routeGVRs["httproute"]).Namespace("default").Create(context.Background(), httpRoute, metav1.CreateOptions{})
		require.NoError(t, err)

		task := New(client)

		// Test filtering by httproute
		result, err := task.Execute(context.Background(), json.RawMessage(`{"kind":"httproute"}`))
		require.NoError(t, err)

		details, ok := result.Details.(*RouteList)
		require.True(t, ok)
		assert.Equal(t, 1, details.Total, "Expected Total=1 for httproute filter")
		assert.True(t, details.GatewayAPIInstalled)
	})

	t.Run("filter by tlsroute when not installed", func(t *testing.T) {
		scheme := runtime.NewScheme()
		client := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(
			scheme,
			map[schema.GroupVersionResource]string{
				routeGVRs["tlsroute"]: "TLSRouteList",
			},
		)

		// Add a reactor that returns NotFound error for TLSRoute list requests
		client.PrependReactor("list", "tlsroutes", func(action k8stesting.Action) (handled bool, ret runtime.Object, err error) {
			return true, nil, apierrors.NewNotFound(
				schema.GroupResource{Group: "gateway.networking.k8s.io", Resource: "tlsroutes"},
				"",
			)
		})

		task := New(client)

		// Test filtering by tlsroute (should return 0 routes)
		result, err := task.Execute(context.Background(), json.RawMessage(`{"kind":"tlsroute"}`))
		require.NoError(t, err)

		details, ok := result.Details.(*RouteList)
		require.True(t, ok)
		// TLSRoute GVR is not in the fake client, so it should silently skip
		assert.Equal(t, 0, details.Total, "Expected Total=0 for tlsroute filter (not in client)")
		assert.False(t, details.GatewayAPIInstalled)
	})
}

// Helper to create an HTTPRoute for testing
func newHTTPRoute(name, namespace string) *unstructured.Unstructured {
	route := &unstructured.Unstructured{}
	route.SetGroupVersionKind(schema.GroupVersionKind{
		Group:   "gateway.networking.k8s.io",
		Version: "v1",
		Kind:    "HTTPRoute",
	})
	route.SetName(name)
	route.SetNamespace(namespace)
	route.SetCreationTimestamp(metav1.Now())

	_ = unstructured.SetNestedSlice(route.Object, []interface{}{
		map[string]interface{}{
			"name": "test-gateway",
		},
	}, "spec", "parentRefs")

	_ = unstructured.SetNestedSlice(route.Object, []interface{}{}, "status", "parents")

	return route
}

// TestTask_Execute_MultipleRoutes tests handling multiple routes
func TestTask_Execute_MultipleRoutes(t *testing.T) {
	scheme := runtime.NewScheme()
	// Register all route types since Execute defaults to "all"
	client := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(
		scheme,
		map[schema.GroupVersionResource]string{
			routeGVRs["httproute"]: "HTTPRouteList",
			routeGVRs["tlsroute"]:  "TLSRouteList",
			routeGVRs["grpcroute"]: "GRPCRouteList",
			routeGVRs["tcproute"]:  "TCPRouteList",
			routeGVRs["udproute"]:  "UDPRouteList",
		},
	)

	route1 := newHTTPRoute("route-a", "default")
	route2 := newHTTPRoute("route-b", "default")
	route3 := newHTTPRoute("route-c", "kube-system")

	// Create all routes in the fake client
	_, err := client.Resource(routeGVRs["httproute"]).Namespace("default").Create(context.Background(), route1, metav1.CreateOptions{})
	require.NoError(t, err)
	_, err = client.Resource(routeGVRs["httproute"]).Namespace("default").Create(context.Background(), route2, metav1.CreateOptions{})
	require.NoError(t, err)
	_, err = client.Resource(routeGVRs["httproute"]).Namespace("kube-system").Create(context.Background(), route3, metav1.CreateOptions{})
	require.NoError(t, err)

	task := New(client)
	result, err := task.Execute(context.Background(), json.RawMessage(`{}`))
	require.NoError(t, err)

	details, ok := result.Details.(*RouteList)
	require.True(t, ok)
	assert.Equal(t, 3, details.Total)

	// Verify sorting: by Kind, then Namespace, then Name
	// All are HTTPRoute, so should be sorted by namespace then name
	expected := []struct {
		namespace string
		name      string
	}{
		{"default", "route-a"},
		{"default", "route-b"},
		{"kube-system", "route-c"},
	}

	require.Len(t, details.Routes, len(expected))
	for i, exp := range expected {
		route := details.Routes[i]
		assert.Equal(t, exp.namespace, route.Namespace, "Route[%d] namespace mismatch", i)
		assert.Equal(t, exp.name, route.Name, "Route[%d] name mismatch", i)
	}
}

// TestTask_Execute_WithNamespaceFilter tests namespace filtering
func TestTask_Execute_WithNamespaceFilter(t *testing.T) {
	scheme := runtime.NewScheme()
	// Register all route types since Execute defaults to "all"
	client := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(
		scheme,
		map[schema.GroupVersionResource]string{
			routeGVRs["httproute"]: "HTTPRouteList",
			routeGVRs["tlsroute"]:  "TLSRouteList",
			routeGVRs["grpcroute"]: "GRPCRouteList",
			routeGVRs["tcproute"]:  "TCPRouteList",
			routeGVRs["udproute"]:  "UDPRouteList",
		},
	)

	route1 := newHTTPRoute("route-a", "default")
	route2 := newHTTPRoute("route-b", "kube-system")

	// Create routes in the fake client
	_, err := client.Resource(routeGVRs["httproute"]).Namespace("default").Create(context.Background(), route1, metav1.CreateOptions{})
	require.NoError(t, err)
	_, err = client.Resource(routeGVRs["httproute"]).Namespace("kube-system").Create(context.Background(), route2, metav1.CreateOptions{})
	require.NoError(t, err)

	task := New(client)
	result, err := task.Execute(context.Background(), json.RawMessage(`{"namespace":"default"}`))
	require.NoError(t, err)

	details, ok := result.Details.(*RouteList)
	require.True(t, ok)

	// The fake client does filter by namespace
	assert.Equal(t, 1, details.Total)
	require.Len(t, details.Routes, 1)
	assert.Equal(t, "default", details.Routes[0].Namespace)
	assert.Equal(t, "route-a", details.Routes[0].Name)
}
