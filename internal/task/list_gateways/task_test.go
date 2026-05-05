package list_gateways

import (
	"context"
	"encoding/json"
	"testing"
	"time"

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
	assert.Equal(t, "list_gateways", task.Name())
}

func TestTask_Execute_GatewayAPINotInstalled(t *testing.T) {
	// Create a fake dynamic client that returns "not found" for Gateway resources
	// We still need to register the GatewayList kind to avoid panic, but then use a reactor to return NotFound
	scheme := runtime.NewScheme()
	client := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(
		scheme,
		map[schema.GroupVersionResource]string{
			gatewayGVR: "GatewayList",
		},
	)

	// Add a reactor that returns NotFound error for Gateway list requests
	client.PrependReactor("list", "gateways", func(action k8stesting.Action) (handled bool, ret runtime.Object, err error) {
		return true, nil, apierrors.NewNotFound(
			schema.GroupResource{Group: "gateway.networking.k8s.io", Resource: "gateways"},
			"",
		)
	})

	task := New(client)

	payload := Payload{
		Namespace: "default",
	}
	payloadJSON, err := json.Marshal(payload)
	require.NoError(t, err)

	result, err := task.Execute(context.Background(), payloadJSON)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.Success, "should succeed even when Gateway API is not installed")

	// Check details
	details, ok := result.Details.(*GatewayList)
	require.True(t, ok, "expected GatewayList in Details")
	assert.False(t, details.GatewayAPIInstalled, "should indicate Gateway API is not installed")
	assert.Equal(t, 0, details.Total)
	assert.Empty(t, details.Gateways)
}

func TestTask_Execute_EmptyCluster(t *testing.T) {
	// Create a fake dynamic client with Gateway CRDs but no Gateways
	scheme := runtime.NewScheme()
	client := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(
		scheme,
		map[schema.GroupVersionResource]string{
			gatewayGVR: "GatewayList",
		},
	)

	task := New(client)

	payload := Payload{
		Namespace: "default",
	}
	payloadJSON, err := json.Marshal(payload)
	require.NoError(t, err)

	result, err := task.Execute(context.Background(), payloadJSON)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.Success)

	// Check details
	details, ok := result.Details.(*GatewayList)
	require.True(t, ok, "expected GatewayList in Details")
	assert.True(t, details.GatewayAPIInstalled, "should indicate Gateway API is installed")
	assert.Equal(t, 0, details.Total)
	assert.Empty(t, details.Gateways)
}

func TestTask_Execute_WithGateways(t *testing.T) {
	// Create fake client first
	scheme := runtime.NewScheme()
	client := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(
		scheme,
		map[schema.GroupVersionResource]string{
			gatewayGVR: "GatewayList",
		},
	)

	// Create test gateways as unstructured objects and add them via Create
	now := time.Now()

	gateway1 := &unstructured.Unstructured{}
	gateway1.SetGroupVersionKind(schema.GroupVersionKind{
		Group:   "gateway.networking.k8s.io",
		Version: "v1",
		Kind:    "Gateway",
	})
	gateway1.SetName("test-gateway-1")
	gateway1.SetNamespace("default")
	gateway1.SetCreationTimestamp(metav1.NewTime(now.Add(-2 * time.Hour)))

	_ = unstructured.SetNestedField(gateway1.Object, "istio", "spec", "gatewayClassName")
	_ = unstructured.SetNestedSlice(gateway1.Object, []interface{}{
		map[string]interface{}{
			"name":     "http",
			"port":     float64(80),
			"protocol": "HTTP",
			"hostname": "*.example.com",
		},
		map[string]interface{}{
			"name":     "https",
			"port":     float64(443),
			"protocol": "HTTPS",
			"hostname": "*.example.com",
		},
	}, "spec", "listeners")
	_ = unstructured.SetNestedSlice(gateway1.Object, []interface{}{
		map[string]interface{}{
			"type":  "IPAddress",
			"value": "10.0.0.1",
		},
		map[string]interface{}{
			"type":  "IPAddress",
			"value": "10.0.0.2",
		},
	}, "status", "addresses")
	_ = unstructured.SetNestedSlice(gateway1.Object, []interface{}{
		map[string]interface{}{
			"type":   "Accepted",
			"status": "True",
			"reason": "Accepted",
		},
		map[string]interface{}{
			"type":   "Programmed",
			"status": "True",
			"reason": "Programmed",
		},
	}, "status", "conditions")

	gateway2 := &unstructured.Unstructured{}
	gateway2.SetGroupVersionKind(schema.GroupVersionKind{
		Group:   "gateway.networking.k8s.io",
		Version: "v1",
		Kind:    "Gateway",
	})
	gateway2.SetName("test-gateway-2")
	gateway2.SetNamespace("kube-system")
	gateway2.SetCreationTimestamp(metav1.NewTime(now.Add(-24 * time.Hour)))

	_ = unstructured.SetNestedField(gateway2.Object, "nginx", "spec", "gatewayClassName")
	_ = unstructured.SetNestedSlice(gateway2.Object, []interface{}{
		map[string]interface{}{
			"name":     "tcp",
			"port":     float64(8080),
			"protocol": "TCP",
		},
	}, "spec", "listeners")
	_ = unstructured.SetNestedSlice(gateway2.Object, []interface{}{
		map[string]interface{}{
			"type":   "Accepted",
			"status": "True",
			"reason": "Accepted",
		},
		map[string]interface{}{
			"type":   "Programmed",
			"status": "False",
			"reason": "NotReconciled",
		},
	}, "status", "conditions")

	// Create the gateways in the fake client
	_, err := client.Resource(gatewayGVR).Namespace("default").Create(context.Background(), gateway1, metav1.CreateOptions{})
	require.NoError(t, err)
	_, err = client.Resource(gatewayGVR).Namespace("kube-system").Create(context.Background(), gateway2, metav1.CreateOptions{})
	require.NoError(t, err)

	task := New(client)

	t.Run("all namespaces", func(t *testing.T) {
		payload := Payload{}
		payloadJSON, err := json.Marshal(payload)
		require.NoError(t, err)

		result, err := task.Execute(context.Background(), payloadJSON)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.True(t, result.Success)

		// Check details
		details, ok := result.Details.(*GatewayList)
		require.True(t, ok, "expected GatewayList in Details")
		assert.True(t, details.GatewayAPIInstalled)
		assert.Equal(t, 2, details.Total)
		require.Len(t, details.Gateways, 2)

		// Check first gateway (sorted by namespace then name)
		gw1 := details.Gateways[0]
		assert.Equal(t, "test-gateway-1", gw1.Name)
		assert.Equal(t, "default", gw1.Namespace)
		assert.Equal(t, "istio", gw1.GatewayClass)
		assert.Equal(t, "2h", gw1.Age)

		// Check listeners
		require.Len(t, gw1.Listeners, 2)
		assert.Equal(t, "http", gw1.Listeners[0].Name)
		assert.Equal(t, int32(80), gw1.Listeners[0].Port)
		assert.Equal(t, "HTTP", gw1.Listeners[0].Protocol)
		assert.Equal(t, "*.example.com", gw1.Listeners[0].Hostname)

		assert.Equal(t, "https", gw1.Listeners[1].Name)
		assert.Equal(t, int32(443), gw1.Listeners[1].Port)
		assert.Equal(t, "HTTPS", gw1.Listeners[1].Protocol)

		// Check addresses
		require.Len(t, gw1.Addresses, 2)
		assert.Equal(t, "10.0.0.1", gw1.Addresses[0])
		assert.Equal(t, "10.0.0.2", gw1.Addresses[1])

		// Check conditions
		require.Len(t, gw1.Conditions, 2)
		assert.Equal(t, "Accepted", gw1.Conditions[0].Type)
		assert.Equal(t, "True", gw1.Conditions[0].Status)
		assert.Equal(t, "Accepted", gw1.Conditions[0].Reason)

		assert.Equal(t, "Programmed", gw1.Conditions[1].Type)
		assert.Equal(t, "True", gw1.Conditions[1].Status)

		// Check second gateway
		gw2 := details.Gateways[1]
		assert.Equal(t, "test-gateway-2", gw2.Name)
		assert.Equal(t, "kube-system", gw2.Namespace)
		assert.Equal(t, "nginx", gw2.GatewayClass)
		assert.Equal(t, "1d", gw2.Age)

		require.Len(t, gw2.Listeners, 1)
		assert.Equal(t, "tcp", gw2.Listeners[0].Name)
		assert.Equal(t, int32(8080), gw2.Listeners[0].Port)
		assert.Equal(t, "TCP", gw2.Listeners[0].Protocol)
		assert.Empty(t, gw2.Listeners[0].Hostname)

		// No addresses in status
		assert.Empty(t, gw2.Addresses)

		// Check conditions show Programmed=False
		require.Len(t, gw2.Conditions, 2)
		assert.Equal(t, "Programmed", gw2.Conditions[1].Type)
		assert.Equal(t, "False", gw2.Conditions[1].Status)
		assert.Equal(t, "NotReconciled", gw2.Conditions[1].Reason)
	})

	t.Run("specific namespace", func(t *testing.T) {
		payload := Payload{
			Namespace: "default",
		}
		payloadJSON, err := json.Marshal(payload)
		require.NoError(t, err)

		result, err := task.Execute(context.Background(), payloadJSON)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.True(t, result.Success)

		details, ok := result.Details.(*GatewayList)
		require.True(t, ok)
		assert.True(t, details.GatewayAPIInstalled)
		assert.Equal(t, 1, details.Total)
		require.Len(t, details.Gateways, 1)
		assert.Equal(t, "test-gateway-1", details.Gateways[0].Name)
		assert.Equal(t, "default", details.Gateways[0].Namespace)
	})
}

func TestTask_Execute_InvalidPayload(t *testing.T) {
	client := dynamicfake.NewSimpleDynamicClient(runtime.NewScheme())
	task := New(client)

	result, err := task.Execute(context.Background(), json.RawMessage(`{invalid json`))
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.False(t, result.Success)
	assert.Contains(t, result.Error, "invalid payload")
}
