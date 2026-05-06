package list_endpoints

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/utils/ptr"
)

func TestTask_Name(t *testing.T) {
	clientset := fake.NewSimpleClientset()
	task := New(clientset)
	assert.Equal(t, "list_endpoints", task.Name())
}

func TestTask_Execute_EmptyCluster(t *testing.T) {
	clientset := fake.NewSimpleClientset()
	task := New(clientset)

	result, err := task.Execute(context.Background(), json.RawMessage("{}"))
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.Success)
	assert.Contains(t, result.Message, "0 endpoint slices")
}

func TestTask_Execute_WithEndpointSlices(t *testing.T) {
	protocol := corev1.ProtocolTCP
	slice := &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "my-service-abc12",
			Namespace:         "default",
			CreationTimestamp: metav1.NewTime(time.Now().Add(-1 * time.Hour)),
			Labels: map[string]string{
				"kubernetes.io/service-name": "my-service",
			},
		},
		AddressType: discoveryv1.AddressTypeIPv4,
		Endpoints: []discoveryv1.Endpoint{
			{
				Addresses: []string{"10.0.0.1", "10.0.0.2"},
				Conditions: discoveryv1.EndpointConditions{
					Ready:   ptr.To(true),
					Serving: ptr.To(true),
				},
				NodeName: ptr.To("node-1"),
				TargetRef: &corev1.ObjectReference{
					Kind: "Pod",
					Name: "my-pod-xyz",
				},
			},
		},
		Ports: []discoveryv1.EndpointPort{
			{
				Name:     ptr.To("http"),
				Port:     ptr.To(int32(8080)),
				Protocol: &protocol,
			},
		},
	}

	clientset := fake.NewSimpleClientset(slice)
	task := New(clientset)

	result, err := task.Execute(context.Background(), json.RawMessage("{}"))
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.Success)

	details, ok := result.Details.(*EndpointSliceList)
	require.True(t, ok)
	assert.Equal(t, 1, details.Total)
	require.Len(t, details.Slices, 1)

	sliceInfo := details.Slices[0]
	assert.Equal(t, "my-service-abc12", sliceInfo.Name)
	assert.Equal(t, "my-service", sliceInfo.ServiceName)
	assert.Equal(t, "IPv4", sliceInfo.AddressType)

	require.Len(t, sliceInfo.Endpoints, 1)
	assert.Equal(t, []string{"10.0.0.1", "10.0.0.2"}, sliceInfo.Endpoints[0].Addresses)
	assert.Equal(t, true, *sliceInfo.Endpoints[0].Conditions.Ready)
	assert.Equal(t, "node-1", sliceInfo.Endpoints[0].NodeName)
	assert.Equal(t, "Pod/my-pod-xyz", sliceInfo.Endpoints[0].TargetRef)

	require.Len(t, sliceInfo.Ports, 1)
	assert.Equal(t, "http", sliceInfo.Ports[0].Name)
	assert.Equal(t, int32(8080), sliceInfo.Ports[0].Port)
}

func TestTask_Execute_FilterByServiceName(t *testing.T) {
	protocol := corev1.ProtocolTCP
	slice1 := &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "svc-a-slice",
			Namespace: "default",
			Labels:    map[string]string{"kubernetes.io/service-name": "svc-a"},
		},
		AddressType: discoveryv1.AddressTypeIPv4,
		Endpoints:   []discoveryv1.Endpoint{{Addresses: []string{"10.0.0.1"}}},
		Ports:       []discoveryv1.EndpointPort{{Port: ptr.To(int32(80)), Protocol: &protocol}},
	}
	slice2 := &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "svc-b-slice",
			Namespace: "default",
			Labels:    map[string]string{"kubernetes.io/service-name": "svc-b"},
		},
		AddressType: discoveryv1.AddressTypeIPv4,
		Endpoints:   []discoveryv1.Endpoint{{Addresses: []string{"10.0.0.2"}}},
		Ports:       []discoveryv1.EndpointPort{{Port: ptr.To(int32(80)), Protocol: &protocol}},
	}

	clientset := fake.NewSimpleClientset(slice1, slice2)
	task := New(clientset)

	payload, _ := json.Marshal(Payload{ServiceName: "svc-a"})
	result, err := task.Execute(context.Background(), payload)
	require.NoError(t, err)

	details, ok := result.Details.(*EndpointSliceList)
	require.True(t, ok)
	assert.Equal(t, 1, details.Total)
	assert.Equal(t, "svc-a", details.Slices[0].ServiceName)
}
