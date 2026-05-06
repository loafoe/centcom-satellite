package list_services

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes/fake"
)

func TestTask_Name(t *testing.T) {
	clientset := fake.NewSimpleClientset()
	task := New(clientset)
	assert.Equal(t, "list_services", task.Name())
}

func TestTask_Execute_EmptyCluster(t *testing.T) {
	clientset := fake.NewSimpleClientset()
	task := New(clientset)

	payload := Payload{
		Namespace: "default",
	}
	payloadBytes, err := json.Marshal(payload)
	require.NoError(t, err)

	result, err := task.Execute(context.Background(), payloadBytes)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.Success)
	assert.Contains(t, result.Message, "0 services")

	details, ok := result.Details.(*ServiceList)
	require.True(t, ok)
	assert.Equal(t, 0, details.Total)
	assert.Empty(t, details.Services)
}

func TestTask_Execute_WithServices(t *testing.T) {
	// Create test service
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "test-service",
			Namespace:         "default",
			CreationTimestamp: metav1.NewTime(time.Now().Add(-1 * time.Hour)),
			Labels: map[string]string{
				"app": "test",
			},
		},
		Spec: corev1.ServiceSpec{
			Type:      corev1.ServiceTypeClusterIP,
			ClusterIP: "10.96.0.1",
			Selector: map[string]string{
				"app": "test",
			},
			Ports: []corev1.ServicePort{
				{
					Name:       "http",
					Port:       80,
					TargetPort: intstr.FromInt(8080),
					Protocol:   corev1.ProtocolTCP,
				},
				{
					Name:       "https",
					Port:       443,
					TargetPort: intstr.FromString("https"),
					Protocol:   corev1.ProtocolTCP,
				},
			},
		},
	}

	// Create matching pods
	pod1 := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-pod-1",
			Namespace: "default",
			Labels: map[string]string{
				"app": "test",
			},
		},
		Status: corev1.PodStatus{
			Phase: corev1.PodRunning,
		},
	}

	pod2 := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-pod-2",
			Namespace: "default",
			Labels: map[string]string{
				"app": "test",
			},
		},
		Status: corev1.PodStatus{
			Phase: corev1.PodRunning,
		},
	}

	clientset := fake.NewSimpleClientset(svc, pod1, pod2)
	task := New(clientset)

	payload := Payload{
		Namespace:       "default",
		IncludePodCount: true, // Enable pod counting
	}
	payloadBytes, err := json.Marshal(payload)
	require.NoError(t, err)

	result, err := task.Execute(context.Background(), payloadBytes)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.Success)
	assert.Contains(t, result.Message, "1 service")

	details, ok := result.Details.(*ServiceList)
	require.True(t, ok)
	assert.Equal(t, 1, details.Total)
	require.Len(t, details.Services, 1)

	// Verify service info
	svcInfo := details.Services[0]
	assert.Equal(t, "test-service", svcInfo.Name)
	assert.Equal(t, "default", svcInfo.Namespace)
	assert.Equal(t, "ClusterIP", svcInfo.Type)
	assert.Equal(t, "10.96.0.1", svcInfo.ClusterIP)
	assert.Equal(t, 2, svcInfo.PodCount) // Both pods match selector (IncludePodCount=true)
	assert.NotEmpty(t, svcInfo.Age)

	// Verify ports
	require.Len(t, svcInfo.Ports, 2)
	assert.Equal(t, "http", svcInfo.Ports[0].Name)
	assert.Equal(t, int32(80), svcInfo.Ports[0].Port)
	assert.Equal(t, "8080", svcInfo.Ports[0].TargetPort)
	assert.Equal(t, "TCP", svcInfo.Ports[0].Protocol)

	assert.Equal(t, "https", svcInfo.Ports[1].Name)
	assert.Equal(t, int32(443), svcInfo.Ports[1].Port)
	assert.Equal(t, "https", svcInfo.Ports[1].TargetPort)
	assert.Equal(t, "TCP", svcInfo.Ports[1].Protocol)

	// Verify selector
	require.NotNil(t, svcInfo.Selector)
	assert.Equal(t, "test", svcInfo.Selector["app"])
}

func TestTask_Execute_NamespaceFilter(t *testing.T) {
	svc1 := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "service-ns1",
			Namespace:         "namespace1",
			CreationTimestamp: metav1.NewTime(time.Now().Add(-1 * time.Hour)),
		},
		Spec: corev1.ServiceSpec{
			Type:      corev1.ServiceTypeClusterIP,
			ClusterIP: "10.96.0.1",
		},
	}

	svc2 := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "service-ns2",
			Namespace:         "namespace2",
			CreationTimestamp: metav1.NewTime(time.Now().Add(-1 * time.Hour)),
		},
		Spec: corev1.ServiceSpec{
			Type:      corev1.ServiceTypeClusterIP,
			ClusterIP: "10.96.0.2",
		},
	}

	clientset := fake.NewSimpleClientset(svc1, svc2)
	task := New(clientset)

	payload := Payload{
		Namespace: "namespace1",
	}
	payloadBytes, err := json.Marshal(payload)
	require.NoError(t, err)

	result, err := task.Execute(context.Background(), payloadBytes)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.Success)

	details, ok := result.Details.(*ServiceList)
	require.True(t, ok)
	assert.Equal(t, 1, details.Total)
	require.Len(t, details.Services, 1)
	assert.Equal(t, "service-ns1", details.Services[0].Name)
	assert.Equal(t, "namespace1", details.Services[0].Namespace)
}

func TestTask_Execute_LabelSelector(t *testing.T) {
	svc1 := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "service-app1",
			Namespace:         "default",
			CreationTimestamp: metav1.NewTime(time.Now().Add(-1 * time.Hour)),
			Labels: map[string]string{
				"app": "frontend",
			},
		},
		Spec: corev1.ServiceSpec{
			Type:      corev1.ServiceTypeClusterIP,
			ClusterIP: "10.96.0.1",
		},
	}

	svc2 := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "service-app2",
			Namespace:         "default",
			CreationTimestamp: metav1.NewTime(time.Now().Add(-1 * time.Hour)),
			Labels: map[string]string{
				"app": "backend",
			},
		},
		Spec: corev1.ServiceSpec{
			Type:      corev1.ServiceTypeClusterIP,
			ClusterIP: "10.96.0.2",
		},
	}

	clientset := fake.NewSimpleClientset(svc1, svc2)
	task := New(clientset)

	payload := Payload{
		Namespace:     "default",
		LabelSelector: "app=frontend",
	}
	payloadBytes, err := json.Marshal(payload)
	require.NoError(t, err)

	result, err := task.Execute(context.Background(), payloadBytes)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.Success)

	details, ok := result.Details.(*ServiceList)
	require.True(t, ok)
	assert.Equal(t, 1, details.Total)
	require.Len(t, details.Services, 1)
	assert.Equal(t, "service-app1", details.Services[0].Name)
}

func TestTask_Execute_LoadBalancerType(t *testing.T) {
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "lb-service",
			Namespace:         "default",
			CreationTimestamp: metav1.NewTime(time.Now().Add(-1 * time.Hour)),
		},
		Spec: corev1.ServiceSpec{
			Type:      corev1.ServiceTypeLoadBalancer,
			ClusterIP: "10.96.0.1",
			Ports: []corev1.ServicePort{
				{
					Name:       "http",
					Port:       80,
					TargetPort: intstr.FromInt(8080),
					Protocol:   corev1.ProtocolTCP,
					NodePort:   30080,
				},
			},
		},
		Status: corev1.ServiceStatus{
			LoadBalancer: corev1.LoadBalancerStatus{
				Ingress: []corev1.LoadBalancerIngress{
					{IP: "203.0.113.1"},
					{IP: "203.0.113.2"},
				},
			},
		},
	}

	clientset := fake.NewSimpleClientset(svc)
	task := New(clientset)

	payload := Payload{
		Namespace: "default",
	}
	payloadBytes, err := json.Marshal(payload)
	require.NoError(t, err)

	result, err := task.Execute(context.Background(), payloadBytes)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.Success)

	details, ok := result.Details.(*ServiceList)
	require.True(t, ok)
	assert.Equal(t, 1, details.Total)
	require.Len(t, details.Services, 1)

	svcInfo := details.Services[0]
	assert.Equal(t, "LoadBalancer", svcInfo.Type)
	assert.Equal(t, []string{"203.0.113.1", "203.0.113.2"}, svcInfo.ExternalIPs)

	// Verify NodePort
	require.Len(t, svcInfo.Ports, 1)
	assert.Equal(t, int32(30080), svcInfo.Ports[0].NodePort)
}

func TestTask_Execute_AllNamespaces(t *testing.T) {
	svc1 := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "svc1",
			Namespace:         "ns1",
			CreationTimestamp: metav1.NewTime(time.Now().Add(-1 * time.Hour)),
		},
		Spec: corev1.ServiceSpec{
			Type:      corev1.ServiceTypeClusterIP,
			ClusterIP: "10.96.0.1",
		},
	}

	svc2 := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "svc2",
			Namespace:         "ns2",
			CreationTimestamp: metav1.NewTime(time.Now().Add(-2 * time.Hour)),
		},
		Spec: corev1.ServiceSpec{
			Type:      corev1.ServiceTypeClusterIP,
			ClusterIP: "10.96.0.2",
		},
	}

	clientset := fake.NewSimpleClientset(svc1, svc2)
	task := New(clientset)

	// Empty namespace means all namespaces
	payload := Payload{}
	payloadBytes, err := json.Marshal(payload)
	require.NoError(t, err)

	result, err := task.Execute(context.Background(), payloadBytes)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.Success)
	assert.Contains(t, result.Message, "all namespaces")

	details, ok := result.Details.(*ServiceList)
	require.True(t, ok)
	assert.Equal(t, 2, details.Total)
	require.Len(t, details.Services, 2)

	// Verify sorting by namespace then name
	assert.Equal(t, "ns1", details.Services[0].Namespace)
	assert.Equal(t, "svc1", details.Services[0].Name)
	assert.Equal(t, "ns2", details.Services[1].Namespace)
	assert.Equal(t, "svc2", details.Services[1].Name)
}

func TestTask_Execute_WithoutPodCount(t *testing.T) {
	// Create test service with selector
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "test-service",
			Namespace:         "default",
			CreationTimestamp: metav1.NewTime(time.Now().Add(-1 * time.Hour)),
		},
		Spec: corev1.ServiceSpec{
			Type:      corev1.ServiceTypeClusterIP,
			ClusterIP: "10.96.0.1",
			Selector: map[string]string{
				"app": "test",
			},
		},
	}

	// Create matching pods
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-pod",
			Namespace: "default",
			Labels: map[string]string{
				"app": "test",
			},
		},
	}

	clientset := fake.NewSimpleClientset(svc, pod)
	task := New(clientset)

	// Default: IncludePodCount is false
	payload := Payload{
		Namespace: "default",
	}
	payloadBytes, err := json.Marshal(payload)
	require.NoError(t, err)

	result, err := task.Execute(context.Background(), payloadBytes)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.Success)

	details, ok := result.Details.(*ServiceList)
	require.True(t, ok)
	require.Len(t, details.Services, 1)

	// PodCount should be 0 when IncludePodCount is false (default)
	assert.Equal(t, 0, details.Services[0].PodCount)
}
