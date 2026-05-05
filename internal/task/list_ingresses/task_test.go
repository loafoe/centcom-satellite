package list_ingresses

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestTask_Name(t *testing.T) {
	clientset := fake.NewSimpleClientset()
	task := New(clientset)
	assert.Equal(t, "list_ingresses", task.Name())
}

func TestTask_Execute_EmptyCluster(t *testing.T) {
	clientset := fake.NewSimpleClientset()
	task := New(clientset)

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
	details, ok := result.Details.(*IngressList)
	require.True(t, ok, "expected IngressList in Details")
	assert.Equal(t, 0, details.Total)
	assert.Empty(t, details.Ingresses)
}

func TestTask_Execute_WithIngresses(t *testing.T) {
	// Create test ingresses
	pathTypePrefix := networkingv1.PathTypePrefix
	pathTypeExact := networkingv1.PathTypeExact
	ingressClassName := "nginx"

	ingress1 := &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "test-ingress-1",
			Namespace:         "default",
			CreationTimestamp: metav1.NewTime(time.Now().Add(-2 * time.Hour)),
		},
		Spec: networkingv1.IngressSpec{
			IngressClassName: &ingressClassName,
			TLS: []networkingv1.IngressTLS{
				{
					Hosts:      []string{"example.com", "www.example.com"},
					SecretName: "example-tls",
				},
			},
			Rules: []networkingv1.IngressRule{
				{
					Host: "example.com",
					IngressRuleValue: networkingv1.IngressRuleValue{
						HTTP: &networkingv1.HTTPIngressRuleValue{
							Paths: []networkingv1.HTTPIngressPath{
								{
									Path:     "/api",
									PathType: &pathTypePrefix,
									Backend: networkingv1.IngressBackend{
										Service: &networkingv1.IngressServiceBackend{
											Name: "api-service",
											Port: networkingv1.ServiceBackendPort{
												Number: 8080,
											},
										},
									},
								},
								{
									Path:     "/health",
									PathType: &pathTypeExact,
									Backend: networkingv1.IngressBackend{
										Service: &networkingv1.IngressServiceBackend{
											Name: "health-service",
											Port: networkingv1.ServiceBackendPort{
												Name: "http",
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
		Status: networkingv1.IngressStatus{
			LoadBalancer: networkingv1.IngressLoadBalancerStatus{
				Ingress: []networkingv1.IngressLoadBalancerIngress{
					{IP: "10.0.0.1"},
					{IP: "10.0.0.2"},
				},
			},
		},
	}

	ingress2 := &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "test-ingress-2",
			Namespace:         "default",
			CreationTimestamp: metav1.NewTime(time.Now().Add(-24 * time.Hour)),
		},
		Spec: networkingv1.IngressSpec{
			// No IngressClassName (nil)
			Rules: []networkingv1.IngressRule{
				{
					Host: "test.example.com",
					IngressRuleValue: networkingv1.IngressRuleValue{
						HTTP: &networkingv1.HTTPIngressRuleValue{
							Paths: []networkingv1.HTTPIngressPath{
								{
									Path:     "/",
									PathType: &pathTypePrefix,
									Backend: networkingv1.IngressBackend{
										Service: &networkingv1.IngressServiceBackend{
											Name: "web-service",
											Port: networkingv1.ServiceBackendPort{
												Number: 80,
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	clientset := fake.NewSimpleClientset(ingress1, ingress2)
	task := New(clientset)

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
	details, ok := result.Details.(*IngressList)
	require.True(t, ok, "expected IngressList in Details")
	assert.Equal(t, 2, details.Total)
	require.Len(t, details.Ingresses, 2)

	// Check first ingress
	ing1 := details.Ingresses[0]
	assert.Equal(t, "test-ingress-1", ing1.Name)
	assert.Equal(t, "default", ing1.Namespace)
	assert.Equal(t, "nginx", ing1.IngressClass)
	assert.Equal(t, "2h", ing1.Age)
	assert.Equal(t, []string{"10.0.0.1", "10.0.0.2"}, ing1.LoadBalancerIPs)

	// Check TLS configuration
	require.Len(t, ing1.TLS, 1)
	assert.Equal(t, []string{"example.com", "www.example.com"}, ing1.TLS[0].Hosts)
	assert.Equal(t, "example-tls", ing1.TLS[0].SecretName)

	// Check rules
	require.Len(t, ing1.Rules, 1)
	assert.Equal(t, "example.com", ing1.Rules[0].Host)
	require.Len(t, ing1.Rules[0].Paths, 2)

	// Check first path
	path1 := ing1.Rules[0].Paths[0]
	assert.Equal(t, "/api", path1.Path)
	assert.Equal(t, "Prefix", path1.PathType)
	assert.Equal(t, "api-service", path1.ServiceName)
	assert.Equal(t, "8080", path1.ServicePort)

	// Check second path (named port)
	path2 := ing1.Rules[0].Paths[1]
	assert.Equal(t, "/health", path2.Path)
	assert.Equal(t, "Exact", path2.PathType)
	assert.Equal(t, "health-service", path2.ServiceName)
	assert.Equal(t, "http", path2.ServicePort)

	// Check second ingress (no IngressClass, no TLS)
	ing2 := details.Ingresses[1]
	assert.Equal(t, "test-ingress-2", ing2.Name)
	assert.Equal(t, "default", ing2.Namespace)
	assert.Empty(t, ing2.IngressClass)
	assert.Equal(t, "1d", ing2.Age)
	assert.Empty(t, ing2.LoadBalancerIPs)
	assert.Empty(t, ing2.TLS)

	require.Len(t, ing2.Rules, 1)
	assert.Equal(t, "test.example.com", ing2.Rules[0].Host)
	require.Len(t, ing2.Rules[0].Paths, 1)
	assert.Equal(t, "/", ing2.Rules[0].Paths[0].Path)
	assert.Equal(t, "web-service", ing2.Rules[0].Paths[0].ServiceName)
	assert.Equal(t, "80", ing2.Rules[0].Paths[0].ServicePort)
}
