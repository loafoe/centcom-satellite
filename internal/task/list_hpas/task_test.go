package list_hpas

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	autoscalingv2 "k8s.io/api/autoscaling/v2"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestTask_Name(t *testing.T) {
	assert.Equal(t, "list_hpas", New(fake.NewSimpleClientset()).Name())
}

func TestTask_Execute_ReturnsTargetRefAndReplicas(t *testing.T) {
	minReplicas := int32(2)
	hpa := &autoscalingv2.HorizontalPodAutoscaler{
		ObjectMeta: metav1.ObjectMeta{Name: "checkout-hpa", Namespace: "default"},
		Spec: autoscalingv2.HorizontalPodAutoscalerSpec{
			ScaleTargetRef: autoscalingv2.CrossVersionObjectReference{Kind: "Deployment", Name: "checkout"},
			MinReplicas:    &minReplicas,
			MaxReplicas:    5,
		},
		Status: autoscalingv2.HorizontalPodAutoscalerStatus{
			CurrentReplicas: 3,
			DesiredReplicas: 3,
		},
	}
	taskObj := New(fake.NewSimpleClientset(hpa))
	result, err := taskObj.Execute(context.Background(), json.RawMessage(`{}`))
	require.NoError(t, err)
	require.True(t, result.Success)

	list, ok := result.Details.(*HPAList)
	require.True(t, ok)
	require.Len(t, list.HPAs, 1)
	h := list.HPAs[0]
	assert.Equal(t, "checkout-hpa", h.Name)
	assert.Equal(t, "Deployment", h.TargetRef.Kind)
	assert.Equal(t, "checkout", h.TargetRef.Name)
	assert.Equal(t, int32(2), h.MinReplicas)
	assert.Equal(t, int32(5), h.MaxReplicas)
	assert.Equal(t, int32(3), h.CurrentReplicas)
}

func TestTask_Execute_DefaultsMinReplicasToOneWhenUnset(t *testing.T) {
	hpa := &autoscalingv2.HorizontalPodAutoscaler{
		ObjectMeta: metav1.ObjectMeta{Name: "no-min", Namespace: "default"},
		Spec:       autoscalingv2.HorizontalPodAutoscalerSpec{MaxReplicas: 10},
	}
	taskObj := New(fake.NewSimpleClientset(hpa))
	result, err := taskObj.Execute(context.Background(), json.RawMessage(`{}`))
	require.NoError(t, err)
	list := result.Details.(*HPAList)
	require.Len(t, list.HPAs, 1)
	assert.Equal(t, int32(1), list.HPAs[0].MinReplicas)
}

func TestTask_Execute_ResourceMetricWithUtilizationTargetAndCurrent(t *testing.T) {
	util50 := int32(50)
	util80 := int32(80)
	hpa := &autoscalingv2.HorizontalPodAutoscaler{
		ObjectMeta: metav1.ObjectMeta{Name: "cpu-hpa", Namespace: "default"},
		Spec: autoscalingv2.HorizontalPodAutoscalerSpec{
			MaxReplicas: 5,
			Metrics: []autoscalingv2.MetricSpec{
				{
					Type: autoscalingv2.ResourceMetricSourceType,
					Resource: &autoscalingv2.ResourceMetricSource{
						Name:   "cpu",
						Target: autoscalingv2.MetricTarget{AverageUtilization: &util80},
					},
				},
			},
		},
		Status: autoscalingv2.HorizontalPodAutoscalerStatus{
			CurrentMetrics: []autoscalingv2.MetricStatus{
				{
					Type: autoscalingv2.ResourceMetricSourceType,
					Resource: &autoscalingv2.ResourceMetricStatus{
						Name:    "cpu",
						Current: autoscalingv2.MetricValueStatus{AverageUtilization: &util50},
					},
				},
			},
		},
	}
	taskObj := New(fake.NewSimpleClientset(hpa))
	result, err := taskObj.Execute(context.Background(), json.RawMessage(`{}`))
	require.NoError(t, err)
	list := result.Details.(*HPAList)
	require.Len(t, list.HPAs, 1)
	require.Len(t, list.HPAs[0].Metrics, 1)
	m := list.HPAs[0].Metrics[0]
	assert.Equal(t, "cpu", m.Name)
	assert.Equal(t, "80%", m.Target)
	assert.Equal(t, "50%", m.Current)
}

func TestTask_Execute_NamespaceFilter(t *testing.T) {
	a := &autoscalingv2.HorizontalPodAutoscaler{ObjectMeta: metav1.ObjectMeta{Name: "a", Namespace: "ns-a"}, Spec: autoscalingv2.HorizontalPodAutoscalerSpec{MaxReplicas: 1}}
	b := &autoscalingv2.HorizontalPodAutoscaler{ObjectMeta: metav1.ObjectMeta{Name: "b", Namespace: "ns-b"}, Spec: autoscalingv2.HorizontalPodAutoscalerSpec{MaxReplicas: 1}}
	taskObj := New(fake.NewSimpleClientset(a, b))
	result, err := taskObj.Execute(context.Background(), json.RawMessage(`{"namespace":"ns-a"}`))
	require.NoError(t, err)
	list := result.Details.(*HPAList)
	require.Len(t, list.HPAs, 1)
	assert.Equal(t, "a", list.HPAs[0].Name)
}

func TestTask_Execute_EmptyClusterReturnsEmptyList(t *testing.T) {
	taskObj := New(fake.NewSimpleClientset())
	result, err := taskObj.Execute(context.Background(), json.RawMessage(`{}`))
	require.NoError(t, err)
	require.True(t, result.Success)
	list := result.Details.(*HPAList)
	assert.Equal(t, 0, list.Total)
	assert.Empty(t, list.HPAs)
}
