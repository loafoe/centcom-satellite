package pod_resize

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/loafoe/centcom-satellite/internal/config"
)

func defaultConfig() config.PodResizeConfig {
	return config.PodResizeConfig{
		MemoryAbsoluteCap: "20Gi",
		CPUAbsoluteCap:    "2",
		ShrinkBuffer:      20,
	}
}

func newTestPod(memReq, memLim, cpuReq, cpuLim string) *corev1.Pod {
	limits := corev1.ResourceList{}
	if memLim != "" {
		limits[corev1.ResourceMemory] = resource.MustParse(memLim)
	}
	if cpuLim != "" {
		limits[corev1.ResourceCPU] = resource.MustParse(cpuLim)
	}
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "app-1", Namespace: "default"},
		Spec: corev1.PodSpec{
			NodeName: "node-1",
			Containers: []corev1.Container{
				{
					Name: "main",
					Resources: corev1.ResourceRequirements{
						Requests: corev1.ResourceList{
							corev1.ResourceMemory: resource.MustParse(memReq),
							corev1.ResourceCPU:    resource.MustParse(cpuReq),
						},
						Limits: limits,
					},
				},
			},
		},
		Status: corev1.PodStatus{Phase: corev1.PodRunning},
	}
}

func newTestNode(memAllocatable, cpuAllocatable string) *corev1.Node {
	return &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "node-1"},
		Status: corev1.NodeStatus{
			Allocatable: corev1.ResourceList{
				corev1.ResourceMemory: resource.MustParse(memAllocatable),
				corev1.ResourceCPU:    resource.MustParse(cpuAllocatable),
			},
		},
	}
}

func TestTask_Name(t *testing.T) {
	assert.Equal(t, "pod_resize", New(fake.NewSimpleClientset(), defaultConfig()).Name())
}

func TestTask_Execute_MemoryAbsoluteCap(t *testing.T) {
	pod := newTestPod("1Gi", "2Gi", "500m", "1")
	node := newTestNode("64Gi", "16")
	clientset := fake.NewSimpleClientset(pod, node)
	tk := New(clientset, defaultConfig())

	payload := Payload{Namespace: "default", Pod: "app-1"}
	payload.Resources.Memory = "21Gi"
	raw, err := json.Marshal(payload)
	require.NoError(t, err)

	result, execErr := tk.Execute(context.Background(), raw)
	require.NoError(t, execErr)
	require.NotNil(t, result)
	assert.False(t, result.Success)
	assert.Contains(t, result.Error, "exceeds absolute cap for memory")
	assert.Contains(t, result.Error, "max 20Gi")
}

func TestTask_Execute_MemoryWithinCapSucceeds(t *testing.T) {
	pod := newTestPod("1Gi", "2Gi", "500m", "1")
	node := newTestNode("64Gi", "16")
	clientset := fake.NewSimpleClientset(pod, node)
	tk := New(clientset, defaultConfig())

	payload := Payload{Namespace: "default", Pod: "app-1"}
	payload.Resources.Memory = "20Gi"
	raw, err := json.Marshal(payload)
	require.NoError(t, err)

	result, execErr := tk.Execute(context.Background(), raw)
	require.NoError(t, execErr)
	require.NotNil(t, result)
	assert.True(t, result.Success)
}

func TestTask_Execute_CPUAbsoluteCap(t *testing.T) {
	pod := newTestPod("1Gi", "2Gi", "500m", "1")
	node := newTestNode("64Gi", "16")
	clientset := fake.NewSimpleClientset(pod, node)
	tk := New(clientset, defaultConfig())

	payload := Payload{Namespace: "default", Pod: "app-1"}
	payload.Resources.CPU = "3"
	raw, err := json.Marshal(payload)
	require.NoError(t, err)

	result, execErr := tk.Execute(context.Background(), raw)
	require.NoError(t, execErr)
	require.NotNil(t, result)
	assert.False(t, result.Success)
	assert.Contains(t, result.Error, "exceeds absolute cap for cpu")
	assert.Contains(t, result.Error, "max 2")
}

func TestTask_Execute_CPUWithinCapSucceeds(t *testing.T) {
	pod := newTestPod("1Gi", "2Gi", "500m", "1")
	node := newTestNode("64Gi", "16")
	clientset := fake.NewSimpleClientset(pod, node)
	tk := New(clientset, defaultConfig())

	payload := Payload{Namespace: "default", Pod: "app-1"}
	payload.Resources.CPU = "2"
	raw, err := json.Marshal(payload)
	require.NoError(t, err)

	result, execErr := tk.Execute(context.Background(), raw)
	require.NoError(t, execErr)
	require.NotNil(t, result)
	assert.True(t, result.Success)
}

func TestTask_Execute_NoPercentageCapAppliedAnymore(t *testing.T) {
	// Previously a >50% jump from a 1Gi request would have been rejected by the
	// percentage cap even though it's well under the absolute cap. That cap is gone.
	pod := newTestPod("1Gi", "2Gi", "500m", "1")
	node := newTestNode("64Gi", "16")
	clientset := fake.NewSimpleClientset(pod, node)
	tk := New(clientset, defaultConfig())

	payload := Payload{Namespace: "default", Pod: "app-1"}
	payload.Resources.Memory = "10Gi"
	payload.Resources.CPU = "2"
	raw, err := json.Marshal(payload)
	require.NoError(t, err)

	result, execErr := tk.Execute(context.Background(), raw)
	require.NoError(t, execErr)
	require.NotNil(t, result)
	assert.True(t, result.Success)
}

func TestTask_Execute_MissingResourcesRejected(t *testing.T) {
	pod := newTestPod("1Gi", "2Gi", "500m", "1")
	clientset := fake.NewSimpleClientset(pod)
	tk := New(clientset, defaultConfig())

	payload := Payload{Namespace: "default", Pod: "app-1"}
	raw, err := json.Marshal(payload)
	require.NoError(t, err)

	result, execErr := tk.Execute(context.Background(), raw)
	require.NoError(t, execErr)
	require.NotNil(t, result)
	assert.False(t, result.Success)
	assert.Contains(t, result.Error, "at least one of resources.memory or resources.cpu is required")
}
