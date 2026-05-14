package nodeclaim_delete

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
	assert.Equal(t, "nodeclaim_delete", task.Name())
}

func TestTask_Execute_MissingName(t *testing.T) {
	client := dynamicfake.NewSimpleDynamicClient(runtime.NewScheme())
	task := New(client)

	payload := Payload{Name: ""}
	payloadJSON, err := json.Marshal(payload)
	require.NoError(t, err)

	result, err := task.Execute(context.Background(), payloadJSON)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.False(t, result.Success)
	assert.Contains(t, result.Error, "name is required")
}

func TestTask_Execute_InvalidPayload(t *testing.T) {
	client := dynamicfake.NewSimpleDynamicClient(runtime.NewScheme())
	task := New(client)

	result, err := task.Execute(context.Background(), json.RawMessage(`{invalid`))
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.False(t, result.Success)
	assert.Contains(t, result.Error, "invalid payload")
}

func TestTask_Execute_NodeClaimNotFound(t *testing.T) {
	scheme := runtime.NewScheme()
	client := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(
		scheme,
		map[schema.GroupVersionResource]string{
			nodeClaimGVR: "NodeClaimList",
		},
	)

	client.PrependReactor("get", "nodeclaims", func(action k8stesting.Action) (handled bool, ret runtime.Object, err error) {
		return true, nil, apierrors.NewNotFound(
			schema.GroupResource{Group: "karpenter.sh", Resource: "nodeclaims"},
			"nonexistent",
		)
	})

	task := New(client)

	payload := Payload{Name: "nonexistent"}
	payloadJSON, err := json.Marshal(payload)
	require.NoError(t, err)

	result, err := task.Execute(context.Background(), payloadJSON)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.False(t, result.Success)
	assert.Contains(t, result.Error, "nodeclaim not found")
}

func TestTask_Execute_DoNotDisruptBlocks(t *testing.T) {
	scheme := runtime.NewScheme()
	client := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(
		scheme,
		map[schema.GroupVersionResource]string{
			nodeClaimGVR: "NodeClaimList",
		},
	)

	nodeClaim := &unstructured.Unstructured{}
	nodeClaim.SetGroupVersionKind(schema.GroupVersionKind{
		Group:   "karpenter.sh",
		Version: "v1",
		Kind:    "NodeClaim",
	})
	nodeClaim.SetName("protected-node")
	nodeClaim.SetAnnotations(map[string]string{
		"karpenter.sh/do-not-disrupt": "true",
	})

	_, err := client.Resource(nodeClaimGVR).Create(context.Background(), nodeClaim, metav1.CreateOptions{})
	require.NoError(t, err)

	task := New(client)

	payload := Payload{Name: "protected-node", Force: false}
	payloadJSON, err := json.Marshal(payload)
	require.NoError(t, err)

	result, err := task.Execute(context.Background(), payloadJSON)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.False(t, result.Success)
	assert.Contains(t, result.Error, "do-not-disrupt")
	assert.Contains(t, result.Error, "force=true")
}

func TestTask_Execute_ForceBypassesDoNotDisrupt(t *testing.T) {
	scheme := runtime.NewScheme()
	client := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(
		scheme,
		map[schema.GroupVersionResource]string{
			nodeClaimGVR: "NodeClaimList",
		},
	)

	nodeClaim := &unstructured.Unstructured{}
	nodeClaim.SetGroupVersionKind(schema.GroupVersionKind{
		Group:   "karpenter.sh",
		Version: "v1",
		Kind:    "NodeClaim",
	})
	nodeClaim.SetName("protected-node")
	nodeClaim.SetAnnotations(map[string]string{
		"karpenter.sh/do-not-disrupt": "true",
	})
	nodeClaim.SetLabels(map[string]string{
		"karpenter.sh/nodepool": "default",
	})
	_ = unstructured.SetNestedField(nodeClaim.Object, "ip-10-0-1-42.ec2.internal", "status", "nodeName")
	_ = unstructured.SetNestedField(nodeClaim.Object, "m5.large", "status", "instanceType")

	_, err := client.Resource(nodeClaimGVR).Create(context.Background(), nodeClaim, metav1.CreateOptions{})
	require.NoError(t, err)

	task := New(client)

	payload := Payload{Name: "protected-node", Force: true}
	payloadJSON, err := json.Marshal(payload)
	require.NoError(t, err)

	result, err := task.Execute(context.Background(), payloadJSON)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.Success)
	assert.Contains(t, result.Message, "deletion initiated")

	details, ok := result.Details.(*DeleteDetails)
	require.True(t, ok)
	assert.Equal(t, "protected-node", details.Name)
	assert.Equal(t, "ip-10-0-1-42.ec2.internal", details.NodeName)
	assert.Equal(t, "m5.large", details.InstanceType)
	assert.Equal(t, "default", details.NodePool)
	assert.True(t, details.Force)
}

func TestTask_Execute_DryRun(t *testing.T) {
	scheme := runtime.NewScheme()
	client := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(
		scheme,
		map[schema.GroupVersionResource]string{
			nodeClaimGVR: "NodeClaimList",
		},
	)

	nodeClaim := &unstructured.Unstructured{}
	nodeClaim.SetGroupVersionKind(schema.GroupVersionKind{
		Group:   "karpenter.sh",
		Version: "v1",
		Kind:    "NodeClaim",
	})
	nodeClaim.SetName("test-node")
	nodeClaim.SetLabels(map[string]string{
		"karpenter.sh/nodepool": "default",
	})
	_ = unstructured.SetNestedField(nodeClaim.Object, "ip-10-0-1-42.ec2.internal", "status", "nodeName")
	_ = unstructured.SetNestedField(nodeClaim.Object, "m5.large", "status", "instanceType")

	_, err := client.Resource(nodeClaimGVR).Create(context.Background(), nodeClaim, metav1.CreateOptions{})
	require.NoError(t, err)

	task := New(client)

	payload := Payload{Name: "test-node", DryRun: true}
	payloadJSON, err := json.Marshal(payload)
	require.NoError(t, err)

	result, err := task.Execute(context.Background(), payloadJSON)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.Success)
	assert.Contains(t, result.Message, "[DRY-RUN]")

	// Verify NodeClaim still exists
	_, err = client.Resource(nodeClaimGVR).Get(context.Background(), "test-node", metav1.GetOptions{})
	assert.NoError(t, err, "NodeClaim should still exist after dry run")

	details, ok := result.Details.(*DeleteDetails)
	require.True(t, ok)
	assert.True(t, details.DryRun)
}

func TestTask_Execute_SuccessfulDeletion(t *testing.T) {
	scheme := runtime.NewScheme()
	client := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(
		scheme,
		map[schema.GroupVersionResource]string{
			nodeClaimGVR: "NodeClaimList",
		},
	)

	nodeClaim := &unstructured.Unstructured{}
	nodeClaim.SetGroupVersionKind(schema.GroupVersionKind{
		Group:   "karpenter.sh",
		Version: "v1",
		Kind:    "NodeClaim",
	})
	nodeClaim.SetName("deletable-node")
	nodeClaim.SetLabels(map[string]string{
		"karpenter.sh/nodepool": "spot-pool",
	})
	_ = unstructured.SetNestedField(nodeClaim.Object, "ip-10-0-2-100.ec2.internal", "status", "nodeName")
	_ = unstructured.SetNestedField(nodeClaim.Object, "c5.xlarge", "status", "instanceType")

	_, err := client.Resource(nodeClaimGVR).Create(context.Background(), nodeClaim, metav1.CreateOptions{})
	require.NoError(t, err)

	task := New(client)

	payload := Payload{Name: "deletable-node"}
	payloadJSON, err := json.Marshal(payload)
	require.NoError(t, err)

	result, err := task.Execute(context.Background(), payloadJSON)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.Success)
	assert.Contains(t, result.Message, "deletion initiated")

	// Verify NodeClaim was deleted
	_, err = client.Resource(nodeClaimGVR).Get(context.Background(), "deletable-node", metav1.GetOptions{})
	assert.True(t, apierrors.IsNotFound(err), "NodeClaim should be deleted")

	details, ok := result.Details.(*DeleteDetails)
	require.True(t, ok)
	assert.Equal(t, "deletable-node", details.Name)
	assert.Equal(t, "ip-10-0-2-100.ec2.internal", details.NodeName)
	assert.Equal(t, "c5.xlarge", details.InstanceType)
	assert.Equal(t, "spot-pool", details.NodePool)
	assert.False(t, details.DryRun)
	assert.False(t, details.Force)
}
