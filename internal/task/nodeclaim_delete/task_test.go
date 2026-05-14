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
