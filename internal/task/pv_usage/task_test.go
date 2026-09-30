package pv_usage

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/client-go/kubernetes/fake"
)

func TestTask_Name(t *testing.T) {
	assert.Equal(t, TaskName, New(fake.NewSimpleClientset()).Name())
}

func TestTask_Execute_InvalidPayload(t *testing.T) {
	result, err := New(fake.NewSimpleClientset()).Execute(context.Background(), json.RawMessage(`{"threshold_percent":`))
	require.NoError(t, err)
	assert.False(t, result.Success)
	assert.Contains(t, result.Error, "invalid payload")
}

// TestTask_Execute_NoNodes covers a satellite with no cluster nodes
// (e.g. right after startup, or an AWS-only satellite): the parallel
// node-query fan-out must handle zero nodes cleanly rather than assuming
// at least one result.
func TestTask_Execute_NoNodes(t *testing.T) {
	result, err := New(fake.NewSimpleClientset()).Execute(context.Background(), json.RawMessage("{}"))
	require.NoError(t, err)
	assert.True(t, result.Success)

	report, ok := result.Details.(*UsageReport)
	require.True(t, ok)
	assert.Equal(t, 0, report.NodesQueried)
	assert.Empty(t, report.NodeErrors)
}
