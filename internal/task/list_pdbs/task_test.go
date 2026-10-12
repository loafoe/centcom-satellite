package list_pdbs

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	policyv1 "k8s.io/api/policy/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes/fake"
)

func TestTask_Name(t *testing.T) {
	assert.Equal(t, "list_pdbs", New(fake.NewSimpleClientset()).Name())
}

func TestTask_Execute_ReturnsSelectorAndStatus(t *testing.T) {
	minAvail := intstr.FromInt(2)
	pdb := &policyv1.PodDisruptionBudget{
		ObjectMeta: metav1.ObjectMeta{Name: "checkout-pdb", Namespace: "default"},
		Spec: policyv1.PodDisruptionBudgetSpec{
			MinAvailable: &minAvail,
			Selector:     &metav1.LabelSelector{MatchLabels: map[string]string{"app": "checkout"}},
		},
		Status: policyv1.PodDisruptionBudgetStatus{
			CurrentHealthy:     3,
			DesiredHealthy:     2,
			DisruptionsAllowed: 1,
			ExpectedPods:       3,
		},
	}
	taskObj := New(fake.NewSimpleClientset(pdb))
	result, err := taskObj.Execute(context.Background(), json.RawMessage(`{}`))
	require.NoError(t, err)
	require.True(t, result.Success)

	list, ok := result.Details.(*PDBList)
	require.True(t, ok)
	require.Len(t, list.PDBs, 1)
	p := list.PDBs[0]
	assert.Equal(t, "checkout-pdb", p.Name)
	assert.Equal(t, "2", p.MinAvailable)
	assert.Equal(t, map[string]string{"app": "checkout"}, p.Selector)
	assert.Equal(t, int32(3), p.CurrentHealthy)
	assert.Equal(t, int32(2), p.DesiredHealthy)
	assert.Equal(t, int32(1), p.DisruptionsAllowed)
	assert.Equal(t, int32(3), p.ExpectedPods)
}

func TestTask_Execute_MaxUnavailable(t *testing.T) {
	maxUnavail := intstr.FromString("25%")
	pdb := &policyv1.PodDisruptionBudget{
		ObjectMeta: metav1.ObjectMeta{Name: "web-pdb", Namespace: "default"},
		Spec:       policyv1.PodDisruptionBudgetSpec{MaxUnavailable: &maxUnavail},
	}
	taskObj := New(fake.NewSimpleClientset(pdb))
	result, err := taskObj.Execute(context.Background(), json.RawMessage(`{}`))
	require.NoError(t, err)
	list := result.Details.(*PDBList)
	require.Len(t, list.PDBs, 1)
	assert.Equal(t, "25%", list.PDBs[0].MaxUnavailable)
	assert.Empty(t, list.PDBs[0].MinAvailable)
}

func TestTask_Execute_NamespaceFilter(t *testing.T) {
	a := &policyv1.PodDisruptionBudget{ObjectMeta: metav1.ObjectMeta{Name: "a", Namespace: "ns-a"}}
	b := &policyv1.PodDisruptionBudget{ObjectMeta: metav1.ObjectMeta{Name: "b", Namespace: "ns-b"}}
	taskObj := New(fake.NewSimpleClientset(a, b))
	result, err := taskObj.Execute(context.Background(), json.RawMessage(`{"namespace":"ns-b"}`))
	require.NoError(t, err)
	list := result.Details.(*PDBList)
	require.Len(t, list.PDBs, 1)
	assert.Equal(t, "b", list.PDBs[0].Name)
}

func TestTask_Execute_NoSelectorOmitsSelectorField(t *testing.T) {
	pdb := &policyv1.PodDisruptionBudget{ObjectMeta: metav1.ObjectMeta{Name: "no-selector", Namespace: "default"}}
	taskObj := New(fake.NewSimpleClientset(pdb))
	result, err := taskObj.Execute(context.Background(), json.RawMessage(`{}`))
	require.NoError(t, err)
	list := result.Details.(*PDBList)
	require.Len(t, list.PDBs, 1)
	assert.Nil(t, list.PDBs[0].Selector)
}

func TestTask_Execute_EmptyClusterReturnsEmptyList(t *testing.T) {
	taskObj := New(fake.NewSimpleClientset())
	result, err := taskObj.Execute(context.Background(), json.RawMessage(`{}`))
	require.NoError(t, err)
	require.True(t, result.Success)
	list := result.Details.(*PDBList)
	assert.Equal(t, 0, list.Total)
	assert.Empty(t, list.PDBs)
}
