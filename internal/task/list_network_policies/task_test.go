package list_network_policies

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestTask_Name(t *testing.T) {
	clientset := fake.NewSimpleClientset()
	task := New(clientset)
	assert.Equal(t, "list_network_policies", task.Name())
}

func TestTask_Execute_EmptyCluster(t *testing.T) {
	clientset := fake.NewSimpleClientset()
	task := New(clientset)

	result, err := task.Execute(context.Background(), json.RawMessage("{}"))
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.Success)
	assert.Contains(t, result.Message, "0 network policies")
}

func TestTask_Execute_WithNetworkPolicies(t *testing.T) {
	policy := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "deny-all",
			Namespace:         "default",
			CreationTimestamp: metav1.NewTime(time.Now().Add(-1 * time.Hour)),
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{"app": "web"},
			},
			PolicyTypes: []networkingv1.PolicyType{
				networkingv1.PolicyTypeIngress,
				networkingv1.PolicyTypeEgress,
			},
			Ingress: []networkingv1.NetworkPolicyIngressRule{
				{}, // one ingress rule
			},
			Egress: []networkingv1.NetworkPolicyEgressRule{
				{}, {}, // two egress rules
			},
		},
	}

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "web-pod",
			Namespace: "default",
			Labels:    map[string]string{"app": "web"},
		},
	}

	clientset := fake.NewSimpleClientset(policy, pod)
	task := New(clientset)

	result, err := task.Execute(context.Background(), json.RawMessage("{}"))
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.Success)

	details, ok := result.Details.(*NetworkPolicyList)
	require.True(t, ok)
	assert.Equal(t, 1, details.Total)
	require.Len(t, details.Policies, 1)

	policyInfo := details.Policies[0]
	assert.Equal(t, "deny-all", policyInfo.Name)
	assert.Equal(t, "default", policyInfo.Namespace)
	assert.Equal(t, "app=web", policyInfo.PodSelector)
	assert.Equal(t, []string{"Ingress", "Egress"}, policyInfo.PolicyTypes)
	assert.Equal(t, 1, policyInfo.IngressRules)
	assert.Equal(t, 2, policyInfo.EgressRules)
	assert.Equal(t, 1, policyInfo.AffectedPods)
}

func TestTask_Execute_EmptyPodSelector(t *testing.T) {
	policy := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "deny-all-pods",
			Namespace: "default",
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{}, // empty = all pods
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
		},
	}

	clientset := fake.NewSimpleClientset(policy)
	task := New(clientset)

	result, err := task.Execute(context.Background(), json.RawMessage("{}"))
	require.NoError(t, err)

	details, ok := result.Details.(*NetworkPolicyList)
	require.True(t, ok)
	assert.Equal(t, "(all)", details.Policies[0].PodSelector)
}

func TestTask_Execute_NamespaceFilter(t *testing.T) {
	policy1 := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "pol-1", Namespace: "ns1"},
		Spec:       networkingv1.NetworkPolicySpec{PodSelector: metav1.LabelSelector{}},
	}
	policy2 := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "pol-2", Namespace: "ns2"},
		Spec:       networkingv1.NetworkPolicySpec{PodSelector: metav1.LabelSelector{}},
	}

	clientset := fake.NewSimpleClientset(policy1, policy2)
	task := New(clientset)

	payload, _ := json.Marshal(Payload{Namespace: "ns1"})
	result, err := task.Execute(context.Background(), payload)
	require.NoError(t, err)

	details, ok := result.Details.(*NetworkPolicyList)
	require.True(t, ok)
	assert.Equal(t, 1, details.Total)
	assert.Equal(t, "pol-1", details.Policies[0].Name)
}
