// Package list_network_policies provides NetworkPolicy listing functionality.
package list_network_policies

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/loafoe/centcom-satellite/internal/task"
)

const TaskName = "list_network_policies"

// Payload for list_network_policies task.
type Payload struct {
	Namespace     string `json:"namespace,omitempty"`
	LabelSelector string `json:"label_selector,omitempty"`
}

// NetworkPolicyList contains the network policy listing.
type NetworkPolicyList struct {
	Total    int                 `json:"total"`
	Policies []NetworkPolicyInfo `json:"policies"`
}

// NetworkPolicyInfo contains network policy details.
type NetworkPolicyInfo struct {
	Name         string   `json:"name"`
	Namespace    string   `json:"namespace"`
	PodSelector  string   `json:"pod_selector"`
	PolicyTypes  []string `json:"policy_types"`
	IngressRules int      `json:"ingress_rules"`
	EgressRules  int      `json:"egress_rules"`
	AffectedPods int      `json:"affected_pods"`
	Age          string   `json:"age"`
}

// Task handles network policy listing.
type Task struct {
	clientset kubernetes.Interface
}

// New creates a new list network policies task.
func New(clientset kubernetes.Interface) *Task {
	return &Task{clientset: clientset}
}

// Name returns the task type identifier.
func (t *Task) Name() string {
	return TaskName
}

// Execute lists network policies.
func (t *Task) Execute(ctx context.Context, rawPayload json.RawMessage) (*task.Result, error) {
	var payload Payload
	if len(rawPayload) > 0 && string(rawPayload) != "{}" {
		if err := json.Unmarshal(rawPayload, &payload); err != nil {
			return task.NewErrorResult(fmt.Sprintf("invalid payload: %v", err)), nil
		}
	}

	namespace := payload.Namespace
	if namespace == "" {
		namespace = metav1.NamespaceAll
	}

	listOpts := metav1.ListOptions{}
	if payload.LabelSelector != "" {
		listOpts.LabelSelector = payload.LabelSelector
	}

	policies, err := t.clientset.NetworkingV1().NetworkPolicies(namespace).List(ctx, listOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to list network policies: %w", err)
	}

	result := &NetworkPolicyList{
		Total:    len(policies.Items),
		Policies: make([]NetworkPolicyInfo, 0, len(policies.Items)),
	}

	for i := range policies.Items {
		policy := &policies.Items[i]
		policyInfo := t.buildPolicyInfo(ctx, policy)
		result.Policies = append(result.Policies, policyInfo)
	}

	sort.Slice(result.Policies, func(i, j int) bool {
		if result.Policies[i].Namespace != result.Policies[j].Namespace {
			return result.Policies[i].Namespace < result.Policies[j].Namespace
		}
		return result.Policies[i].Name < result.Policies[j].Name
	})

	msg := fmt.Sprintf("Found %d network policies", result.Total)
	if namespace != metav1.NamespaceAll {
		msg = fmt.Sprintf("Found %d network policies in namespace %s", result.Total, namespace)
	}
	return task.NewSuccessResultWithDetails(msg, result), nil
}

func (t *Task) buildPolicyInfo(ctx context.Context, policy *networkingv1.NetworkPolicy) NetworkPolicyInfo {
	info := NetworkPolicyInfo{
		Name:         policy.Name,
		Namespace:    policy.Namespace,
		PodSelector:  formatSelector(policy.Spec.PodSelector),
		IngressRules: len(policy.Spec.Ingress),
		EgressRules:  len(policy.Spec.Egress),
		Age:          formatAge(policy.CreationTimestamp.Time),
	}

	// Extract policy types
	for _, pt := range policy.Spec.PolicyTypes {
		info.PolicyTypes = append(info.PolicyTypes, string(pt))
	}
	if len(info.PolicyTypes) == 0 {
		// Default: if no policy types specified, Ingress is implied if ingress rules exist
		if len(policy.Spec.Ingress) > 0 {
			info.PolicyTypes = append(info.PolicyTypes, "Ingress")
		}
	}

	// Count affected pods
	info.AffectedPods = t.countAffectedPods(ctx, policy)

	return info
}

func (t *Task) countAffectedPods(ctx context.Context, policy *networkingv1.NetworkPolicy) int {
	selector, err := metav1.LabelSelectorAsSelector(&policy.Spec.PodSelector)
	if err != nil {
		return 0
	}

	pods, err := t.clientset.CoreV1().Pods(policy.Namespace).List(ctx, metav1.ListOptions{
		LabelSelector: selector.String(),
	})
	if err != nil {
		return 0
	}

	return len(pods.Items)
}

func formatSelector(selector metav1.LabelSelector) string {
	if len(selector.MatchLabels) == 0 && len(selector.MatchExpressions) == 0 {
		return "(all)"
	}
	s, err := metav1.LabelSelectorAsSelector(&selector)
	if err != nil {
		return "(invalid)"
	}
	str := s.String()
	if str == "" {
		return "(all)"
	}
	return str
}

func formatAge(t time.Time) string {
	d := time.Since(t)
	switch {
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd", int(d.Hours()/24))
	}
}
