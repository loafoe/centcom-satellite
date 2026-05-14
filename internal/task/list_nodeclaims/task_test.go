package list_nodeclaims

import (
	"context"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
)

func TestTask_Name(t *testing.T) {
	task := New(nil)
	if task.Name() != TaskName {
		t.Errorf("expected %s, got %s", TaskName, task.Name())
	}
}

func TestTask_Execute_EmptyCluster(t *testing.T) {
	scheme := runtime.NewScheme()
	gvr := schema.GroupVersionResource{Group: "karpenter.sh", Version: "v1", Resource: "nodeclaims"}
	client := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(scheme,
		map[schema.GroupVersionResource]string{
			gvr: "NodeClaimList",
		})

	task := New(client)
	result, err := task.Execute(context.Background(), []byte("{}"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Success {
		t.Errorf("expected success, got failure: %s", result.Message)
	}

	list, ok := result.Details.(*NodeClaimList)
	if !ok {
		t.Fatalf("expected *NodeClaimList, got %T", result.Details)
	}
	if list.Total != 0 {
		t.Errorf("expected 0 nodeclaims, got %d", list.Total)
	}
}

func TestTask_Execute_WithNodeClaims(t *testing.T) {
	nc1 := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "karpenter.sh/v1",
			"kind":       "NodeClaim",
			"metadata": map[string]interface{}{
				"name": "default-abc123",
				"labels": map[string]interface{}{
					"karpenter.sh/nodepool": "default",
				},
			},
			"status": map[string]interface{}{
				"nodeName":     "ip-10-0-1-42.ec2.internal",
				"instanceType": "m5.large",
				"conditions": []interface{}{
					map[string]interface{}{
						"type":   "Ready",
						"status": "True",
					},
				},
			},
		},
	}

	nc2 := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "karpenter.sh/v1",
			"kind":       "NodeClaim",
			"metadata": map[string]interface{}{
				"name": "spot-xyz789",
				"labels": map[string]interface{}{
					"karpenter.sh/nodepool": "spot",
				},
				"annotations": map[string]interface{}{
					"karpenter.sh/do-not-disrupt": "true",
				},
			},
			"status": map[string]interface{}{
				"nodeName":     "ip-10-0-2-100.ec2.internal",
				"instanceType": "c5.xlarge",
				"conditions": []interface{}{
					map[string]interface{}{
						"type":   "Ready",
						"status": "True",
					},
				},
			},
		},
	}

	scheme := runtime.NewScheme()
	gvr := schema.GroupVersionResource{Group: "karpenter.sh", Version: "v1", Resource: "nodeclaims"}
	client := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(scheme,
		map[schema.GroupVersionResource]string{
			gvr: "NodeClaimList",
		},
		nc1, nc2)

	task := New(client)
	result, err := task.Execute(context.Background(), []byte("{}"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Success {
		t.Errorf("expected success, got failure: %s", result.Message)
	}

	list, ok := result.Details.(*NodeClaimList)
	if !ok {
		t.Fatalf("expected *NodeClaimList, got %T", result.Details)
	}
	if list.Total != 2 {
		t.Errorf("expected 2 nodeclaims, got %d", list.Total)
	}

	// Check first nodeclaim (sorted alphabetically, so default-abc123 first)
	if list.NodeClaims[0].Name != "default-abc123" {
		t.Errorf("expected default-abc123, got %s", list.NodeClaims[0].Name)
	}
	if list.NodeClaims[0].NodePool != "default" {
		t.Errorf("expected nodepool default, got %s", list.NodeClaims[0].NodePool)
	}
	if list.NodeClaims[0].InstanceType != "m5.large" {
		t.Errorf("expected m5.large, got %s", list.NodeClaims[0].InstanceType)
	}

	// Check second nodeclaim has do-not-disrupt
	if !list.NodeClaims[1].DoNotDisrupt {
		t.Error("expected spot-xyz789 to have do_not_disrupt=true")
	}
}

func TestTask_Execute_FilterByNodePool(t *testing.T) {
	nc1 := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "karpenter.sh/v1",
			"kind":       "NodeClaim",
			"metadata": map[string]interface{}{
				"name": "default-abc123",
				"labels": map[string]interface{}{
					"karpenter.sh/nodepool": "default",
				},
			},
			"status": map[string]interface{}{
				"conditions": []interface{}{
					map[string]interface{}{"type": "Ready", "status": "True"},
				},
			},
		},
	}

	scheme := runtime.NewScheme()
	gvr := schema.GroupVersionResource{Group: "karpenter.sh", Version: "v1", Resource: "nodeclaims"}
	client := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(scheme,
		map[schema.GroupVersionResource]string{
			gvr: "NodeClaimList",
		},
		nc1)

	task := New(client)
	result, err := task.Execute(context.Background(), []byte(`{"nodepool":"default"}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Success {
		t.Errorf("expected success, got failure: %s", result.Message)
	}
}

func TestTask_Execute_InvalidPayload(t *testing.T) {
	scheme := runtime.NewScheme()
	gvr := schema.GroupVersionResource{Group: "karpenter.sh", Version: "v1", Resource: "nodeclaims"}
	client := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(scheme,
		map[schema.GroupVersionResource]string{
			gvr: "NodeClaimList",
		})

	task := New(client)
	result, err := task.Execute(context.Background(), []byte("invalid json"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Success {
		t.Error("expected failure for invalid payload")
	}
}

func TestGetNodeClaimStatus(t *testing.T) {
	tests := []struct {
		name       string
		conditions []interface{}
		want       string
	}{
		{
			name: "Ready",
			conditions: []interface{}{
				map[string]interface{}{"type": "Ready", "status": "True"},
			},
			want: "Ready",
		},
		{
			name: "Launching",
			conditions: []interface{}{
				map[string]interface{}{"type": "Launched", "status": "True"},
				map[string]interface{}{"type": "Registered", "status": "False"},
			},
			want: "Launching",
		},
		{
			name: "Initializing",
			conditions: []interface{}{
				map[string]interface{}{"type": "Initialized", "status": "True"},
				map[string]interface{}{"type": "Ready", "status": "False"},
			},
			want: "Initializing",
		},
		{
			name:       "No conditions",
			conditions: nil,
			want:       "Unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nc := &unstructured.Unstructured{
				Object: map[string]interface{}{
					"status": map[string]interface{}{
						"conditions": tt.conditions,
					},
				},
			}
			if tt.conditions == nil {
				nc.Object["status"] = map[string]interface{}{}
			}
			got := getNodeClaimStatus(nc)
			if got != tt.want {
				t.Errorf("getNodeClaimStatus() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestBuildNodeClaimInfo(t *testing.T) {
	nc := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "karpenter.sh/v1",
			"kind":       "NodeClaim",
			"metadata": map[string]interface{}{
				"name":              "test-claim",
				"creationTimestamp": metav1.Now().Format("2006-01-02T15:04:05Z"),
				"labels": map[string]interface{}{
					"karpenter.sh/nodepool":       "default",
					"topology.kubernetes.io/zone": "us-east-1a",
				},
				"annotations": map[string]interface{}{
					"karpenter.sh/do-not-disrupt": "true",
				},
			},
			"status": map[string]interface{}{
				"nodeName":     "ip-10-0-1-42",
				"instanceType": "m5.large",
				"conditions": []interface{}{
					map[string]interface{}{"type": "Ready", "status": "True"},
				},
			},
		},
	}

	task := &Task{}
	info := task.buildNodeClaimInfo(nc)

	if info.Name != "test-claim" {
		t.Errorf("expected name test-claim, got %s", info.Name)
	}
	if info.NodeName != "ip-10-0-1-42" {
		t.Errorf("expected node name ip-10-0-1-42, got %s", info.NodeName)
	}
	if info.InstanceType != "m5.large" {
		t.Errorf("expected instance type m5.large, got %s", info.InstanceType)
	}
	if info.NodePool != "default" {
		t.Errorf("expected nodepool default, got %s", info.NodePool)
	}
	if info.Zone != "us-east-1a" {
		t.Errorf("expected zone us-east-1a, got %s", info.Zone)
	}
	if !info.DoNotDisrupt {
		t.Error("expected do_not_disrupt to be true")
	}
	if info.Status != "Ready" {
		t.Errorf("expected status Ready, got %s", info.Status)
	}
}
