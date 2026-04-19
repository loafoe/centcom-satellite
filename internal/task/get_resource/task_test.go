package get_resource

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	"k8s.io/client-go/restmapper"
)

func TestTask_Name(t *testing.T) {
	task := New(nil, nil)
	if task.Name() != TaskName {
		t.Errorf("expected %q, got %q", TaskName, task.Name())
	}
}

func TestTask_Execute_ValidationErrors(t *testing.T) {
	task := New(nil, nil)

	tests := []struct {
		name       string
		payload    Payload
		wantErrMsg string
	}{
		{
			name:       "missing apiVersion",
			payload:    Payload{Kind: "Pod", Name: "test"},
			wantErrMsg: "apiVersion is required",
		},
		{
			name:       "missing kind",
			payload:    Payload{APIVersion: "v1", Name: "test"},
			wantErrMsg: "kind is required",
		},
		{
			name:       "missing name",
			payload:    Payload{APIVersion: "v1", Kind: "Pod"},
			wantErrMsg: "name is required",
		},
		{
			name:       "secret blocked",
			payload:    Payload{APIVersion: "v1", Kind: "Secret", Name: "my-secret"},
			wantErrMsg: "FORBIDDEN",
		},
		{
			name:       "secret blocked case insensitive",
			payload:    Payload{APIVersion: "v1", Kind: "secret", Name: "my-secret"},
			wantErrMsg: "FORBIDDEN",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payloadBytes, _ := json.Marshal(tt.payload)
			result, err := task.Execute(context.Background(), payloadBytes)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result.Success {
				t.Errorf("expected failure, got success")
			}
			if !strings.Contains(result.Error, tt.wantErrMsg) {
				t.Errorf("expected error containing %q, got %q", tt.wantErrMsg, result.Error)
			}
		})
	}
}

func TestTask_Execute_NamespaceRequired(t *testing.T) {
	// Create a fake REST mapper that knows about Pods (namespaced)
	resources := []*restmapper.APIGroupResources{
		{
			Group: metav1.APIGroup{
				Name: "",
				Versions: []metav1.GroupVersionForDiscovery{
					{GroupVersion: "v1", Version: "v1"},
				},
			},
			VersionedResources: map[string][]metav1.APIResource{
				"v1": {
					{Name: "pods", Namespaced: true, Kind: "Pod"},
				},
			},
		},
	}
	mapper := restmapper.NewDiscoveryRESTMapper(resources)

	scheme := runtime.NewScheme()
	dynamicClient := dynamicfake.NewSimpleDynamicClient(scheme)

	task := New(dynamicClient, mapper)

	payload := Payload{
		APIVersion: "v1",
		Kind:       "Pod",
		Name:       "test-pod",
		// Namespace intentionally omitted
	}
	payloadBytes, _ := json.Marshal(payload)

	result, err := task.Execute(context.Background(), payloadBytes)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Success {
		t.Errorf("expected failure for missing namespace")
	}
	if !strings.Contains(result.Error, "NAMESPACE_REQUIRED") {
		t.Errorf("expected NAMESPACE_REQUIRED error, got: %s", result.Error)
	}
}

func TestTask_Execute_Success(t *testing.T) {
	// Create a fake REST mapper
	resources := []*restmapper.APIGroupResources{
		{
			Group: metav1.APIGroup{
				Name: "",
				Versions: []metav1.GroupVersionForDiscovery{
					{GroupVersion: "v1", Version: "v1"},
				},
			},
			VersionedResources: map[string][]metav1.APIResource{
				"v1": {
					{Name: "pods", Namespaced: true, Kind: "Pod"},
					{Name: "nodes", Namespaced: false, Kind: "Node"},
				},
			},
		},
	}
	mapper := restmapper.NewDiscoveryRESTMapper(resources)

	// Create a fake dynamic client with a test pod
	scheme := runtime.NewScheme()
	testPod := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "v1",
			"kind":       "Pod",
			"metadata": map[string]interface{}{
				"name":      "test-pod",
				"namespace": "default",
				"labels": map[string]interface{}{
					"app": "test",
				},
			},
			"status": map[string]interface{}{
				"phase": "Running",
				"conditions": []interface{}{
					map[string]interface{}{
						"type":   "Ready",
						"status": "True",
					},
				},
			},
		},
	}
	dynamicClient := dynamicfake.NewSimpleDynamicClient(scheme, testPod)

	task := New(dynamicClient, mapper)

	t.Run("summary output", func(t *testing.T) {
		payload := Payload{
			APIVersion: "v1",
			Kind:       "Pod",
			Name:       "test-pod",
			Namespace:  "default",
			Output:     "summary",
		}
		payloadBytes, _ := json.Marshal(payload)

		result, err := task.Execute(context.Background(), payloadBytes)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !result.Success {
			t.Errorf("expected success, got error: %s", result.Error)
		}

		// Check that Details is a Summary
		summary, ok := result.Details.(*Summary)
		if !ok {
			t.Fatalf("expected *Summary, got %T", result.Details)
		}
		if summary.Name != "test-pod" {
			t.Errorf("expected name 'test-pod', got %q", summary.Name)
		}
		if summary.Scope != "namespaced" {
			t.Errorf("expected scope 'namespaced', got %q", summary.Scope)
		}
	})

	t.Run("json output", func(t *testing.T) {
		payload := Payload{
			APIVersion: "v1",
			Kind:       "Pod",
			Name:       "test-pod",
			Namespace:  "default",
			Output:     "json",
		}
		payloadBytes, _ := json.Marshal(payload)

		result, err := task.Execute(context.Background(), payloadBytes)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !result.Success {
			t.Errorf("expected success, got error: %s", result.Error)
		}

		// Check that Details is a map (raw object)
		obj, ok := result.Details.(map[string]interface{})
		if !ok {
			t.Fatalf("expected map[string]interface{}, got %T", result.Details)
		}
		if obj["kind"] != "Pod" {
			t.Errorf("expected kind 'Pod', got %v", obj["kind"])
		}
	})
}

func TestTask_Execute_ClusterScoped(t *testing.T) {
	resources := []*restmapper.APIGroupResources{
		{
			Group: metav1.APIGroup{
				Name: "",
				Versions: []metav1.GroupVersionForDiscovery{
					{GroupVersion: "v1", Version: "v1"},
				},
			},
			VersionedResources: map[string][]metav1.APIResource{
				"v1": {
					{Name: "nodes", Namespaced: false, Kind: "Node"},
				},
			},
		},
	}
	mapper := restmapper.NewDiscoveryRESTMapper(resources)

	testNode := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "v1",
			"kind":       "Node",
			"metadata": map[string]interface{}{
				"name": "test-node",
			},
		},
	}
	scheme := runtime.NewScheme()
	dynamicClient := dynamicfake.NewSimpleDynamicClient(scheme, testNode)

	task := New(dynamicClient, mapper)

	payload := Payload{
		APIVersion: "v1",
		Kind:       "Node",
		Name:       "test-node",
		// No namespace - should work for cluster-scoped
	}
	payloadBytes, _ := json.Marshal(payload)

	result, err := task.Execute(context.Background(), payloadBytes)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Success {
		t.Errorf("expected success for cluster-scoped resource, got error: %s", result.Error)
	}

	summary := result.Details.(*Summary)
	if summary.Scope != "cluster" {
		t.Errorf("expected scope 'cluster', got %q", summary.Scope)
	}
}
