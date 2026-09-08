package list_resources

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	"k8s.io/client-go/restmapper"

	"github.com/loafoe/centcom-satellite/internal/task/resourceaccess"
)

func TestTask_Name(t *testing.T) {
	task := New(nil, nil, nil)
	if task.Name() != TaskName {
		t.Errorf("expected %q, got %q", TaskName, task.Name())
	}
}

func TestTask_Execute_ValidationErrors(t *testing.T) {
	task := New(nil, nil, nil)

	tests := []struct {
		name       string
		payload    Payload
		wantErrMsg string
	}{
		{
			name:       "missing apiVersion",
			payload:    Payload{Kind: "Pod"},
			wantErrMsg: "apiVersion is required",
		},
		{
			name:       "missing kind",
			payload:    Payload{APIVersion: "v1"},
			wantErrMsg: "kind is required",
		},
		{
			name:       "secret blocked",
			payload:    Payload{APIVersion: "v1", Kind: "Secret"},
			wantErrMsg: "BLOCKED",
		},
		{
			name:       "secret blocked case insensitive",
			payload:    Payload{APIVersion: "v1", Kind: "secret"},
			wantErrMsg: "BLOCKED",
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

func TestTask_Execute_CustomDenylist(t *testing.T) {
	denylist := resourceaccess.New([]schema.GroupKind{{Group: "external-secrets.io", Kind: "SecretStore"}})
	task := New(nil, nil, denylist)

	payload := Payload{APIVersion: "external-secrets.io/v1", Kind: "SecretStore"}
	payloadBytes, _ := json.Marshal(payload)

	result, err := task.Execute(context.Background(), payloadBytes)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Success {
		t.Errorf("expected failure for denylisted kind")
	}
	if !strings.Contains(result.Error, "BLOCKED") {
		t.Errorf("expected BLOCKED error, got: %s", result.Error)
	}
}

func TestTask_Execute_APINotFound(t *testing.T) {
	mapper := restmapper.NewDiscoveryRESTMapper(nil)
	scheme := runtime.NewScheme()
	dynamicClient := dynamicfake.NewSimpleDynamicClient(scheme)

	task := New(dynamicClient, mapper, nil)

	payload := Payload{APIVersion: "nope.example.com/v1", Kind: "Nope"}
	payloadBytes, _ := json.Marshal(payload)

	result, err := task.Execute(context.Background(), payloadBytes)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Success {
		t.Errorf("expected failure for unknown kind")
	}
	if !strings.Contains(result.Error, "API_NOT_FOUND") {
		t.Errorf("expected API_NOT_FOUND error, got: %s", result.Error)
	}
}

func buildMapper(group string, versioned map[string][]metav1.APIResource, versions []metav1.GroupVersionForDiscovery) *restmapper.APIGroupResources {
	return &restmapper.APIGroupResources{
		Group: metav1.APIGroup{
			Name:     group,
			Versions: versions,
		},
		VersionedResources: versioned,
	}
}

func TestTask_Execute_ListsAcrossNamespaces(t *testing.T) {
	resources := []*restmapper.APIGroupResources{
		buildMapper("dip.io",
			map[string][]metav1.APIResource{
				"v1alpha1": {{Name: "helmapplications", Namespaced: true, Kind: "HelmApplication"}},
			},
			[]metav1.GroupVersionForDiscovery{{GroupVersion: "dip.io/v1alpha1", Version: "v1alpha1"}}),
	}
	mapper := restmapper.NewDiscoveryRESTMapper(resources)

	gvr := schema.GroupVersionResource{Group: "dip.io", Version: "v1alpha1", Resource: "helmapplications"}
	scheme := runtime.NewScheme()

	mk := func(ns, name string, ready string) *unstructured.Unstructured {
		return &unstructured.Unstructured{
			Object: map[string]interface{}{
				"apiVersion": "dip.io/v1alpha1",
				"kind":       "HelmApplication",
				"metadata": map[string]interface{}{
					"name":      name,
					"namespace": ns,
				},
				"status": map[string]interface{}{
					"conditions": []interface{}{
						map[string]interface{}{"type": "Ready", "status": ready},
					},
				},
			},
		}
	}

	dynamicClient := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(scheme,
		map[schema.GroupVersionResource]string{gvr: "HelmApplicationList"},
		mk("argocd", "bootstrap", "True"),
		mk("argocd", "dex-issuer", "True"),
	)

	task := New(dynamicClient, mapper, nil)

	payload := Payload{APIVersion: "dip.io/v1alpha1", Kind: "HelmApplication"}
	payloadBytes, _ := json.Marshal(payload)

	result, err := task.Execute(context.Background(), payloadBytes)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Success {
		t.Fatalf("expected success, got error: %s", result.Error)
	}

	list, ok := result.Details.(*ListResult)
	if !ok {
		t.Fatalf("expected *ListResult, got %T", result.Details)
	}
	if list.Total != 2 {
		t.Errorf("expected 2 items, got %d", list.Total)
	}
	if list.Scope != "namespaced" {
		t.Errorf("expected scope 'namespaced', got %q", list.Scope)
	}
	names := map[string]bool{}
	for _, item := range list.Items {
		names[item.Name] = true
		if item.Namespace != "argocd" {
			t.Errorf("expected namespace 'argocd', got %q", item.Namespace)
		}
		if len(item.Conditions) != 1 || item.Conditions[0].Type != "Ready" || item.Conditions[0].Status != "True" {
			t.Errorf("expected a single Ready=True condition, got %+v", item.Conditions)
		}
	}
	if !names["bootstrap"] || !names["dex-issuer"] {
		t.Errorf("expected both bootstrap and dex-issuer in results, got %v", names)
	}
}

func TestTask_Execute_ScopedNamespace(t *testing.T) {
	resources := []*restmapper.APIGroupResources{
		buildMapper("dip.io",
			map[string][]metav1.APIResource{
				"v1alpha1": {{Name: "helmapplications", Namespaced: true, Kind: "HelmApplication"}},
			},
			[]metav1.GroupVersionForDiscovery{{GroupVersion: "dip.io/v1alpha1", Version: "v1alpha1"}}),
	}
	mapper := restmapper.NewDiscoveryRESTMapper(resources)

	gvr := schema.GroupVersionResource{Group: "dip.io", Version: "v1alpha1", Resource: "helmapplications"}
	scheme := runtime.NewScheme()

	mk := func(ns, name string) *unstructured.Unstructured {
		return &unstructured.Unstructured{
			Object: map[string]interface{}{
				"apiVersion": "dip.io/v1alpha1",
				"kind":       "HelmApplication",
				"metadata": map[string]interface{}{
					"name":      name,
					"namespace": ns,
				},
			},
		}
	}

	dynamicClient := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(scheme,
		map[schema.GroupVersionResource]string{gvr: "HelmApplicationList"},
		mk("argocd", "bootstrap"),
		mk("other-ns", "something-else"),
	)

	task := New(dynamicClient, mapper, nil)

	payload := Payload{APIVersion: "dip.io/v1alpha1", Kind: "HelmApplication", Namespace: "argocd"}
	payloadBytes, _ := json.Marshal(payload)

	result, err := task.Execute(context.Background(), payloadBytes)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Success {
		t.Fatalf("expected success, got error: %s", result.Error)
	}

	list := result.Details.(*ListResult)
	if list.Total != 1 {
		t.Fatalf("expected 1 item scoped to argocd, got %d", list.Total)
	}
	if list.Items[0].Name != "bootstrap" {
		t.Errorf("expected 'bootstrap', got %q", list.Items[0].Name)
	}
}

func TestTask_Execute_ClusterScoped(t *testing.T) {
	resources := []*restmapper.APIGroupResources{
		buildMapper("",
			map[string][]metav1.APIResource{
				"v1": {{Name: "nodes", Namespaced: false, Kind: "Node"}},
			},
			[]metav1.GroupVersionForDiscovery{{GroupVersion: "v1", Version: "v1"}}),
	}
	mapper := restmapper.NewDiscoveryRESTMapper(resources)

	gvr := schema.GroupVersionResource{Group: "", Version: "v1", Resource: "nodes"}
	scheme := runtime.NewScheme()

	node := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "v1",
			"kind":       "Node",
			"metadata":   map[string]interface{}{"name": "node-1"},
		},
	}

	dynamicClient := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(scheme,
		map[schema.GroupVersionResource]string{gvr: "NodeList"},
		node,
	)

	task := New(dynamicClient, mapper, nil)

	payload := Payload{APIVersion: "v1", Kind: "Node"}
	payloadBytes, _ := json.Marshal(payload)

	result, err := task.Execute(context.Background(), payloadBytes)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Success {
		t.Fatalf("expected success, got error: %s", result.Error)
	}

	list := result.Details.(*ListResult)
	if list.Scope != "cluster" {
		t.Errorf("expected scope 'cluster', got %q", list.Scope)
	}
	if list.Total != 1 || list.Items[0].Name != "node-1" {
		t.Errorf("expected single node-1, got %+v", list.Items)
	}
	if list.Items[0].Namespace != "" {
		t.Errorf("expected empty namespace for cluster-scoped resource, got %q", list.Items[0].Namespace)
	}
}
