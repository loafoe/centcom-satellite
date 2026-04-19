# get_resource Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a `get_resource` task to pico-agent that retrieves any Kubernetes resource using the dynamic client, exposed via pico-mcp as an MCP tool.

**Architecture:** Extend pico-agent's k8s client with dynamic client + REST mapper. New task package uses these to fetch any resource by GVK. Summary output extracts common fields + heuristic status fields. pico-mcp exposes as MCP tool forwarding to pico-agent.

**Tech Stack:** Go, client-go (dynamic, restmapper), k8s.io/apimachinery

**Repos:**
- pico-agent: `~/DEV/Go/pico-agent`
- pico-mcp: `~/DEV/Go/pico-mcp`

---

## File Structure

**pico-agent:**
- Modify: `internal/k8s/client.go` — add DynamicClient and RESTMapper fields
- Create: `internal/task/get_resource/task.go` — main task implementation
- Create: `internal/task/get_resource/summary.go` — summary extraction logic
- Create: `internal/task/get_resource/errors.go` — structured error types
- Create: `internal/task/get_resource/task_test.go` — unit tests
- Modify: `cmd/pico-agent/main.go` — register task

**pico-mcp:**
- Modify: `internal/mcp/server.go` — add get_resource tool and handler

---

## Task 1: Extend k8s client with dynamic client and REST mapper

**Files:**
- Modify: `internal/k8s/client.go`

- [ ] **Step 1: Update Client struct and imports**

```go
// In internal/k8s/client.go, update imports:
import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/restmapper"
	"k8s.io/client-go/tools/clientcmd"
)

// Client wraps the Kubernetes clients.
type Client struct {
	Clientset     kubernetes.Interface
	DynamicClient dynamic.Interface
	RESTMapper    meta.RESTMapper
}
```

- [ ] **Step 2: Update NewClient to initialize dynamic client and REST mapper**

```go
// NewClient creates a new Kubernetes client.
func NewClient() (*Client, error) {
	config, err := getConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to get kubernetes config: %w", err)
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create kubernetes client: %w", err)
	}

	dynamicClient, err := dynamic.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create dynamic client: %w", err)
	}

	discoveryClient, err := discovery.NewDiscoveryClientForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create discovery client: %w", err)
	}

	groupResources, err := restmapper.GetAPIGroupResources(discoveryClient)
	if err != nil {
		return nil, fmt.Errorf("failed to get API group resources: %w", err)
	}

	restMapper := restmapper.NewDiscoveryRESTMapper(groupResources)

	return &Client{
		Clientset:     clientset,
		DynamicClient: dynamicClient,
		RESTMapper:    restMapper,
	}, nil
}
```

- [ ] **Step 3: Run existing tests to verify no regression**

Run: `cd ~/DEV/Go/pico-agent && go build ./...`
Expected: Build succeeds

- [ ] **Step 4: Commit**

```bash
cd ~/DEV/Go/pico-agent
git add internal/k8s/client.go
git commit -m "feat(k8s): add dynamic client and REST mapper to k8s.Client"
```

---

## Task 2: Create error types for get_resource

**Files:**
- Create: `internal/task/get_resource/errors.go`

- [ ] **Step 1: Create errors.go with structured error types**

```go
// Package get_resource provides generic Kubernetes resource retrieval.
package get_resource

import (
	"encoding/json"
	"fmt"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
)

// ErrorCode represents a structured error code for get_resource failures.
type ErrorCode string

const (
	ErrNotFound          ErrorCode = "NOT_FOUND"
	ErrForbidden         ErrorCode = "FORBIDDEN"
	ErrAPINotFound       ErrorCode = "API_NOT_FOUND"
	ErrInvalidRequest    ErrorCode = "INVALID_REQUEST"
	ErrNamespaceRequired ErrorCode = "NAMESPACE_REQUIRED"
	ErrTimeout           ErrorCode = "TIMEOUT"
)

// StructuredError represents an error with code, message, and hint.
type StructuredError struct {
	Code    ErrorCode `json:"code"`
	Message string    `json:"message"`
	Hint    string    `json:"hint"`
}

func (e *StructuredError) Error() string {
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

func (e *StructuredError) JSON() json.RawMessage {
	data, _ := json.Marshal(e)
	return data
}

// NewNotFoundError creates a NOT_FOUND error.
func NewNotFoundError(kind, name string) *StructuredError {
	return &StructuredError{
		Code:    ErrNotFound,
		Message: fmt.Sprintf("%s %q not found", kind, name),
		Hint:    "Check the resource name and namespace",
	}
}

// NewForbiddenError creates a FORBIDDEN error.
func NewForbiddenError(kind, name string) *StructuredError {
	return &StructuredError{
		Code:    ErrForbidden,
		Message: fmt.Sprintf("access denied to %s %q", kind, name),
		Hint:    "pico-agent needs RBAC permission for this resource",
	}
}

// NewAPINotFoundError creates an API_NOT_FOUND error.
func NewAPINotFoundError(apiVersion, kind string) *StructuredError {
	return &StructuredError{
		Code:    ErrAPINotFound,
		Message: fmt.Sprintf("API %s/%s not found", apiVersion, kind),
		Hint:    "Install the CRD or check apiVersion spelling",
	}
}

// NewInvalidRequestError creates an INVALID_REQUEST error.
func NewInvalidRequestError(message string) *StructuredError {
	return &StructuredError{
		Code:    ErrInvalidRequest,
		Message: message,
		Hint:    "Check apiVersion format (group/version)",
	}
}

// NewNamespaceRequiredError creates a NAMESPACE_REQUIRED error.
func NewNamespaceRequiredError(kind string) *StructuredError {
	return &StructuredError{
		Code:    ErrNamespaceRequired,
		Message: fmt.Sprintf("%s is a namespaced resource", kind),
		Hint:    "This resource requires a namespace parameter",
	}
}

// NewTimeoutError creates a TIMEOUT error.
func NewTimeoutError() *StructuredError {
	return &StructuredError{
		Code:    ErrTimeout,
		Message: "request timed out",
		Hint:    "Retry or check cluster health",
	}
}

// MapAPIError converts a Kubernetes API error to a StructuredError.
func MapAPIError(err error, kind, name, apiVersion string) *StructuredError {
	if apierrors.IsNotFound(err) {
		return NewNotFoundError(kind, name)
	}
	if apierrors.IsForbidden(err) {
		return NewForbiddenError(kind, name)
	}
	if apierrors.IsTimeout(err) {
		return NewTimeoutError()
	}
	// Check for API group not found (NoMatch error from REST mapper)
	if _, ok := err.(*meta.NoKindMatchError); ok {
		return NewAPINotFoundError(apiVersion, kind)
	}
	// Default to invalid request for other errors
	return NewInvalidRequestError(err.Error())
}
```

- [ ] **Step 2: Add missing import for meta**

The import `"k8s.io/apimachinery/pkg/api/meta"` is needed for NoKindMatchError.

- [ ] **Step 3: Verify it compiles**

Run: `cd ~/DEV/Go/pico-agent && go build ./internal/task/get_resource/...`
Expected: Build succeeds

- [ ] **Step 4: Commit**

```bash
cd ~/DEV/Go/pico-agent
git add internal/task/get_resource/errors.go
git commit -m "feat(get_resource): add structured error types"
```

---

## Task 3: Create summary extraction logic

**Files:**
- Create: `internal/task/get_resource/summary.go`

- [ ] **Step 1: Create summary.go with Summary struct and extraction**

```go
package get_resource

import (
	"time"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// Summary is the LLM-optimized output format.
type Summary struct {
	APIVersion  string            `json:"apiVersion"`
	Kind        string            `json:"kind"`
	Name        string            `json:"name"`
	Namespace   string            `json:"namespace"`
	Scope       string            `json:"scope"`
	Age         string            `json:"age"`
	CreatedAt   string            `json:"createdAt"`
	Generation  int64             `json:"generation"`
	Labels      map[string]string `json:"labels,omitempty"`
	Annotations []string          `json:"annotations,omitempty"`
	Conditions  []Condition       `json:"conditions,omitempty"`
	Status      map[string]any    `json:"status,omitempty"`
}

// Condition represents a resource condition.
type Condition struct {
	Type               string `json:"type"`
	Status             string `json:"status"`
	Reason             string `json:"reason,omitempty"`
	Message            string `json:"message,omitempty"`
	LastTransitionTime string `json:"lastTransitionTime,omitempty"`
	Age                string `json:"age,omitempty"`
}

// ExtractSummary extracts a Summary from an unstructured resource.
func ExtractSummary(obj *unstructured.Unstructured, isNamespaced bool) *Summary {
	now := time.Now()

	summary := &Summary{
		APIVersion: obj.GetAPIVersion(),
		Kind:       obj.GetKind(),
		Name:       obj.GetName(),
		Namespace:  obj.GetNamespace(),
		Scope:      "cluster",
		Generation: obj.GetGeneration(),
		Labels:     obj.GetLabels(),
	}

	if isNamespaced {
		summary.Scope = "namespaced"
	}

	// Created timestamp and age
	createdAt := obj.GetCreationTimestamp()
	if !createdAt.IsZero() {
		summary.CreatedAt = createdAt.Format(time.RFC3339)
		summary.Age = formatDuration(now.Sub(createdAt.Time))
	}

	// Annotation keys only (values often too large)
	annotations := obj.GetAnnotations()
	if len(annotations) > 0 {
		keys := make([]string, 0, len(annotations))
		for k := range annotations {
			keys = append(keys, k)
		}
		summary.Annotations = keys
	}

	// Extract status fields
	status, found, _ := unstructured.NestedMap(obj.Object, "status")
	if found {
		summary.Conditions = extractConditions(status, now)
		summary.Status = extractStatusFields(status)
	}

	return summary
}

func extractConditions(status map[string]any, now time.Time) []Condition {
	conditionsRaw, found, _ := unstructured.NestedSlice(status, "conditions")
	if !found {
		return nil
	}

	conditions := make([]Condition, 0, len(conditionsRaw))
	for _, c := range conditionsRaw {
		condMap, ok := c.(map[string]any)
		if !ok {
			continue
		}

		cond := Condition{
			Type:    getString(condMap, "type"),
			Status:  getString(condMap, "status"),
			Reason:  getString(condMap, "reason"),
			Message: getString(condMap, "message"),
		}

		if lastTransition := getString(condMap, "lastTransitionTime"); lastTransition != "" {
			cond.LastTransitionTime = lastTransition
			if t, err := time.Parse(time.RFC3339, lastTransition); err == nil {
				cond.Age = formatDuration(now.Sub(t))
			}
		}

		conditions = append(conditions, cond)
	}

	return conditions
}

func extractStatusFields(status map[string]any) map[string]any {
	fields := make(map[string]any)

	// Phase (common in many resources)
	if phase, ok := status["phase"].(string); ok {
		fields["phase"] = phase
	}

	// Observed generation (staleness indicator)
	if og, ok := status["observedGeneration"]; ok {
		fields["observedGeneration"] = og
	}

	// Replica counts (workload-like resources)
	for _, key := range []string{"replicas", "readyReplicas", "availableReplicas", "updatedReplicas"} {
		if val, ok := status[key]; ok {
			fields[key] = val
		}
	}

	if len(fields) == 0 {
		return nil
	}
	return fields
}

func getString(m map[string]any, key string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}

func formatDuration(d time.Duration) string {
	if d < time.Minute {
		return "just now"
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm", int(d.Minutes()))
	}
	if d < 24*time.Hour {
		return fmt.Sprintf("%dh%dm", int(d.Hours()), int(d.Minutes())%60)
	}
	days := int(d.Hours() / 24)
	hours := int(d.Hours()) % 24
	return fmt.Sprintf("%dd%dh", days, hours)
}
```

- [ ] **Step 2: Add missing fmt import**

Add `"fmt"` to the imports.

- [ ] **Step 3: Verify it compiles**

Run: `cd ~/DEV/Go/pico-agent && go build ./internal/task/get_resource/...`
Expected: Build succeeds

- [ ] **Step 4: Commit**

```bash
cd ~/DEV/Go/pico-agent
git add internal/task/get_resource/summary.go
git commit -m "feat(get_resource): add summary extraction logic"
```

---

## Task 4: Create main task implementation

**Files:**
- Create: `internal/task/get_resource/task.go`

- [ ] **Step 1: Create task.go with Payload and Task struct**

```go
// Package get_resource provides generic Kubernetes resource retrieval.
package get_resource

import (
	"context"
	"encoding/json"
	"fmt"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"

	"github.com/loafoe/pico-agent/internal/task"
)

const TaskName = "get_resource"

// Payload is the input for get_resource.
type Payload struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Name       string `json:"name"`
	Namespace  string `json:"namespace,omitempty"`
	Output     string `json:"output,omitempty"` // "summary" (default) or "json"
}

// Task handles generic resource retrieval.
type Task struct {
	dynamicClient dynamic.Interface
	restMapper    meta.RESTMapper
}

// New creates a new get_resource task.
func New(dynamicClient dynamic.Interface, restMapper meta.RESTMapper) *Task {
	return &Task{
		dynamicClient: dynamicClient,
		restMapper:    restMapper,
	}
}

// Name returns the task type identifier.
func (t *Task) Name() string {
	return TaskName
}

// Execute retrieves a Kubernetes resource.
func (t *Task) Execute(ctx context.Context, payloadBytes json.RawMessage) (*task.Result, error) {
	var payload Payload
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return task.NewErrorResult(NewInvalidRequestError("invalid payload: " + err.Error()).Error()), nil
	}

	// Validate required fields
	if payload.APIVersion == "" {
		return task.NewErrorResult(NewInvalidRequestError("apiVersion is required").Error()), nil
	}
	if payload.Kind == "" {
		return task.NewErrorResult(NewInvalidRequestError("kind is required").Error()), nil
	}
	if payload.Name == "" {
		return task.NewErrorResult(NewInvalidRequestError("name is required").Error()), nil
	}

	// Parse apiVersion to GroupVersion
	gv, err := schema.ParseGroupVersion(payload.APIVersion)
	if err != nil {
		return task.NewErrorResult(NewInvalidRequestError("invalid apiVersion: " + err.Error()).Error()), nil
	}

	gvk := gv.WithKind(payload.Kind)

	// Map GVK to GVR using REST mapper
	mapping, err := t.restMapper.RESTMapping(gvk.GroupKind(), gvk.Version)
	if err != nil {
		structErr := MapAPIError(err, payload.Kind, payload.Name, payload.APIVersion)
		return t.errorResult(structErr), nil
	}

	// Check if resource is namespaced
	isNamespaced := mapping.Scope.Name() == meta.RESTScopeNameNamespace
	if isNamespaced && payload.Namespace == "" {
		structErr := NewNamespaceRequiredError(payload.Kind)
		return t.errorResult(structErr), nil
	}

	// Get the resource
	var resourceClient dynamic.ResourceInterface
	if isNamespaced {
		resourceClient = t.dynamicClient.Resource(mapping.Resource).Namespace(payload.Namespace)
	} else {
		resourceClient = t.dynamicClient.Resource(mapping.Resource)
	}

	obj, err := resourceClient.Get(ctx, payload.Name, metav1.GetOptions{})
	if err != nil {
		structErr := MapAPIError(err, payload.Kind, payload.Name, payload.APIVersion)
		return t.errorResult(structErr), nil
	}

	// Format output
	output := payload.Output
	if output == "" {
		output = "summary"
	}

	switch output {
	case "json":
		return task.NewSuccessResultWithDetails(
			fmt.Sprintf("Retrieved %s %q", payload.Kind, payload.Name),
			obj.Object,
		), nil
	case "summary":
		summary := ExtractSummary(obj, isNamespaced)
		return task.NewSuccessResultWithDetails(
			fmt.Sprintf("Retrieved %s %q", payload.Kind, payload.Name),
			summary,
		), nil
	default:
		return task.NewErrorResult(NewInvalidRequestError("output must be 'summary' or 'json'").Error()), nil
	}
}

func (t *Task) errorResult(err *StructuredError) *task.Result {
	return &task.Result{
		Success: false,
		Error:   err.Error(),
		Details: err,
	}
}
```

- [ ] **Step 2: Verify it compiles**

Run: `cd ~/DEV/Go/pico-agent && go build ./internal/task/get_resource/...`
Expected: Build succeeds

- [ ] **Step 3: Commit**

```bash
cd ~/DEV/Go/pico-agent
git add internal/task/get_resource/task.go
git commit -m "feat(get_resource): add main task implementation"
```

---

## Task 5: Add unit tests for get_resource

**Files:**
- Create: `internal/task/get_resource/task_test.go`

- [ ] **Step 1: Create task_test.go with test cases**

```go
package get_resource

import (
	"context"
	"encoding/json"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
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
			if result.Error == "" || !contains(result.Error, tt.wantErrMsg) {
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
	if !contains(result.Error, "NAMESPACE_REQUIRED") {
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

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsAt(s, substr, 0))
}

func containsAt(s, substr string, start int) bool {
	for i := start; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
```

- [ ] **Step 2: Run tests**

Run: `cd ~/DEV/Go/pico-agent && go test ./internal/task/get_resource/... -v`
Expected: All tests pass

- [ ] **Step 3: Commit**

```bash
cd ~/DEV/Go/pico-agent
git add internal/task/get_resource/task_test.go
git commit -m "test(get_resource): add unit tests"
```

---

## Task 6: Register task in main.go

**Files:**
- Modify: `cmd/pico-agent/main.go`

- [ ] **Step 1: Add import for get_resource**

Add to imports:
```go
"github.com/loafoe/pico-agent/internal/task/get_resource"
```

- [ ] **Step 2: Register the task after other task registrations**

After line 89 (after `get_events` registration), add:
```go
registry.Register(get_resource.New(k8sClient.DynamicClient, k8sClient.RESTMapper))
```

- [ ] **Step 3: Verify build succeeds**

Run: `cd ~/DEV/Go/pico-agent && go build ./...`
Expected: Build succeeds

- [ ] **Step 4: Run all tests**

Run: `cd ~/DEV/Go/pico-agent && go test ./... -v`
Expected: All tests pass

- [ ] **Step 5: Commit**

```bash
cd ~/DEV/Go/pico-agent
git add cmd/pico-agent/main.go
git commit -m "feat(main): register get_resource task"
```

---

## Task 7: Add get_resource MCP tool to pico-mcp

**Files:**
- Modify: `~/DEV/Go/pico-mcp/internal/mcp/server.go`

- [ ] **Step 1: Add tool registration in registerTools()**

Add after the `get_events` tool registration (around line 349):

```go
// Specific tool: get_resource - read-only query for any resource by GVK
s.mcpServer.AddTool(mcp.NewTool("get_resource",
	mcp.WithDescription("Get any Kubernetes resource by apiVersion, kind, and name. Returns LLM-optimized summary by default."),
	mcp.WithString("agent_id", mcp.Required(), mcp.Description("The ID of the target pico-agent")),
	mcp.WithString("apiVersion", mcp.Required(), mcp.Description("API version (e.g. 'v1', 'apps/v1', 'pkg.crossplane.io/v1beta1')")),
	mcp.WithString("kind", mcp.Required(), mcp.Description("Resource kind (e.g. 'Pod', 'Deployment', 'Function')")),
	mcp.WithString("name", mcp.Required(), mcp.Description("Resource name")),
	mcp.WithString("namespace", mcp.Description("Namespace (omit for cluster-scoped resources)")),
	mcp.WithString("output", mcp.Description("Output format: 'summary' (default) or 'json'")),
	mcp.WithReadOnlyHintAnnotation(true),
	mcp.WithDestructiveHintAnnotation(false),
	mcp.WithOpenWorldHintAnnotation(false),
), s.handleGetResource)
```

- [ ] **Step 2: Add handler function**

Add after `handleGetEvents` function (around line 759):

```go
func (s *Server) handleGetResource(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	agentID, err := request.RequireString("agent_id")
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("invalid agent ID: %v", err)), nil
	}

	client, err := s.registry.GetClient(agentID)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	// Build payload from parameters
	payload := map[string]any{
		"apiVersion": request.GetString("apiVersion", ""),
		"kind":       request.GetString("kind", ""),
		"name":       request.GetString("name", ""),
	}
	if namespace := request.GetString("namespace", ""); namespace != "" {
		payload["namespace"] = namespace
	}
	if output := request.GetString("output", ""); output != "" {
		payload["output"] = output
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to marshal payload: %v", err)), nil
	}

	result, err := client.ExecuteTask(ctx, "get_resource", payloadBytes)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to execute get_resource: %v", err)), nil
	}

	return s.formatResult(result), nil
}
```

- [ ] **Step 3: Verify build succeeds**

Run: `cd ~/DEV/Go/pico-mcp && go build ./...`
Expected: Build succeeds

- [ ] **Step 4: Run tests**

Run: `cd ~/DEV/Go/pico-mcp && go test ./... -v`
Expected: All tests pass

- [ ] **Step 5: Commit**

```bash
cd ~/DEV/Go/pico-mcp
git add internal/mcp/server.go
git commit -m "feat(mcp): add get_resource tool"
```

---

## Task 8: Update README documentation

**Files:**
- Modify: `~/DEV/Go/pico-mcp/README.md`

- [ ] **Step 1: Add get_resource to the MCP Tools table**

In the "Workload Visibility" section, add a new row after `get_events`:

```markdown
| `get_resource` | Get any resource by apiVersion/kind/name (built-in or CRD) |
```

- [ ] **Step 2: Commit**

```bash
cd ~/DEV/Go/pico-mcp
git add README.md
git commit -m "docs: add get_resource to MCP tools table"
```

---

## Verification

After completing all tasks:

- [ ] **Step 1: Build both projects**

```bash
cd ~/DEV/Go/pico-agent && go build ./...
cd ~/DEV/Go/pico-mcp && go build ./...
```

- [ ] **Step 2: Run all tests**

```bash
cd ~/DEV/Go/pico-agent && go test ./...
cd ~/DEV/Go/pico-mcp && go test ./...
```

- [ ] **Step 3: Manual integration test (requires cluster)**

Start pico-agent, then test with curl or MCP client:
```json
{
  "type": "get_resource",
  "payload": {
    "apiVersion": "v1",
    "kind": "Namespace",
    "name": "default"
  }
}
```

Expected: Returns summary with namespace details.
