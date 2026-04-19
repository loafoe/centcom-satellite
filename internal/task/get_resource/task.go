// Package get_resource provides generic Kubernetes resource retrieval.
package get_resource

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

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

	// Block sensitive resource types
	if strings.EqualFold(payload.Kind, "Secret") {
		return task.NewErrorResult(NewBlockedError("Secret").Error()), nil
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
