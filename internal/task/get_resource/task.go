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

	"github.com/loafoe/centcom-satellite/internal/redact"
	"github.com/loafoe/centcom-satellite/internal/task"
	"github.com/loafoe/centcom-satellite/internal/task/resourceaccess"
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
	denylist      *resourceaccess.Denylist
}

// New creates a new get_resource task. denylist may be nil, in which case
// only the non-negotiable default (Secret) is blocked - see
// resourceaccess.New.
func New(dynamicClient dynamic.Interface, restMapper meta.RESTMapper, denylist *resourceaccess.Denylist) *Task {
	if denylist == nil {
		denylist = resourceaccess.New(nil)
	}
	return &Task{
		dynamicClient: dynamicClient,
		restMapper:    restMapper,
		denylist:      denylist,
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

	// Parse apiVersion to GroupVersion. Done before the denylist check since
	// denial is by group+kind, not kind alone (Layer 2 - see
	// internal/task/resourceaccess).
	gv, err := schema.ParseGroupVersion(payload.APIVersion)
	if err != nil {
		return task.NewErrorResult(NewInvalidRequestError("invalid apiVersion: " + err.Error()).Error()), nil
	}

	gvk := gv.WithKind(payload.Kind)

	// Layer 2: shared, config-driven GVK denylist. Secret is always denied,
	// even with empty config (resourceaccess.DefaultDenied) - defense in
	// depth alongside Layer 1 (the `view` ClusterRoleBinding the Helm chart
	// grants when this task is enabled, which already excludes secrets at
	// the RBAC layer): a bug in either layer alone still leaves the other
	// holding.
	if t.denylist.IsDenied(gvk.GroupKind()) {
		return task.NewErrorResult(NewBlockedError(payload.Kind).Error()), nil
	}

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
		// Layer 3: redact secret-shaped values inside the object graph, e.g.
		// a plaintext password in a Pod's env or a bearer token in a
		// webhook's clientConfig - values that leak through an otherwise
		// legitimately-readable object rather than as a Secret resource,
		// which neither Layer 1 (RBAC) nor Layer 2 (kind denylist) can catch.
		redacted, n := redact.WalkObject(obj.Object)
		return task.NewSuccessResultWithDetails(
			redactedMessage(payload.Kind, payload.Name, n),
			redacted,
		), nil
	case "summary":
		summary := ExtractSummary(obj, isNamespaced)
		n := redactSummary(summary)
		return task.NewSuccessResultWithDetails(
			redactedMessage(payload.Kind, payload.Name, n),
			summary,
		), nil
	default:
		return task.NewErrorResult(NewInvalidRequestError("output must be 'summary' or 'json'").Error()), nil
	}
}

// redactedMessage builds the success message, noting how many values were
// masked so a caller isn't left wondering why a field looks odd.
func redactedMessage(kind, name string, redactedCount int) string {
	if redactedCount == 0 {
		return fmt.Sprintf("Retrieved %s %q", kind, name)
	}
	return fmt.Sprintf("Retrieved %s %q (%d value(s) redacted)", kind, name, redactedCount)
}

// redactSummary applies Layer 3 redaction to the parts of a Summary that
// carry free-form or passthrough content: Status (a curated but arbitrary
// map of status fields) and each Condition's Message (free text from the
// resource's own status.conditions). The rest of Summary (name, labels,
// timestamps) is structural metadata, not passthrough content, so it's left
// alone. Returns the number of values redacted.
func redactSummary(s *Summary) int {
	count := 0
	if s.Status != nil {
		redacted, n := redact.WalkObject(s.Status)
		s.Status = redacted.(map[string]any)
		count += n
	}
	for i, c := range s.Conditions {
		if reason := redact.Check("message", c.Message); reason != "" {
			s.Conditions[i].Message = fmt.Sprintf("[REDACTED: %s, %d chars]", reason, len(c.Message))
			count++
		}
	}
	return count
}

func (t *Task) errorResult(err *StructuredError) *task.Result {
	return &task.Result{
		Success: false,
		Error:   err.Error(),
		Details: err,
	}
}
