// Package list_resources provides generic Kubernetes resource discovery by
// apiVersion/kind — the discovery counterpart to get_resource. get_resource
// requires an exact name; this returns the names/namespaces that actually
// exist so a caller can find one to pass to get_resource, instead of having
// to already know it via some other out-of-band means.
package list_resources

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"

	"github.com/loafoe/centcom-satellite/internal/task"
	"github.com/loafoe/centcom-satellite/internal/task/get_resource"
	"github.com/loafoe/centcom-satellite/internal/task/resourceaccess"
)

const TaskName = "list_resources"

// defaultLimit and maxLimit bound how many items a single call can return,
// so an unbounded "list every X in the cluster" can't blow up the response.
// A caller that needs more should narrow with namespace/labelSelector.
const (
	defaultLimit = 200
	maxLimit     = 1000
)

// Payload is the input for list_resources.
type Payload struct {
	APIVersion    string `json:"apiVersion"`
	Kind          string `json:"kind"`
	Namespace     string `json:"namespace,omitempty"`     // omit to list across all namespaces (namespaced kinds) / ignored for cluster-scoped kinds
	LabelSelector string `json:"labelSelector,omitempty"`
	Limit         int64  `json:"limit,omitempty"` // default 200, capped at 1000
}

// ListResult is the LLM-optimized output format.
type ListResult struct {
	APIVersion string        `json:"apiVersion"`
	Kind       string        `json:"kind"`
	Scope      string        `json:"scope"` // "namespaced" or "cluster"
	Total      int           `json:"total"`
	Truncated  bool          `json:"truncated"`
	Items      []ResourceRef `json:"items"`
}

// ResourceRef is a lightweight reference to a discovered resource: enough to
// pass straight into get_resource. Status is intentionally limited to
// condition type/status pairs (no message/reason free text) — a listing
// covers potentially many objects at once, so unlike get_resource's Layer 3
// redaction of a single object, the leaner shape here avoids the need for
// per-item redaction entirely.
type ResourceRef struct {
	Name       string      `json:"name"`
	Namespace  string      `json:"namespace,omitempty"`
	Age        string      `json:"age,omitempty"`
	Conditions []Condition `json:"conditions,omitempty"`
}

// Condition is a minimal type/status pair from status.conditions.
type Condition struct {
	Type   string `json:"type"`
	Status string `json:"status"`
}

// Task handles generic resource listing.
type Task struct {
	dynamicClient dynamic.Interface
	restMapper    meta.RESTMapper
	denylist      *resourceaccess.Denylist
}

// New creates a new list_resources task. denylist may be nil, in which case
// only the non-negotiable default (Secret) is blocked - see
// resourceaccess.New. Pass the same Denylist instance used for get_resource
// so the exclusion can't be bypassed by listing instead of getting.
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

// Execute lists Kubernetes resources matching apiVersion/kind.
func (t *Task) Execute(ctx context.Context, payloadBytes json.RawMessage) (*task.Result, error) {
	var payload Payload
	if len(payloadBytes) > 0 {
		if err := json.Unmarshal(payloadBytes, &payload); err != nil {
			return task.NewErrorResult(get_resource.NewInvalidRequestError("invalid payload: " + err.Error()).Error()), nil
		}
	}

	if payload.APIVersion == "" {
		return task.NewErrorResult(get_resource.NewInvalidRequestError("apiVersion is required").Error()), nil
	}
	if payload.Kind == "" {
		return task.NewErrorResult(get_resource.NewInvalidRequestError("kind is required").Error()), nil
	}

	gv, err := schema.ParseGroupVersion(payload.APIVersion)
	if err != nil {
		return task.NewErrorResult(get_resource.NewInvalidRequestError("invalid apiVersion: " + err.Error()).Error()), nil
	}
	gvk := gv.WithKind(payload.Kind)

	// Same shared, config-driven GVK denylist as get_resource - Secret is
	// always denied even with empty config.
	if t.denylist.IsDenied(gvk.GroupKind()) {
		return task.NewErrorResult(get_resource.NewBlockedError(payload.Kind).Error()), nil
	}

	mapping, err := t.restMapper.RESTMapping(gvk.GroupKind(), gvk.Version)
	if err != nil {
		structErr := get_resource.MapAPIError(err, payload.Kind, "", payload.APIVersion)
		return t.errorResult(structErr), nil
	}

	isNamespaced := mapping.Scope.Name() == meta.RESTScopeNameNamespace

	limit := payload.Limit
	if limit <= 0 {
		limit = defaultLimit
	}
	if limit > maxLimit {
		limit = maxLimit
	}
	listOpts := metav1.ListOptions{
		LabelSelector: payload.LabelSelector,
		Limit:         limit,
	}

	var resourceClient dynamic.ResourceInterface = t.dynamicClient.Resource(mapping.Resource)
	if isNamespaced && payload.Namespace != "" {
		resourceClient = t.dynamicClient.Resource(mapping.Resource).Namespace(payload.Namespace)
	}

	list, err := resourceClient.List(ctx, listOpts)
	if err != nil {
		structErr := mapListError(err, payload.Kind)
		return t.errorResult(structErr), nil
	}

	items := make([]ResourceRef, 0, len(list.Items))
	now := time.Now()
	for i := range list.Items {
		items = append(items, extractRef(&list.Items[i], now))
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].Namespace != items[j].Namespace {
			return items[i].Namespace < items[j].Namespace
		}
		return items[i].Name < items[j].Name
	})

	scope := "cluster"
	if isNamespaced {
		scope = "namespaced"
	}

	result := &ListResult{
		APIVersion: payload.APIVersion,
		Kind:       payload.Kind,
		Scope:      scope,
		Total:      len(items),
		Truncated:  list.GetContinue() != "",
		Items:      items,
	}

	return task.NewSuccessResultWithDetails(
		fmt.Sprintf("Found %d %s(s)", result.Total, payload.Kind),
		result,
	), nil
}

func extractRef(obj *unstructured.Unstructured, now time.Time) ResourceRef {
	ref := ResourceRef{
		Name:      obj.GetName(),
		Namespace: obj.GetNamespace(),
	}

	createdAt := obj.GetCreationTimestamp()
	if !createdAt.IsZero() {
		ref.Age = formatAge(now.Sub(createdAt.Time))
	}

	status, found, _ := unstructured.NestedSlice(obj.Object, "status", "conditions")
	if found {
		for _, c := range status {
			condMap, ok := c.(map[string]any)
			if !ok {
				continue
			}
			condType, _ := condMap["type"].(string)
			condStatus, _ := condMap["status"].(string)
			if condType == "" {
				continue
			}
			ref.Conditions = append(ref.Conditions, Condition{Type: condType, Status: condStatus})
		}
	}

	return ref
}

func formatAge(d time.Duration) string {
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

// mapListError maps a List() API error, distinct from get_resource's
// MapAPIError because there's no single resource name to report - a Forbidden
// here means "can't list the kind at all", not "can't read this one object".
func mapListError(err error, kind string) *get_resource.StructuredError {
	if apierrors.IsForbidden(err) {
		return &get_resource.StructuredError{
			Code:    get_resource.ErrForbidden,
			Message: fmt.Sprintf("access denied to list %s", kind),
			Hint:    "centcom-satellite needs RBAC permission for this resource",
		}
	}
	if apierrors.IsTimeout(err) {
		return get_resource.NewTimeoutError()
	}
	if _, ok := err.(*meta.NoKindMatchError); ok {
		return get_resource.NewAPINotFoundError("", kind)
	}
	return get_resource.NewInvalidRequestError(err.Error())
}

func (t *Task) errorResult(err *get_resource.StructuredError) *task.Result {
	return &task.Result{
		Success: false,
		Error:   err.Error(),
		Details: err,
	}
}
