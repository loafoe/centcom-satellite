// Package get_resource provides generic Kubernetes resource retrieval.
package get_resource

import (
	"encoding/json"
	"errors"
	"fmt"

	"k8s.io/apimachinery/pkg/api/meta"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
)

// ErrorCode represents a structured error code for get_resource failures.
type ErrorCode string

const (
	ErrNotFound          ErrorCode = "NOT_FOUND"
	ErrForbidden         ErrorCode = "FORBIDDEN"
	ErrBlocked           ErrorCode = "BLOCKED"
	ErrAPINotFound       ErrorCode = "API_NOT_FOUND"
	ErrInvalidRequest    ErrorCode = "INVALID_REQUEST"
	ErrNamespaceRequired ErrorCode = "NAMESPACE_REQUIRED"
	ErrTimeout           ErrorCode = "TIMEOUT"
	ErrServerError       ErrorCode = "SERVER_ERROR"
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
		Hint:    "centcom-satellite needs RBAC permission for this resource",
	}
}

// NewBlockedError creates a BLOCKED error for explicitly blocked resource types.
func NewBlockedError(kind string) *StructuredError {
	return &StructuredError{
		Code:    ErrBlocked,
		Message: fmt.Sprintf("%s resources are explicitly blocked", kind),
		Hint:    "This resource type cannot be retrieved for security reasons",
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

// NewServerError creates a SERVER_ERROR error for a transient apiserver-side
// failure (5xx, 429 flow control, or a transport-level failure with no
// APIStatus at all - connection refused, TLS, etc.). Unlike
// NewInvalidRequestError's hint ("check apiVersion format"), this is never a
// request mistake, so the hint says to retry instead of misleadingly
// pointing at the request shape.
func NewServerError(err error) *StructuredError {
	return &StructuredError{
		Code:    ErrServerError,
		Message: err.Error(),
		Hint:    "Transient apiserver problem, not a request mistake; retry",
	}
}

// IsServerFault reports whether err is a 5xx/429/transport-level failure
// rather than a definite 4xx client mistake — same classification
// k8sclient.WrapError uses (every apiserver error implements
// apierrors.APIStatus, whose Status().Code carries the real HTTP status).
func IsServerFault(err error) bool {
	var status apierrors.APIStatus
	if errors.As(err, &status) {
		code := status.Status().Code
		return !(code >= 400 && code < 500 && code != 429)
	}
	return true
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
	// A genuine server-side/throttling/transport failure is not a request
	// mistake - don't mislabel it as one.
	if IsServerFault(err) {
		return NewServerError(err)
	}
	// Default to invalid request for other (definite 4xx client-fault) errors
	return NewInvalidRequestError(err.Error())
}
