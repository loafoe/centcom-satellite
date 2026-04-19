// Package get_resource provides generic Kubernetes resource retrieval.
package get_resource

import (
	"encoding/json"
	"fmt"

	"k8s.io/apimachinery/pkg/api/meta"
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
