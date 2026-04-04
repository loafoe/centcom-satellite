// Package task provides the task execution framework.
package task

import (
	"context"
	"encoding/json"
)

// Request represents an incoming task request.
type Request struct {
	// Type identifies which task handler should process this request.
	Type string `json:"type"`

	// Payload contains task-specific data.
	Payload json.RawMessage `json:"payload"`
}

// Result represents the outcome of a task execution.
type Result struct {
	// Success indicates whether the task completed successfully.
	Success bool `json:"success"`

	// Message provides additional context about the result.
	Message string `json:"message,omitempty"`

	// Error contains error details if the task failed.
	Error string `json:"error,omitempty"`

	// Details contains task-specific additional information.
	Details any `json:"details,omitempty"`
}

// NewSuccessResult creates a successful result with a message.
func NewSuccessResult(message string) *Result {
	return &Result{
		Success: true,
		Message: message,
	}
}

// NewSuccessResultWithDetails creates a successful result with a message and details.
func NewSuccessResultWithDetails(message string, details any) *Result {
	return &Result{
		Success: true,
		Message: message,
		Details: details,
	}
}

// NewErrorResult creates a failed result with an error message.
func NewErrorResult(err string) *Result {
	return &Result{
		Success: false,
		Error:   err,
	}
}

// Task defines the interface that all task handlers must implement.
type Task interface {
	// Name returns the unique identifier for this task type.
	Name() string

	// Execute processes the task with the given payload.
	// The context carries request-scoped values like trace spans.
	Execute(ctx context.Context, payload json.RawMessage) (*Result, error)
}
