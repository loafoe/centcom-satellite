package task

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
)

var (
	// ErrTaskNotFound is returned when requesting an unknown task type.
	ErrTaskNotFound = errors.New("task not found")

	// ErrEmptyTaskType is returned when the task type is empty.
	ErrEmptyTaskType = errors.New("task type cannot be empty")
)

// Registry manages task handlers.
type Registry struct {
	mu    sync.RWMutex
	tasks map[string]Task
}

// NewRegistry creates a new task registry.
func NewRegistry() *Registry {
	return &Registry{
		tasks: make(map[string]Task),
	}
}

// Register adds a task handler to the registry.
// If a task with the same name already exists, it will be replaced.
func (r *Registry) Register(t Task) {
	r.mu.Lock()
	defer r.mu.Unlock()

	name := t.Name()
	r.tasks[name] = t
	slog.Info("registered task", "name", name)
}

// Get retrieves a task handler by name.
func (r *Registry) Get(name string) (Task, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	t, ok := r.tasks[name]
	return t, ok
}

// List returns all registered task names.
func (r *Registry) List() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	names := make([]string, 0, len(r.tasks))
	for name := range r.tasks {
		names = append(names, name)
	}
	return names
}

// Execute runs a task based on the request.
func (r *Registry) Execute(ctx context.Context, req Request) (*Result, error) {
	if req.Type == "" {
		return nil, ErrEmptyTaskType
	}

	task, ok := r.Get(req.Type)
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrTaskNotFound, req.Type)
	}

	return task.Execute(ctx, req.Payload)
}

// ParseRequest parses a JSON request body into a Request.
func ParseRequest(data []byte) (*Request, error) {
	var req Request
	if err := json.Unmarshal(data, &req); err != nil {
		return nil, fmt.Errorf("invalid request format: %w", err)
	}
	return &req, nil
}
