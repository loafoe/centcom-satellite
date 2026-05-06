// Package dns_check provides DNS resolution testing functionality.
package dns_check

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/loafoe/pico-agent/internal/task"
)

const TaskName = "dns_check"

// Payload for dns_check task.
type Payload struct {
	Hostname  string `json:"hostname"`
	Namespace string `json:"namespace,omitempty"`
}

// DNSCheckResult contains DNS resolution results.
type DNSCheckResult struct {
	Hostname   string   `json:"hostname"`
	Resolved   string   `json:"resolved"`
	Addresses  []string `json:"addresses"`
	DurationMs int64    `json:"duration_ms"`
	Error      string   `json:"error,omitempty"`
}

// Resolver interface for DNS lookups (allows testing).
type Resolver interface {
	LookupHost(ctx context.Context, host string) ([]string, error)
}

// Task handles DNS resolution checks.
type Task struct {
	resolver Resolver
}

// New creates a new dns check task.
func New() *Task {
	return &Task{resolver: net.DefaultResolver}
}

// NewWithResolver creates a dns check task with a custom resolver.
func NewWithResolver(resolver Resolver) *Task {
	return &Task{resolver: resolver}
}

// Name returns the task type identifier.
func (t *Task) Name() string {
	return TaskName
}

// Execute performs DNS resolution.
func (t *Task) Execute(ctx context.Context, rawPayload json.RawMessage) (*task.Result, error) {
	var payload Payload
	if err := json.Unmarshal(rawPayload, &payload); err != nil {
		return task.NewErrorResult(fmt.Sprintf("invalid payload: %v", err)), nil
	}

	if payload.Hostname == "" {
		return task.NewErrorResult("hostname is required"), nil
	}

	// Set timeout
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	result := &DNSCheckResult{
		Hostname: payload.Hostname,
	}

	// Build list of names to try
	namesToTry := t.buildNamesToTry(payload.Hostname, payload.Namespace)

	start := time.Now()
	var lastErr error
	var addrs []string

	for _, name := range namesToTry {
		addrs, lastErr = t.resolver.LookupHost(ctx, name)
		if lastErr == nil && len(addrs) > 0 {
			result.Resolved = name
			result.Addresses = addrs
			break
		}
	}

	result.DurationMs = time.Since(start).Milliseconds()

	if result.Resolved == "" {
		if lastErr != nil {
			result.Error = lastErr.Error()
		} else {
			result.Error = "no addresses found"
		}
		return task.NewSuccessResultWithDetails(
			fmt.Sprintf("DNS resolution failed for %s", payload.Hostname),
			result,
		), nil
	}

	return task.NewSuccessResultWithDetails(
		fmt.Sprintf("Resolved %s to %d addresses", result.Resolved, len(result.Addresses)),
		result,
	), nil
}

func (t *Task) buildNamesToTry(hostname, namespace string) []string {
	// If hostname already contains dots, try it as-is first
	if strings.Contains(hostname, ".") {
		return []string{hostname}
	}

	var names []string

	// If namespace provided, try namespace-scoped names first
	if namespace != "" {
		names = append(names,
			fmt.Sprintf("%s.%s.svc.cluster.local", hostname, namespace),
			fmt.Sprintf("%s.%s.svc", hostname, namespace),
			fmt.Sprintf("%s.%s", hostname, namespace),
		)
	}

	// Always try the bare hostname last (uses system search domains)
	names = append(names, hostname)

	return names
}
