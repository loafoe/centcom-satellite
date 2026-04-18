// Package get_logs provides pod log retrieval functionality.
package get_logs

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/loafoe/pico-agent/internal/task"
)

const TaskName = "get_logs"

// maxLogBytes limits log output to prevent excessive memory use and context size.
const maxLogBytes = 512 * 1024 // 512KB

// Payload for get_logs task.
type Payload struct {
	Namespace    string `json:"namespace"`
	PodName      string `json:"pod_name"`
	Container    string `json:"container,omitempty"`
	TailLines    int64  `json:"tail_lines,omitempty"`
	SinceMinutes int64  `json:"since_minutes,omitempty"`
	Previous     bool   `json:"previous,omitempty"`
}

// LogResult contains the retrieved logs.
type LogResult struct {
	PodName   string `json:"pod_name"`
	Container string `json:"container"`
	Lines     int    `json:"lines"`
	Truncated bool   `json:"truncated"`
	Logs      string `json:"logs"`
}

// Task handles pod log retrieval.
type Task struct {
	clientset kubernetes.Interface
}

// New creates a new get_logs task.
func New(clientset kubernetes.Interface) *Task {
	return &Task{clientset: clientset}
}

// Name returns the task type identifier.
func (t *Task) Name() string {
	return TaskName
}

// Execute retrieves logs from a pod container.
func (t *Task) Execute(ctx context.Context, rawPayload json.RawMessage) (*task.Result, error) {
	var payload Payload
	if err := json.Unmarshal(rawPayload, &payload); err != nil {
		return task.NewErrorResult(fmt.Sprintf("invalid payload: %v", err)), nil
	}

	// Validate required fields
	if payload.Namespace == "" {
		return task.NewErrorResult("namespace is required"), nil
	}
	if payload.PodName == "" {
		return task.NewErrorResult("pod_name is required"), nil
	}

	// Default tail_lines to 100 if not specified
	if payload.TailLines <= 0 {
		payload.TailLines = 100
	}

	// Get pod to verify it exists and get first container name if not specified
	pod, err := t.clientset.CoreV1().Pods(payload.Namespace).Get(ctx, payload.PodName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to get pod: %w", err)
	}

	// Determine container name
	containerName := payload.Container
	if containerName == "" {
		if len(pod.Spec.Containers) == 0 {
			return task.NewErrorResult("pod has no containers"), nil
		}
		containerName = pod.Spec.Containers[0].Name
	}

	// Build log options
	opts := &corev1.PodLogOptions{
		Container: containerName,
		TailLines: &payload.TailLines,
		Previous:  payload.Previous,
	}

	// Add SinceSeconds if SinceMinutes is specified
	if payload.SinceMinutes > 0 {
		sinceSeconds := payload.SinceMinutes * 60
		opts.SinceSeconds = &sinceSeconds
	}

	// Get log stream
	stream, err := t.clientset.CoreV1().Pods(payload.Namespace).GetLogs(payload.PodName, opts).Stream(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get log stream: %w", err)
	}
	defer stream.Close()

	// Read with size limit
	limitedReader := io.LimitReader(stream, maxLogBytes+1)
	logBytes, err := io.ReadAll(limitedReader)
	if err != nil {
		return nil, fmt.Errorf("failed to read logs: %w", err)
	}

	// Check if truncated
	truncated := len(logBytes) > maxLogBytes
	if truncated {
		logBytes = logBytes[:maxLogBytes]
		// Ensure we don't split a multi-byte UTF-8 character
		for len(logBytes) > 0 && !utf8.Valid(logBytes) {
			logBytes = logBytes[:len(logBytes)-1]
		}
	}

	// Count newlines for line count
	logs := string(logBytes)
	lineCount := strings.Count(logs, "\n")
	if len(logs) > 0 && !strings.HasSuffix(logs, "\n") {
		lineCount++
	}

	result := &LogResult{
		PodName:   payload.PodName,
		Container: containerName,
		Lines:     lineCount,
		Truncated: truncated,
		Logs:      logs,
	}

	message := fmt.Sprintf("Retrieved %d lines from %s/%s", lineCount, payload.PodName, containerName)
	if truncated {
		message += " (truncated)"
	}

	return task.NewSuccessResultWithDetails(message, result), nil
}
