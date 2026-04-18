// Package get_events provides Kubernetes event retrieval functionality.
package get_events

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/loafoe/pico-agent/internal/task"
)

const TaskName = "get_events"

// Payload for get_events task.
type Payload struct {
	Namespace      string `json:"namespace"`
	InvolvedObject string `json:"involved_object,omitempty"`
	Type           string `json:"type,omitempty"`
	SinceMinutes   int    `json:"since_minutes,omitempty"`
}

// EventList contains the event listing.
type EventList struct {
	Total  int         `json:"total"`
	Events []EventInfo `json:"events"`
}

// EventInfo contains event details.
type EventInfo struct {
	Timestamp string `json:"timestamp"`
	Type      string `json:"type"`
	Reason    string `json:"reason"`
	Object    string `json:"object"`
	Message   string `json:"message"`
	Count     int32  `json:"count"`
}

// Task handles event retrieval.
type Task struct {
	clientset kubernetes.Interface
}

// New creates a new get_events task.
func New(clientset kubernetes.Interface) *Task {
	return &Task{clientset: clientset}
}

// Name returns the task type identifier.
func (t *Task) Name() string {
	return TaskName
}

// Execute retrieves events from a namespace.
func (t *Task) Execute(ctx context.Context, rawPayload json.RawMessage) (*task.Result, error) {
	var payload Payload
	if len(rawPayload) > 0 && string(rawPayload) != "{}" {
		if err := json.Unmarshal(rawPayload, &payload); err != nil {
			return task.NewErrorResult(fmt.Sprintf("invalid payload: %v", err)), nil
		}
	}

	// Validate required fields
	if payload.Namespace == "" {
		return task.NewErrorResult("namespace is required"), nil
	}

	// Default since_minutes to 60 if not specified or <= 0
	if payload.SinceMinutes <= 0 {
		payload.SinceMinutes = 60
	}

	// Default type to "all" if empty
	if payload.Type == "" {
		payload.Type = "all"
	}

	// Build list options
	listOpts := metav1.ListOptions{}

	// Filter by type if "Normal" or "Warning" using FieldSelector
	if payload.Type == "Normal" || payload.Type == "Warning" {
		listOpts.FieldSelector = fmt.Sprintf("type=%s", payload.Type)
	}

	// List events
	events, err := t.clientset.CoreV1().Events(payload.Namespace).List(ctx, listOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to list events: %w", err)
	}

	// Calculate time cutoff
	cutoffTime := time.Now().Add(-time.Duration(payload.SinceMinutes) * time.Minute)

	// Build result list with filtering
	result := &EventList{
		Events: make([]EventInfo, 0),
	}

	for i := range events.Items {
		event := &events.Items[i]

		// Filter by involved object name if specified
		if payload.InvolvedObject != "" && event.InvolvedObject.Name != payload.InvolvedObject {
			continue
		}

		// Get the event timestamp (prefer LastTimestamp, then EventTime, then CreationTimestamp)
		eventTime := getEventTime(event)

		// Filter by time
		if eventTime.Before(cutoffTime) {
			continue
		}

		// Build Object field as "Kind/Name" from InvolvedObject
		objectRef := fmt.Sprintf("%s/%s", event.InvolvedObject.Kind, event.InvolvedObject.Name)

		eventInfo := EventInfo{
			Timestamp: eventTime.Format(time.RFC3339),
			Type:      event.Type,
			Reason:    event.Reason,
			Object:    objectRef,
			Message:   event.Message,
			Count:     event.Count,
		}

		result.Events = append(result.Events, eventInfo)
	}

	// Sort by timestamp descending (newest first)
	sort.Slice(result.Events, func(i, j int) bool {
		return result.Events[i].Timestamp > result.Events[j].Timestamp
	})

	result.Total = len(result.Events)

	return task.NewSuccessResultWithDetails(
		fmt.Sprintf("Found %d events in namespace %s", result.Total, payload.Namespace),
		result,
	), nil
}

// getEventTime returns the most relevant timestamp for an event.
// It prefers LastTimestamp, then EventTime, then CreationTimestamp.
func getEventTime(event *corev1.Event) time.Time {
	// Try LastTimestamp first
	if !event.LastTimestamp.IsZero() {
		return event.LastTimestamp.Time
	}

	// Try EventTime (used in newer event API)
	if !event.EventTime.IsZero() {
		return event.EventTime.Time
	}

	// Fall back to CreationTimestamp
	return event.CreationTimestamp.Time
}
