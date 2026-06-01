// Package get_configmap reads ConfigMap values with automatic redaction of
// secret-looking content.
//
// Values whose key name, structure, or entropy looks like a secret are masked as
// "[REDACTED: <reason>, <n> chars]". There is intentionally no parameter to reveal
// raw values: this LLM-fronted tool must never be a secrets exfiltration path. Raw
// secret values are the domain of kubectl/Secret access, not this task.
//
// binaryData entries are never returned as values; their keys are listed separately.
package get_configmap

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/loafoe/pico-agent/internal/task"
)

const TaskName = "get_configmap"

// Payload contains parameters for the get_configmap task.
type Payload struct {
	Namespace string   `json:"namespace"`
	Name      string   `json:"name"`
	Keys      []string `json:"keys,omitempty"`
}

// ConfigMapDetail contains a ConfigMap's (redacted) values plus redaction metadata.
type ConfigMapDetail struct {
	Name         string            `json:"name"`
	Namespace    string            `json:"namespace"`
	Data         map[string]string `json:"data"`
	RedactedKeys []string          `json:"redacted_keys"`
	BinaryKeys   []string          `json:"binary_keys"`
	Age          string            `json:"age"`
}

// Task handles reading a ConfigMap with redaction.
type Task struct {
	clientset kubernetes.Interface
}

// New creates a new get configmap task.
func New(clientset kubernetes.Interface) *Task {
	return &Task{clientset: clientset}
}

// Name returns the task type identifier.
func (t *Task) Name() string {
	return TaskName
}

// Execute reads a ConfigMap and returns its values with secret-looking values redacted.
func (t *Task) Execute(ctx context.Context, rawPayload json.RawMessage) (*task.Result, error) {
	var payload Payload
	if len(rawPayload) > 0 && string(rawPayload) != "{}" {
		if err := json.Unmarshal(rawPayload, &payload); err != nil {
			return task.NewErrorResult(fmt.Sprintf("invalid payload: %v", err)), nil
		}
	}
	if payload.Namespace == "" {
		return task.NewErrorResult("namespace is required"), nil
	}
	if payload.Name == "" {
		return task.NewErrorResult("name is required"), nil
	}

	cm, err := t.clientset.CoreV1().ConfigMaps(payload.Namespace).Get(ctx, payload.Name, metav1.GetOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			return task.NewErrorResult(fmt.Sprintf("configmap %s/%s not found", payload.Namespace, payload.Name)), nil
		}
		return nil, fmt.Errorf("failed to get configmap %s/%s: %w", payload.Namespace, payload.Name, err)
	}

	// Build the key filter set (empty means "all keys").
	var keyFilter map[string]bool
	if len(payload.Keys) > 0 {
		keyFilter = make(map[string]bool, len(payload.Keys))
		for _, k := range payload.Keys {
			keyFilter[k] = true
		}
	}

	detail := &ConfigMapDetail{
		Name:         cm.Name,
		Namespace:    cm.Namespace,
		Data:         make(map[string]string, len(cm.Data)),
		RedactedKeys: []string{},
		BinaryKeys:   []string{},
		Age:          formatAge(cm.CreationTimestamp.Time),
	}

	for k, v := range cm.Data {
		if keyFilter != nil && !keyFilter[k] {
			continue
		}
		if reason := redact(k, v); reason != "" {
			detail.Data[k] = fmt.Sprintf("[REDACTED: %s, %d chars]", reason, len(v))
			detail.RedactedKeys = append(detail.RedactedKeys, k)
		} else {
			detail.Data[k] = v
		}
	}

	// binaryData values are never returned; only their key names are listed.
	for k := range cm.BinaryData {
		if keyFilter != nil && !keyFilter[k] {
			continue
		}
		detail.BinaryKeys = append(detail.BinaryKeys, k)
	}

	sort.Strings(detail.RedactedKeys)
	sort.Strings(detail.BinaryKeys)

	msg := fmt.Sprintf("Read configmap %s/%s (%d keys, %d redacted)",
		cm.Namespace, cm.Name, len(detail.Data), len(detail.RedactedKeys))

	return task.NewSuccessResultWithDetails(msg, detail), nil
}
