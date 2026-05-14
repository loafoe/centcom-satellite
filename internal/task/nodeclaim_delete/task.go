// Package nodeclaim_delete provides NodeClaim deletion functionality for Karpenter.
package nodeclaim_delete

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"

	"github.com/loafoe/pico-agent/internal/task"
)

const (
	TaskName             = "nodeclaim_delete"
	DoNotDisruptAnnotation = "karpenter.sh/do-not-disrupt"
	NodePoolLabel        = "karpenter.sh/nodepool"
)

var (
	ErrInvalidPayload    = errors.New("invalid payload")
	ErrMissingName       = errors.New("name is required")
	ErrNodeClaimNotFound = errors.New("nodeclaim not found")
	ErrDoNotDisrupt      = errors.New("nodeclaim has karpenter.sh/do-not-disrupt annotation; use force=true to override")
	ErrCRDNotInstalled   = errors.New("nodeclaim CRD not found in cluster")
)

var nodeClaimGVR = schema.GroupVersionResource{
	Group:    "karpenter.sh",
	Version:  "v1",
	Resource: "nodeclaims",
}

// Unused imports are required by Execute method (Task 4)
var (
	_ = context.Background
	_ = json.Marshal
	_ = fmt.Errorf
	_ = slog.Info
	_ = strings.TrimSpace
	_ apierrors.StatusError
	_ = metav1.Now
	_ = unstructured.Unstructured{}
	_ = task.Result{}
)

// Payload represents the input for a nodeclaim delete operation.
type Payload struct {
	Name   string `json:"name"`
	DryRun bool   `json:"dry_run"`
	Force  bool   `json:"force"`
}

// DeleteDetails contains information about the delete operation.
type DeleteDetails struct {
	Name         string `json:"name"`
	NodeName     string `json:"node_name,omitempty"`
	InstanceType string `json:"instance_type,omitempty"`
	NodePool     string `json:"nodepool,omitempty"`
	DryRun       bool   `json:"dry_run"`
	Force        bool   `json:"force"`
}

// Task handles nodeclaim delete operations.
type Task struct {
	dynamicClient dynamic.Interface
}

// New creates a new nodeclaim delete task.
func New(dynamicClient dynamic.Interface) *Task {
	return &Task{dynamicClient: dynamicClient}
}

// Name returns the task type identifier.
func (t *Task) Name() string {
	return TaskName
}
