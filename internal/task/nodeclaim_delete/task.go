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

// Execute performs the nodeclaim delete operation.
func (t *Task) Execute(ctx context.Context, rawPayload json.RawMessage) (*task.Result, error) {
	payload, err := t.parsePayload(rawPayload)
	if err != nil {
		return task.NewErrorResult(err.Error()), nil
	}

	if err := t.validatePayload(payload); err != nil {
		return task.NewErrorResult(err.Error()), nil
	}

	// Get the NodeClaim
	nodeClaim, err := t.dynamicClient.Resource(nodeClaimGVR).Get(ctx, payload.Name, metav1.GetOptions{})
	if err != nil {
		if isNotFoundOrNoCRD(err) {
			if isCRDNotInstalled(err) {
				return task.NewErrorResult(ErrCRDNotInstalled.Error()), nil
			}
			return task.NewErrorResult(fmt.Sprintf("%s: %s", ErrNodeClaimNotFound, payload.Name)), nil
		}
		return nil, fmt.Errorf("failed to get nodeclaim: %w", err)
	}

	// Extract details from the NodeClaim
	details := t.extractDetails(nodeClaim, payload)

	// Check do-not-disrupt annotation
	if !payload.Force {
		annotations := nodeClaim.GetAnnotations()
		if annotations[DoNotDisruptAnnotation] == "true" {
			return task.NewErrorResult(fmt.Sprintf("nodeclaim %s %s", payload.Name, ErrDoNotDisrupt)), nil
		}
	}

	// If dry run, return success without deleting
	if payload.DryRun {
		return task.NewSuccessResultWithDetails(
			fmt.Sprintf("[DRY-RUN] Would delete NodeClaim %s", payload.Name),
			details,
		), nil
	}

	// Delete the NodeClaim
	err = t.dynamicClient.Resource(nodeClaimGVR).Delete(ctx, payload.Name, metav1.DeleteOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to delete nodeclaim: %w", err)
	}

	slog.Info("nodeclaim deletion initiated",
		"name", payload.Name,
		"node_name", details.NodeName,
		"instance_type", details.InstanceType,
		"nodepool", details.NodePool,
		"force", payload.Force,
	)

	return task.NewSuccessResultWithDetails(
		fmt.Sprintf("NodeClaim %s deletion initiated", payload.Name),
		details,
	), nil
}

func (t *Task) parsePayload(rawPayload json.RawMessage) (*Payload, error) {
	if len(rawPayload) == 0 {
		return nil, ErrInvalidPayload
	}

	var payload Payload
	if err := json.Unmarshal(rawPayload, &payload); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidPayload, err)
	}

	return &payload, nil
}

func (t *Task) validatePayload(p *Payload) error {
	if p.Name == "" {
		return ErrMissingName
	}
	return nil
}

func (t *Task) extractDetails(nodeClaim *unstructured.Unstructured, payload *Payload) *DeleteDetails {
	details := &DeleteDetails{
		Name:   payload.Name,
		DryRun: payload.DryRun,
		Force:  payload.Force,
	}

	// Extract node name from status.nodeName
	if nodeName, found, err := unstructured.NestedString(nodeClaim.Object, "status", "nodeName"); err == nil && found {
		details.NodeName = nodeName
	}

	// Extract instance type from status.instanceType
	if instanceType, found, err := unstructured.NestedString(nodeClaim.Object, "status", "instanceType"); err == nil && found {
		details.InstanceType = instanceType
	}

	// Extract nodepool from labels
	labels := nodeClaim.GetLabels()
	if nodePool, ok := labels[NodePoolLabel]; ok {
		details.NodePool = nodePool
	}

	return details
}

func isNotFoundOrNoCRD(err error) bool {
	if apierrors.IsNotFound(err) {
		return true
	}
	errStr := err.Error()
	return strings.Contains(errStr, "the server could not find the requested resource") ||
		strings.Contains(errStr, "no matches for kind")
}

func isCRDNotInstalled(err error) bool {
	errStr := err.Error()
	return strings.Contains(errStr, "the server could not find the requested resource") ||
		strings.Contains(errStr, "no matches for kind")
}
