# NodeClaim Delete Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a `nodeclaim_delete` task that safely deletes Karpenter NodeClaims using the dynamic client.

**Architecture:** Feature-flagged task using `k8s.io/client-go/dynamic` to interact with `karpenter.sh/v1/NodeClaim` CRD. Follows existing patterns from `list_gateways` (dynamic client) and `workload_restart` (feature flag + safety rails).

**Tech Stack:** Go, client-go dynamic, testify, fake dynamic client

**Spec:** `docs/superpowers/specs/2026-05-14-nodeclaim-delete-design.md`

---

## File Structure

| File | Purpose |
|------|---------|
| `internal/task/nodeclaim_delete/task.go` | Task implementation |
| `internal/task/nodeclaim_delete/task_test.go` | Unit tests |
| `internal/config/config.go` | Add `NodeclaimDeleteEnabled` feature flag |
| `cmd/pico-agent/main.go` | Register task when enabled |
| `/Users/andy/DEV/Personal/helm-charts/charts/pico-agent/values.yaml` | Add `features.nodeclaimDelete` |
| `/Users/andy/DEV/Personal/helm-charts/charts/pico-agent/templates/clusterrole.yaml` | Add RBAC rule |
| `/Users/andy/DEV/Personal/helm-charts/charts/pico-agent/templates/deployment.yaml` | Add env var |
| `/Users/andy/DEV/Personal/helm-charts/charts/pico-agent/Chart.yaml` | Bump version |

---

## Task 1: Add Feature Flag to Config

**Files:**
- Modify: `internal/config/config.go`

- [ ] **Step 1.1: Add field to FeaturesConfig struct**

In `internal/config/config.go`, add after `PodResizeConfig`:

```go
// NodeclaimDeleteEnabled enables the nodeclaim_delete task for Karpenter node management.
// Disabled by default as it requires Karpenter and can cause node termination.
NodeclaimDeleteEnabled bool
```

- [ ] **Step 1.2: Load from environment in Load()**

In the `Features: FeaturesConfig{` block, add after `PodResizeConfig`:

```go
NodeclaimDeleteEnabled: getEnvBool("NODECLAIM_DELETE_ENABLED", false),
```

- [ ] **Step 1.3: Run tests**

Run: `go test ./internal/config/...`
Expected: PASS

- [ ] **Step 1.4: Commit**

```bash
git add internal/config/config.go
git commit -m "feat(config): add NodeclaimDeleteEnabled feature flag"
```

---

## Task 2: Create Task Implementation (Types and Constructor)

**Files:**
- Create: `internal/task/nodeclaim_delete/task.go`

- [ ] **Step 2.1: Create task file with package, imports, constants, and types**

Create `internal/task/nodeclaim_delete/task.go`:

```go
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
```

- [ ] **Step 2.2: Verify it compiles**

Run: `go build ./internal/task/nodeclaim_delete/...`
Expected: Success (no output)

- [ ] **Step 2.3: Commit**

```bash
git add internal/task/nodeclaim_delete/task.go
git commit -m "feat(nodeclaim_delete): add types and constructor"
```

---

## Task 3: Write Tests for Core Functionality

**Files:**
- Create: `internal/task/nodeclaim_delete/task_test.go`

- [ ] **Step 3.1: Create test file with test for Name() and missing name validation**

Create `internal/task/nodeclaim_delete/task_test.go`:

```go
package nodeclaim_delete

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	k8stesting "k8s.io/client-go/testing"
)

func TestTask_Name(t *testing.T) {
	task := New(nil)
	assert.Equal(t, "nodeclaim_delete", task.Name())
}

func TestTask_Execute_MissingName(t *testing.T) {
	client := dynamicfake.NewSimpleDynamicClient(runtime.NewScheme())
	task := New(client)

	payload := Payload{Name: ""}
	payloadJSON, err := json.Marshal(payload)
	require.NoError(t, err)

	result, err := task.Execute(context.Background(), payloadJSON)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.False(t, result.Success)
	assert.Contains(t, result.Error, "name is required")
}

func TestTask_Execute_InvalidPayload(t *testing.T) {
	client := dynamicfake.NewSimpleDynamicClient(runtime.NewScheme())
	task := New(client)

	result, err := task.Execute(context.Background(), json.RawMessage(`{invalid`))
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.False(t, result.Success)
	assert.Contains(t, result.Error, "invalid payload")
}
```

- [ ] **Step 3.2: Run tests (expect failures since Execute not implemented)**

Run: `go test ./internal/task/nodeclaim_delete/... -v`
Expected: Compilation error (Execute method not defined)

- [ ] **Step 3.3: Commit test file**

```bash
git add internal/task/nodeclaim_delete/task_test.go
git commit -m "test(nodeclaim_delete): add initial test cases"
```

---

## Task 4: Implement Execute Method

**Files:**
- Modify: `internal/task/nodeclaim_delete/task.go`

- [ ] **Step 4.1: Add Execute method**

Add to `internal/task/nodeclaim_delete/task.go` after the `Name()` method:

```go
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
```

- [ ] **Step 4.2: Run tests**

Run: `go test ./internal/task/nodeclaim_delete/... -v`
Expected: PASS for Name, MissingName, InvalidPayload tests

- [ ] **Step 4.3: Commit**

```bash
git add internal/task/nodeclaim_delete/task.go
git commit -m "feat(nodeclaim_delete): implement Execute method"
```

---

## Task 5: Add Remaining Tests

**Files:**
- Modify: `internal/task/nodeclaim_delete/task_test.go`

- [ ] **Step 5.1: Add test for NodeClaim not found**

Add to `task_test.go`:

```go
func TestTask_Execute_NodeClaimNotFound(t *testing.T) {
	scheme := runtime.NewScheme()
	client := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(
		scheme,
		map[schema.GroupVersionResource]string{
			nodeClaimGVR: "NodeClaimList",
		},
	)

	// Add reactor to return NotFound
	client.PrependReactor("get", "nodeclaims", func(action k8stesting.Action) (handled bool, ret runtime.Object, err error) {
		return true, nil, apierrors.NewNotFound(
			schema.GroupResource{Group: "karpenter.sh", Resource: "nodeclaims"},
			"nonexistent",
		)
	})

	task := New(client)

	payload := Payload{Name: "nonexistent"}
	payloadJSON, err := json.Marshal(payload)
	require.NoError(t, err)

	result, err := task.Execute(context.Background(), payloadJSON)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.False(t, result.Success)
	assert.Contains(t, result.Error, "nodeclaim not found")
}
```

- [ ] **Step 5.2: Add test for do-not-disrupt blocking**

Add to `task_test.go`:

```go
func TestTask_Execute_DoNotDisruptBlocks(t *testing.T) {
	scheme := runtime.NewScheme()
	client := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(
		scheme,
		map[schema.GroupVersionResource]string{
			nodeClaimGVR: "NodeClaimList",
		},
	)

	// Create a NodeClaim with do-not-disrupt annotation
	nodeClaim := &unstructured.Unstructured{}
	nodeClaim.SetGroupVersionKind(schema.GroupVersionKind{
		Group:   "karpenter.sh",
		Version: "v1",
		Kind:    "NodeClaim",
	})
	nodeClaim.SetName("protected-node")
	nodeClaim.SetAnnotations(map[string]string{
		"karpenter.sh/do-not-disrupt": "true",
	})

	_, err := client.Resource(nodeClaimGVR).Create(context.Background(), nodeClaim, metav1.CreateOptions{})
	require.NoError(t, err)

	task := New(client)

	payload := Payload{Name: "protected-node", Force: false}
	payloadJSON, err := json.Marshal(payload)
	require.NoError(t, err)

	result, err := task.Execute(context.Background(), payloadJSON)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.False(t, result.Success)
	assert.Contains(t, result.Error, "do-not-disrupt")
	assert.Contains(t, result.Error, "force=true")
}
```

- [ ] **Step 5.3: Add test for force bypassing do-not-disrupt**

Add to `task_test.go`:

```go
func TestTask_Execute_ForceBypassesDoNotDisrupt(t *testing.T) {
	scheme := runtime.NewScheme()
	client := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(
		scheme,
		map[schema.GroupVersionResource]string{
			nodeClaimGVR: "NodeClaimList",
		},
	)

	// Create a NodeClaim with do-not-disrupt annotation
	nodeClaim := &unstructured.Unstructured{}
	nodeClaim.SetGroupVersionKind(schema.GroupVersionKind{
		Group:   "karpenter.sh",
		Version: "v1",
		Kind:    "NodeClaim",
	})
	nodeClaim.SetName("protected-node")
	nodeClaim.SetAnnotations(map[string]string{
		"karpenter.sh/do-not-disrupt": "true",
	})
	nodeClaim.SetLabels(map[string]string{
		"karpenter.sh/nodepool": "default",
	})
	_ = unstructured.SetNestedField(nodeClaim.Object, "ip-10-0-1-42.ec2.internal", "status", "nodeName")
	_ = unstructured.SetNestedField(nodeClaim.Object, "m5.large", "status", "instanceType")

	_, err := client.Resource(nodeClaimGVR).Create(context.Background(), nodeClaim, metav1.CreateOptions{})
	require.NoError(t, err)

	task := New(client)

	payload := Payload{Name: "protected-node", Force: true}
	payloadJSON, err := json.Marshal(payload)
	require.NoError(t, err)

	result, err := task.Execute(context.Background(), payloadJSON)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.Success)
	assert.Contains(t, result.Message, "deletion initiated")

	// Verify details
	details, ok := result.Details.(*DeleteDetails)
	require.True(t, ok)
	assert.Equal(t, "protected-node", details.Name)
	assert.Equal(t, "ip-10-0-1-42.ec2.internal", details.NodeName)
	assert.Equal(t, "m5.large", details.InstanceType)
	assert.Equal(t, "default", details.NodePool)
	assert.True(t, details.Force)
}
```

- [ ] **Step 5.4: Add test for dry run**

Add to `task_test.go`:

```go
func TestTask_Execute_DryRun(t *testing.T) {
	scheme := runtime.NewScheme()
	client := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(
		scheme,
		map[schema.GroupVersionResource]string{
			nodeClaimGVR: "NodeClaimList",
		},
	)

	// Create a NodeClaim
	nodeClaim := &unstructured.Unstructured{}
	nodeClaim.SetGroupVersionKind(schema.GroupVersionKind{
		Group:   "karpenter.sh",
		Version: "v1",
		Kind:    "NodeClaim",
	})
	nodeClaim.SetName("test-node")
	nodeClaim.SetLabels(map[string]string{
		"karpenter.sh/nodepool": "default",
	})
	_ = unstructured.SetNestedField(nodeClaim.Object, "ip-10-0-1-42.ec2.internal", "status", "nodeName")
	_ = unstructured.SetNestedField(nodeClaim.Object, "m5.large", "status", "instanceType")

	_, err := client.Resource(nodeClaimGVR).Create(context.Background(), nodeClaim, metav1.CreateOptions{})
	require.NoError(t, err)

	task := New(client)

	payload := Payload{Name: "test-node", DryRun: true}
	payloadJSON, err := json.Marshal(payload)
	require.NoError(t, err)

	result, err := task.Execute(context.Background(), payloadJSON)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.Success)
	assert.Contains(t, result.Message, "[DRY-RUN]")

	// Verify NodeClaim still exists
	_, err = client.Resource(nodeClaimGVR).Get(context.Background(), "test-node", metav1.GetOptions{})
	assert.NoError(t, err, "NodeClaim should still exist after dry run")

	// Verify details
	details, ok := result.Details.(*DeleteDetails)
	require.True(t, ok)
	assert.True(t, details.DryRun)
}
```

- [ ] **Step 5.5: Add test for successful deletion**

Add to `task_test.go`:

```go
func TestTask_Execute_SuccessfulDeletion(t *testing.T) {
	scheme := runtime.NewScheme()
	client := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(
		scheme,
		map[schema.GroupVersionResource]string{
			nodeClaimGVR: "NodeClaimList",
		},
	)

	// Create a NodeClaim
	nodeClaim := &unstructured.Unstructured{}
	nodeClaim.SetGroupVersionKind(schema.GroupVersionKind{
		Group:   "karpenter.sh",
		Version: "v1",
		Kind:    "NodeClaim",
	})
	nodeClaim.SetName("deletable-node")
	nodeClaim.SetLabels(map[string]string{
		"karpenter.sh/nodepool": "spot-pool",
	})
	_ = unstructured.SetNestedField(nodeClaim.Object, "ip-10-0-2-100.ec2.internal", "status", "nodeName")
	_ = unstructured.SetNestedField(nodeClaim.Object, "c5.xlarge", "status", "instanceType")

	_, err := client.Resource(nodeClaimGVR).Create(context.Background(), nodeClaim, metav1.CreateOptions{})
	require.NoError(t, err)

	task := New(client)

	payload := Payload{Name: "deletable-node"}
	payloadJSON, err := json.Marshal(payload)
	require.NoError(t, err)

	result, err := task.Execute(context.Background(), payloadJSON)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.Success)
	assert.Contains(t, result.Message, "deletion initiated")

	// Verify NodeClaim was deleted
	_, err = client.Resource(nodeClaimGVR).Get(context.Background(), "deletable-node", metav1.GetOptions{})
	assert.True(t, apierrors.IsNotFound(err), "NodeClaim should be deleted")

	// Verify details
	details, ok := result.Details.(*DeleteDetails)
	require.True(t, ok)
	assert.Equal(t, "deletable-node", details.Name)
	assert.Equal(t, "ip-10-0-2-100.ec2.internal", details.NodeName)
	assert.Equal(t, "c5.xlarge", details.InstanceType)
	assert.Equal(t, "spot-pool", details.NodePool)
	assert.False(t, details.DryRun)
	assert.False(t, details.Force)
}
```

- [ ] **Step 5.6: Run all tests**

Run: `go test ./internal/task/nodeclaim_delete/... -v`
Expected: All tests PASS

- [ ] **Step 5.7: Commit**

```bash
git add internal/task/nodeclaim_delete/task_test.go
git commit -m "test(nodeclaim_delete): add comprehensive test coverage"
```

---

## Task 6: Register Task in main.go

**Files:**
- Modify: `cmd/pico-agent/main.go`

- [ ] **Step 6.1: Add import**

Add to imports in `cmd/pico-agent/main.go`:

```go
"github.com/loafoe/pico-agent/internal/task/nodeclaim_delete"
```

- [ ] **Step 6.2: Register task when feature enabled**

Add after the `pod_resize` registration block (around line 151):

```go
// Optional: nodeclaim_delete task (Karpenter node management)
if cfg.Features.NodeclaimDeleteEnabled {
	registry.Register(nodeclaim_delete.New(k8sClient.DynamicClient))
	slog.Info("nodeclaim_delete task enabled")
}
```

- [ ] **Step 6.3: Build to verify**

Run: `go build ./cmd/pico-agent/...`
Expected: Success

- [ ] **Step 6.4: Commit**

```bash
git add cmd/pico-agent/main.go
git commit -m "feat(main): register nodeclaim_delete task"
```

---

## Task 7: Update Helm Chart

**Files:**
- Modify: `/Users/andy/DEV/Personal/helm-charts/charts/pico-agent/values.yaml`
- Modify: `/Users/andy/DEV/Personal/helm-charts/charts/pico-agent/templates/clusterrole.yaml`
- Modify: `/Users/andy/DEV/Personal/helm-charts/charts/pico-agent/templates/deployment.yaml`
- Modify: `/Users/andy/DEV/Personal/helm-charts/charts/pico-agent/Chart.yaml`

- [ ] **Step 7.1: Add feature flag to values.yaml**

Add after `podResizeAbsoluteCap` (around line 92) in `/Users/andy/DEV/Personal/helm-charts/charts/pico-agent/values.yaml`:

```yaml
  # Enable nodeclaim_delete task for Karpenter node management
  # When enabled, grants get/delete on karpenter.sh nodeclaims
  nodeclaimDelete: false
```

- [ ] **Step 7.2: Add RBAC rule to clusterrole.yaml**

Add before `{{- with .Values.rbac.additionalRules }}` (around line 132) in `/Users/andy/DEV/Personal/helm-charts/charts/pico-agent/templates/clusterrole.yaml`:

```yaml
{{- if .Values.features.nodeclaimDelete }}
  # NodeClaim access for nodeclaim_delete task (Karpenter node management)
  - apiGroups: ["karpenter.sh"]
    resources: ["nodeclaims"]
    verbs: ["get", "delete"]
{{- end }}
```

- [ ] **Step 7.3: Add env var to deployment.yaml**

Add after the `POD_RESIZE_ABSOLUTE_CAP` block (around line 107) in `/Users/andy/DEV/Personal/helm-charts/charts/pico-agent/templates/deployment.yaml`:

```yaml
            {{- if .Values.features.nodeclaimDelete }}
            - name: NODECLAIM_DELETE_ENABLED
              value: "true"
            {{- end }}
```

- [ ] **Step 7.4: Bump chart version**

In `/Users/andy/DEV/Personal/helm-charts/charts/pico-agent/Chart.yaml`, change:

```yaml
version: 0.22.0
```

- [ ] **Step 7.5: Test helm template**

Run: `helm template test /Users/andy/DEV/Personal/helm-charts/charts/pico-agent --set features.nodeclaimDelete=true | grep -A5 "nodeclaim"`
Expected: Should show RBAC rule and env var for nodeclaim_delete

- [ ] **Step 7.6: Commit Helm chart changes**

```bash
cd /Users/andy/DEV/Personal/helm-charts
git add charts/pico-agent/
git commit -m "feat(pico-agent): add nodeclaimDelete feature flag

- Add features.nodeclaimDelete to values.yaml
- Add RBAC rule for karpenter.sh nodeclaims
- Add NODECLAIM_DELETE_ENABLED env var
- Bump chart version to 0.22.0"
```

---

## Task 8: Update Documentation

**Files:**
- Modify: `/Users/andy/DEV/Go/pico-agent/CLAUDE.md`

- [ ] **Step 8.1: Add nodeclaim_delete to Current Tasks section**

Add after the `pv_resize` documentation in CLAUDE.md:

```markdown
### Implemented: `nodeclaim_delete`

Deletes Karpenter NodeClaims for safe node recycling.

**Request**:
```json
{
  "type": "nodeclaim_delete",
  "payload": {
    "name": "default-abc123",
    "dry_run": false,
    "force": false
  }
}
```

**Response**:
```json
{
  "success": true,
  "message": "NodeClaim default-abc123 deletion initiated",
  "details": {
    "name": "default-abc123",
    "node_name": "ip-10-0-1-42.ec2.internal",
    "instance_type": "m5.large",
    "nodepool": "default",
    "dry_run": false,
    "force": false
  }
}
```

**Safety**: Blocks deletion if `karpenter.sh/do-not-disrupt=true` annotation present (use `force=true` to override).
```

- [ ] **Step 8.2: Add configuration env var**

Add to the Configuration environment variables section:

```markdown
- `NODECLAIM_DELETE_ENABLED` (default: false) - Enable nodeclaim_delete task
```

- [ ] **Step 8.3: Update Helm example**

Add to the Helm chart section an example:

```markdown
For NodeClaim deletion (Karpenter node management):
```bash
helm install pico-agent oci://ghcr.io/loafoe/helm-charts/pico-agent \
  --set features.nodeclaimDelete=true
```
```

- [ ] **Step 8.4: Commit documentation**

```bash
cd /Users/andy/DEV/Go/pico-agent
git add CLAUDE.md
git commit -m "docs: add nodeclaim_delete task documentation"
```

---

## Task 9: Final Verification

- [ ] **Step 9.1: Run all tests**

Run: `go test ./... -v`
Expected: All tests PASS

- [ ] **Step 9.2: Run linter**

Run: `golangci-lint run ./...`
Expected: No errors

- [ ] **Step 9.3: Build binary**

Run: `go build -o /dev/null ./cmd/pico-agent`
Expected: Success

- [ ] **Step 9.4: Verify Helm chart**

Run: `helm lint /Users/andy/DEV/Personal/helm-charts/charts/pico-agent`
Expected: No errors

---

## Summary

After completing all tasks:

1. **pico-agent repo** will have:
   - New `nodeclaim_delete` task with full test coverage
   - Feature flag in config
   - Task registration in main.go
   - Updated documentation

2. **helm-charts repo** will have:
   - `features.nodeclaimDelete` value
   - RBAC rules for `karpenter.sh/nodeclaims`
   - Environment variable injection
   - Chart version bump to 0.22.0
