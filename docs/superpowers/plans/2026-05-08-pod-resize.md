# Pod Resize Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement in-place pod memory resize for OOMKill remediation using Kubernetes KEP-1287.

**Architecture:** New `pod_resize` task with safety rails (percentage cap, absolute cap, QoS preservation, node capacity pre-flight). Opt-in via feature flag. Capability advertised in cluster_info.

**Tech Stack:** Go, client-go, Kubernetes 1.27+ patch API

---

## File Structure

```
centcom-satellite/
├── internal/
│   ├── config/config.go              # Add PodResizeEnabled + PodResizeConfig
│   └── task/pod_resize/
│       └── task.go                   # Task implementation (all logic in one file)
├── cmd/centcom-satellite/main.go            # Register task conditionally
└── internal/task/cluster_info/task.go # Add PodResize capability

helm-charts/charts/centcom-satellite/
├── values.yaml                       # Add podResize config
├── templates/deployment.yaml         # Add env vars
└── templates/clusterrole.yaml        # Add conditional RBAC

pico-mcp/
└── internal/mcp/ui/index.html        # Add resize badge
```

---

### Task 1: Add PodResize Config

**Files:**
- Modify: `internal/config/config.go`

- [ ] **Step 1: Add PodResizeConfig struct and fields to FeaturesConfig**

```go
// Add after PodEvictEnabled in FeaturesConfig struct (around line 60):

	// PodResizeEnabled enables the pod_resize task for in-place memory resize.
	// Disabled by default as it requires write permissions and K8s 1.27+.
	PodResizeEnabled bool

	// PodResizeConfig holds configuration for the pod_resize task.
	PodResizeConfig PodResizeConfig
```

```go
// Add new struct after FeaturesConfig (around line 62):

// PodResizeConfig holds pod_resize task configuration.
type PodResizeConfig struct {
	// PercentageCap is the maximum percentage increase allowed (default 50).
	PercentageCap int
	// AbsoluteCap is the maximum memory value allowed (default "4Gi").
	AbsoluteCap string
}
```

- [ ] **Step 2: Load PodResize config in Load function**

```go
// Add after PodEvictEnabled in the Features block (around line 89):
			PodResizeEnabled: getEnvBool("POD_RESIZE_ENABLED", false),
			PodResizeConfig: PodResizeConfig{
				PercentageCap: getEnvInt("POD_RESIZE_PERCENTAGE_CAP", 50),
				AbsoluteCap:   getEnvString("POD_RESIZE_ABSOLUTE_CAP", "4Gi"),
			},
```

- [ ] **Step 3: Run tests**

Run: `cd /Users/andy/DEV/Go/centcom-satellite && go build ./...`
Expected: Build succeeds

- [ ] **Step 4: Commit**

```bash
git add internal/config/config.go
git commit -m "feat(config): add pod_resize feature flag and config"
```

---

### Task 2: Create pod_resize Task

**Files:**
- Create: `internal/task/pod_resize/task.go`

- [ ] **Step 1: Create task file with types**

```go
package pod_resize

import (
	"context"
	"encoding/json"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"

	"github.com/loafoe/centcom-satellite/internal/config"
	"github.com/loafoe/centcom-satellite/internal/task"
)

const TaskName = "pod_resize"

type Payload struct {
	Namespace string `json:"namespace"`
	Pod       string `json:"pod"`
	Container string `json:"container,omitempty"`
	Resources struct {
		Memory string `json:"memory,omitempty"`
	} `json:"resources"`
	DryRun bool `json:"dry_run,omitempty"`
}

type Result struct {
	Success        bool   `json:"success"`
	Pod            string `json:"pod"`
	Container      string `json:"container"`
	PreviousMemory string `json:"previous_memory"`
	NewMemory      string `json:"new_memory"`
	NodeCapacity   struct {
		Allocatable string `json:"allocatable"`
		Available   string `json:"available"`
	} `json:"node_capacity"`
	Warning string `json:"warning,omitempty"`
	DryRun  bool   `json:"dry_run"`
}

type Task struct {
	clientset kubernetes.Interface
	config    config.PodResizeConfig
}

func New(clientset kubernetes.Interface, cfg config.PodResizeConfig) *Task {
	return &Task{
		clientset: clientset,
		config:    cfg,
	}
}

func (t *Task) Name() string {
	return TaskName
}
```

- [ ] **Step 2: Add Execute method with validation**

```go
func (t *Task) Execute(ctx context.Context, rawPayload json.RawMessage) (*task.Result, error) {
	var payload Payload
	if len(rawPayload) > 0 && string(rawPayload) != "{}" {
		if err := json.Unmarshal(rawPayload, &payload); err != nil {
			return task.NewErrorResult(fmt.Sprintf("invalid payload: %v", err)), nil
		}
	}

	if err := t.validatePayload(&payload); err != nil {
		return task.NewErrorResult(err.Error()), nil
	}

	// Get the pod
	pod, err := t.clientset.CoreV1().Pods(payload.Namespace).Get(ctx, payload.Pod, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to get pod: %w", err)
	}

	// Find container
	containerIdx, container := t.findContainer(pod, payload.Container)
	if container == nil {
		return task.NewErrorResult(fmt.Sprintf("container %q not found in pod", payload.Container)), nil
	}

	// Parse requested memory
	requestedMemory, err := resource.ParseQuantity(payload.Resources.Memory)
	if err != nil {
		return task.NewErrorResult(fmt.Sprintf("invalid memory value: %v", err)), nil
	}

	// Get current memory
	currentMemory := container.Resources.Requests.Memory()
	if currentMemory == nil || currentMemory.IsZero() {
		return task.NewErrorResult("container has no memory request set"), nil
	}

	// Validate safety rails
	if err := t.validateSafetyRails(pod, container, currentMemory, &requestedMemory); err != nil {
		return task.NewErrorResult(err.Error()), nil
	}

	// Check node capacity
	nodeCapacity, err := t.checkNodeCapacity(ctx, pod, currentMemory, &requestedMemory)
	if err != nil {
		return task.NewErrorResult(err.Error()), nil
	}

	// Build result
	result := Result{
		Success:        true,
		Pod:            payload.Pod,
		Container:      container.Name,
		PreviousMemory: currentMemory.String(),
		NewMemory:      requestedMemory.String(),
		NodeCapacity:   nodeCapacity,
		Warning:        "resize is ephemeral until pod restart",
		DryRun:         payload.DryRun,
	}

	if payload.DryRun {
		return task.NewSuccessResultWithDetails(
			fmt.Sprintf("Dry-run: would resize %s/%s container %s from %s to %s",
				payload.Namespace, payload.Pod, container.Name, currentMemory.String(), requestedMemory.String()),
			result,
		), nil
	}

	// Perform the resize
	if err := t.resizePod(ctx, payload.Namespace, payload.Pod, containerIdx, &requestedMemory); err != nil {
		return nil, fmt.Errorf("failed to resize pod: %w", err)
	}

	return task.NewSuccessResultWithDetails(
		fmt.Sprintf("Resized %s/%s container %s from %s to %s (ephemeral until pod restart)",
			payload.Namespace, payload.Pod, container.Name, currentMemory.String(), requestedMemory.String()),
		result,
	), nil
}

func (t *Task) validatePayload(payload *Payload) error {
	if payload.Namespace == "" {
		return fmt.Errorf("namespace is required")
	}
	if payload.Pod == "" {
		return fmt.Errorf("pod is required")
	}
	if payload.Resources.Memory == "" {
		return fmt.Errorf("resources.memory is required")
	}
	return nil
}

func (t *Task) findContainer(pod *corev1.Pod, name string) (int, *corev1.Container) {
	for i := range pod.Spec.Containers {
		c := &pod.Spec.Containers[i]
		if name == "" || c.Name == name {
			return i, c
		}
	}
	return -1, nil
}
```

- [ ] **Step 3: Add safety rail validation**

```go
func (t *Task) validateSafetyRails(pod *corev1.Pod, container *corev1.Container, current, requested *resource.Quantity) error {
	// Check percentage cap
	maxAllowed := current.DeepCopy()
	maxAllowed.Add(*resource.NewQuantity(current.Value()*int64(t.config.PercentageCap)/100, resource.BinarySI))
	if requested.Cmp(maxAllowed) > 0 {
		return fmt.Errorf("exceeds percentage cap (%d%%): max %s, requested %s",
			t.config.PercentageCap, maxAllowed.String(), requested.String())
	}

	// Check absolute cap
	absoluteCap, err := resource.ParseQuantity(t.config.AbsoluteCap)
	if err != nil {
		return fmt.Errorf("invalid absolute cap config: %v", err)
	}
	if requested.Cmp(absoluteCap) > 0 {
		return fmt.Errorf("exceeds absolute cap: max %s, requested %s",
			absoluteCap.String(), requested.String())
	}

	// Check QoS preservation
	if t.isGuaranteed(pod) {
		memLimit := container.Resources.Limits.Memory()
		if memLimit != nil && !memLimit.IsZero() && requested.Cmp(*memLimit) != 0 {
			return fmt.Errorf("resize would change QoS class from Guaranteed to Burstable (request %s != limit %s)",
				requested.String(), memLimit.String())
		}
	}

	return nil
}

func (t *Task) isGuaranteed(pod *corev1.Pod) bool {
	for _, c := range pod.Spec.Containers {
		cpuReq := c.Resources.Requests.Cpu()
		cpuLim := c.Resources.Limits.Cpu()
		memReq := c.Resources.Requests.Memory()
		memLim := c.Resources.Limits.Memory()

		if cpuReq == nil || cpuLim == nil || cpuReq.Cmp(*cpuLim) != 0 {
			return false
		}
		if memReq == nil || memLim == nil || memReq.Cmp(*memLim) != 0 {
			return false
		}
	}
	return true
}
```

- [ ] **Step 4: Add node capacity check**

```go
func (t *Task) checkNodeCapacity(ctx context.Context, pod *corev1.Pod, current, requested *resource.Quantity) (struct {
	Allocatable string `json:"allocatable"`
	Available   string `json:"available"`
}, error) {
	var result struct {
		Allocatable string `json:"allocatable"`
		Available   string `json:"available"`
	}

	if pod.Spec.NodeName == "" {
		return result, fmt.Errorf("pod is not scheduled to a node")
	}

	node, err := t.clientset.CoreV1().Nodes().Get(ctx, pod.Spec.NodeName, metav1.GetOptions{})
	if err != nil {
		return result, fmt.Errorf("failed to get node: %w", err)
	}

	allocatable := node.Status.Allocatable.Memory()
	if allocatable == nil {
		return result, fmt.Errorf("node has no allocatable memory")
	}

	// Sum memory requests of all pods on this node
	pods, err := t.clientset.CoreV1().Pods(metav1.NamespaceAll).List(ctx, metav1.ListOptions{
		FieldSelector: fmt.Sprintf("spec.nodeName=%s", pod.Spec.NodeName),
	})
	if err != nil {
		return result, fmt.Errorf("failed to list pods on node: %w", err)
	}

	var totalRequests int64
	for _, p := range pods.Items {
		if p.Status.Phase == corev1.PodSucceeded || p.Status.Phase == corev1.PodFailed {
			continue
		}
		for _, c := range p.Spec.Containers {
			if mem := c.Resources.Requests.Memory(); mem != nil {
				totalRequests += mem.Value()
			}
		}
	}

	delta := requested.Value() - current.Value()
	available := allocatable.Value() - totalRequests

	result.Allocatable = allocatable.String()
	result.Available = resource.NewQuantity(available, resource.BinarySI).String()

	if delta > available {
		return result, fmt.Errorf("node %s has insufficient capacity: %s available, %s needed",
			node.Name, result.Available, resource.NewQuantity(delta, resource.BinarySI).String())
	}

	return result, nil
}
```

- [ ] **Step 5: Add resize implementation**

```go
func (t *Task) resizePod(ctx context.Context, namespace, podName string, containerIdx int, memory *resource.Quantity) error {
	patch := fmt.Sprintf(`[{"op": "replace", "path": "/spec/containers/%d/resources/requests/memory", "value": "%s"}]`,
		containerIdx, memory.String())

	_, err := t.clientset.CoreV1().Pods(namespace).Patch(ctx, podName, types.JSONPatchType, []byte(patch), metav1.PatchOptions{})
	return err
}
```

- [ ] **Step 6: Run build**

Run: `cd /Users/andy/DEV/Go/centcom-satellite && go build ./...`
Expected: Build succeeds

- [ ] **Step 7: Commit**

```bash
git add internal/task/pod_resize/task.go
git commit -m "feat(task): add pod_resize task for in-place memory resize"
```

---

### Task 3: Register Task and Update Capabilities

**Files:**
- Modify: `cmd/centcom-satellite/main.go`
- Modify: `internal/task/cluster_info/task.go`

- [ ] **Step 1: Add import in main.go**

```go
// Add to imports (around line 40):
	"github.com/loafoe/centcom-satellite/internal/task/pod_resize"
```

- [ ] **Step 2: Add PodResize to Capabilities struct in cluster_info/task.go**

```go
// Add to Capabilities struct (around line 35):
	PodResize       bool `json:"pod_resize"`
```

- [ ] **Step 3: Update cluster_info registration in main.go to include PodResize**

```go
// Update the WithCapabilities call (around line 93-98):
	registry.Register(cluster_info.New(k8sClient.Clientset).WithCapabilities(cluster_info.Capabilities{
		WorkloadRestart: cfg.Features.WorkloadRestartEnabled,
		WorkloadScale:   cfg.Features.WorkloadScaleEnabled,
		PodEvict:        cfg.Features.PodEvictEnabled,
		PodResize:       cfg.Features.PodResizeEnabled,
		GetResource:     cfg.Features.GetResourceEnabled,
	}))
```

- [ ] **Step 4: Add conditional task registration in main.go**

```go
// Add after pod_evict registration (around line 140):
	// Optional: pod_resize task (write operation, requires K8s 1.27+)
	if cfg.Features.PodResizeEnabled {
		registry.Register(pod_resize.New(k8sClient.Clientset, cfg.Features.PodResizeConfig))
		slog.Info("pod_resize task enabled")
	}
```

- [ ] **Step 5: Run build**

Run: `cd /Users/andy/DEV/Go/centcom-satellite && go build ./...`
Expected: Build succeeds

- [ ] **Step 6: Commit**

```bash
git add cmd/centcom-satellite/main.go internal/task/cluster_info/task.go
git commit -m "feat: register pod_resize task and advertise capability"
```

---

### Task 4: Update Helm Chart

**Files:**
- Modify: `/Users/andy/DEV/Personal/helm-charts/charts/centcom-satellite/values.yaml`
- Modify: `/Users/andy/DEV/Personal/helm-charts/charts/centcom-satellite/templates/deployment.yaml`
- Modify: `/Users/andy/DEV/Personal/helm-charts/charts/centcom-satellite/templates/clusterrole.yaml`

- [ ] **Step 1: Add podResize to values.yaml**

```yaml
# Add after podEvict in features section (around line 95):
  # Enable pod_resize task for in-place pod memory resize (KEP-1287)
  # Requires Kubernetes 1.27+ with InPlacePodVerticalScaling feature gate
  podResize: false
  # Pod resize safety limits
  podResizePercentageCap: 50
  podResizeAbsoluteCap: "4Gi"
```

- [ ] **Step 2: Add env vars to deployment.yaml**

```yaml
# Add after POD_EVICT_ENABLED block (around line 106):
            {{- if .Values.features.podResize }}
            - name: POD_RESIZE_ENABLED
              value: "true"
            - name: POD_RESIZE_PERCENTAGE_CAP
              value: {{ .Values.features.podResizePercentageCap | quote }}
            - name: POD_RESIZE_ABSOLUTE_CAP
              value: {{ .Values.features.podResizeAbsoluteCap | quote }}
            {{- end }}
```

- [ ] **Step 3: Add RBAC rules to clusterrole.yaml**

```yaml
# Add after podEvict block (around line 121):
{{- if .Values.features.podResize }}
  # Pod patch for pod_resize task (in-place memory resize)
  - apiGroups: [""]
    resources: ["pods"]
    verbs: ["patch"]
  # Node read for capacity check
  - apiGroups: [""]
    resources: ["nodes"]
    verbs: ["get", "list"]
{{- end }}
```

- [ ] **Step 4: Commit**

```bash
cd /Users/andy/DEV/Personal/helm-charts
git add charts/centcom-satellite/values.yaml charts/centcom-satellite/templates/deployment.yaml charts/centcom-satellite/templates/clusterrole.yaml
git commit -m "feat(centcom-satellite): add pod_resize feature flag and RBAC"
```

---

### Task 5: Update pico-mcp UI

**Files:**
- Modify: `/Users/andy/DEV/Go/pico-mcp/internal/mcp/ui/index.html`

- [ ] **Step 1: Add resize badge to agents table (around line 1906)**

```javascript
// Add after pod_evict badge line:
                    if (caps.pod_resize) capBadges += '<span class="badge" style="background: var(--badge-err-bg); color: var(--badge-err-text); font-size: 0.65rem; margin-right: 2px;" title="Can resize pod memory">resize</span>';
```

- [ ] **Step 2: Update hasWriteOps check (around line 2252)**

```javascript
// Change to:
                const hasWriteOps = caps.workload_restart || caps.workload_scale || caps.pod_evict || caps.pod_resize;
```

- [ ] **Step 3: Add resize capability badge to overview pane (around line 2264)**

```javascript
// Add after pod_evict badge:
                if (caps.pod_resize) {
                    html += `<span class="badge" style="background: var(--badge-err-bg); color: var(--badge-err-text);" title="Can resize pod memory in-place">Resize Pods</span>`;
                }
```

- [ ] **Step 4: Commit**

```bash
cd /Users/andy/DEV/Go/pico-mcp
git add internal/mcp/ui/index.html
git commit -m "feat(ui): add pod_resize capability badge"
```

---

### Task 6: Test End-to-End

- [ ] **Step 1: Build centcom-satellite**

Run: `cd /Users/andy/DEV/Go/centcom-satellite && go build ./cmd/centcom-satellite`
Expected: Build succeeds

- [ ] **Step 2: Build pico-mcp**

Run: `cd /Users/andy/DEV/Go/pico-mcp && go build ./cmd/pico-mcp`
Expected: Build succeeds

- [ ] **Step 3: Verify helm template renders correctly**

Run: `cd /Users/andy/DEV/Personal/helm-charts && helm template charts/centcom-satellite --set features.podResize=true | grep -A5 POD_RESIZE`
Expected: Shows POD_RESIZE_ENABLED, POD_RESIZE_PERCENTAGE_CAP, POD_RESIZE_ABSOLUTE_CAP env vars

- [ ] **Step 4: Verify RBAC rules render**

Run: `cd /Users/andy/DEV/Personal/helm-charts && helm template charts/centcom-satellite --set features.podResize=true | grep -A4 "pod_resize"`
Expected: Shows pods patch and nodes get/list rules
