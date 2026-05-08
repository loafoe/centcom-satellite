# Write Operations Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add three opt-in write operations to pico-agent: workload_restart, workload_scale, and pod_evict.

**Architecture:** Each operation is a separate task package with feature flag control. Helm chart provides conditional RBAC. pico-mcp exposes MCP tools and enriches "task not found" errors.

**Tech Stack:** Go, Kubernetes client-go, Helm templates

---

## File Structure

**pico-agent (new files):**
- `internal/task/workload_restart/task.go` - restart implementation
- `internal/task/workload_restart/task_test.go` - restart tests
- `internal/task/workload_scale/task.go` - scale implementation  
- `internal/task/workload_scale/task_test.go` - scale tests
- `internal/task/pod_evict/task.go` - evict implementation
- `internal/task/pod_evict/task_test.go` - evict tests

**pico-agent (modify):**
- `internal/config/config.go` - add feature flags
- `cmd/pico-agent/main.go` - conditional registration

**helm chart (modify):**
- `charts/pico-agent/values.yaml` - add feature flags
- `charts/pico-agent/templates/deployment.yaml` - add env vars
- `charts/pico-agent/templates/clusterrole.yaml` - add RBAC rules

**pico-mcp (modify):**
- `internal/mcp/server.go` - add tools and error enrichment

---

## Task 1: Add Feature Flags to Config

**Files:**
- Modify: `/Users/andy/DEV/Go/pico-agent/internal/config/config.go`

- [ ] **Step 1: Add feature flags to FeaturesConfig struct**

In `config.go`, update `FeaturesConfig`:

```go
// FeaturesConfig holds feature flags.
type FeaturesConfig struct {
	// GetResourceEnabled enables the get_resource task for fetching arbitrary resources.
	GetResourceEnabled bool
	// WorkloadRestartEnabled enables the workload_restart task.
	WorkloadRestartEnabled bool
	// WorkloadScaleEnabled enables the workload_scale task.
	WorkloadScaleEnabled bool
	// PodEvictEnabled enables the pod_evict task.
	PodEvictEnabled bool
}
```

- [ ] **Step 2: Load new flags in Load function**

In the `Load()` function, update the Features initialization:

```go
Features: FeaturesConfig{
	GetResourceEnabled:     getEnvBool("GET_RESOURCE_ENABLED", false),
	WorkloadRestartEnabled: getEnvBool("WORKLOAD_RESTART_ENABLED", false),
	WorkloadScaleEnabled:   getEnvBool("WORKLOAD_SCALE_ENABLED", false),
	PodEvictEnabled:        getEnvBool("POD_EVICT_ENABLED", false),
},
```

- [ ] **Step 3: Verify build**

Run: `cd /Users/andy/DEV/Go/pico-agent && go build ./...`
Expected: Build succeeds

- [ ] **Step 4: Commit**

```bash
git add internal/config/config.go
git commit -m "feat(config): add feature flags for write operations"
```

---

## Task 2: Create workload_restart Task

**Files:**
- Create: `/Users/andy/DEV/Go/pico-agent/internal/task/workload_restart/task.go`

- [ ] **Step 1: Create task package with types**

```go
// Package workload_restart provides workload restart functionality.
package workload_restart

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	policyv1 "k8s.io/api/policy/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"

	"github.com/loafoe/pico-agent/internal/task"
)

const (
	TaskName          = "workload_restart"
	NoRestartAnnotation = "picoclaw.io/no-restart"
)

// Payload for workload_restart task.
type Payload struct {
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
	Kind      string `json:"kind"`
	DryRun    bool   `json:"dry_run"`
}

// RestartDetails contains restart operation details.
type RestartDetails struct {
	DryRun          bool   `json:"dry_run,omitempty"`
	PreviousRestart string `json:"previous_restart,omitempty"`
	Replicas        int32  `json:"replicas"`
	Message         string `json:"message,omitempty"`
}

// Task handles workload restart operations.
type Task struct {
	clientset kubernetes.Interface
}

// New creates a new workload restart task.
func New(clientset kubernetes.Interface) *Task {
	return &Task{clientset: clientset}
}

// Name returns the task type identifier.
func (t *Task) Name() string {
	return TaskName
}
```

- [ ] **Step 2: Add Execute method**

```go
// Execute performs the workload restart.
func (t *Task) Execute(ctx context.Context, rawPayload json.RawMessage) (*task.Result, error) {
	var payload Payload
	if err := json.Unmarshal(rawPayload, &payload); err != nil {
		return task.NewErrorResult(fmt.Sprintf("invalid payload: %v", err)), nil
	}

	if err := t.validatePayload(&payload); err != nil {
		return task.NewErrorResult(err.Error()), nil
	}

	payload.Kind = strings.ToLower(payload.Kind)

	// Check namespace annotation
	ns, err := t.clientset.CoreV1().Namespaces().Get(ctx, payload.Namespace, metav1.GetOptions{})
	if err != nil {
		return task.NewErrorResult(fmt.Sprintf("failed to get namespace: %v", err)), nil
	}
	if ns.Annotations[NoRestartAnnotation] == "true" {
		return task.NewErrorResult(fmt.Sprintf("namespace %s has %s annotation", payload.Namespace, NoRestartAnnotation)), nil
	}

	switch payload.Kind {
	case "deployment":
		return t.restartDeployment(ctx, &payload)
	case "statefulset":
		return t.restartStatefulSet(ctx, &payload)
	case "daemonset":
		return t.restartDaemonSet(ctx, &payload)
	default:
		return task.NewErrorResult(fmt.Sprintf("unsupported kind: %s", payload.Kind)), nil
	}
}

func (t *Task) validatePayload(p *Payload) error {
	if p.Namespace == "" {
		return fmt.Errorf("namespace is required")
	}
	if p.Name == "" {
		return fmt.Errorf("name is required")
	}
	if p.Kind == "" {
		return fmt.Errorf("kind is required")
	}
	kind := strings.ToLower(p.Kind)
	if kind != "deployment" && kind != "statefulset" && kind != "daemonset" {
		return fmt.Errorf("kind must be deployment, statefulset, or daemonset")
	}
	return nil
}
```

- [ ] **Step 3: Add restart methods for each workload type**

```go
func (t *Task) restartDeployment(ctx context.Context, payload *Payload) (*task.Result, error) {
	deploy, err := t.clientset.AppsV1().Deployments(payload.Namespace).Get(ctx, payload.Name, metav1.GetOptions{})
	if err != nil {
		return task.NewErrorResult(fmt.Sprintf("failed to get deployment: %v", err)), nil
	}

	if deploy.Annotations[NoRestartAnnotation] == "true" {
		return task.NewErrorResult(fmt.Sprintf("deployment has %s annotation", NoRestartAnnotation)), nil
	}

	if err := t.checkPDB(ctx, payload.Namespace, deploy.Spec.Selector); err != nil {
		return task.NewErrorResult(err.Error()), nil
	}

	var replicas int32 = 1
	if deploy.Spec.Replicas != nil {
		replicas = *deploy.Spec.Replicas
	}

	previousRestart := ""
	if deploy.Spec.Template.Annotations != nil {
		previousRestart = deploy.Spec.Template.Annotations["kubectl.kubernetes.io/restartedAt"]
	}

	if payload.DryRun {
		return task.NewSuccessResultWithDetails(
			fmt.Sprintf("[DRY-RUN] Would restart deployment %s/%s", payload.Namespace, payload.Name),
			RestartDetails{DryRun: true, PreviousRestart: previousRestart, Replicas: replicas},
		), nil
	}

	patch := fmt.Sprintf(`{"spec":{"template":{"metadata":{"annotations":{"kubectl.kubernetes.io/restartedAt":"%s"}}}}}`, time.Now().Format(time.RFC3339))
	_, err = t.clientset.AppsV1().Deployments(payload.Namespace).Patch(ctx, payload.Name, types.StrategicMergePatchType, []byte(patch), metav1.PatchOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to patch deployment: %w", err)
	}

	return task.NewSuccessResultWithDetails(
		fmt.Sprintf("Restarted deployment %s/%s", payload.Namespace, payload.Name),
		RestartDetails{PreviousRestart: previousRestart, Replicas: replicas},
	), nil
}

func (t *Task) restartStatefulSet(ctx context.Context, payload *Payload) (*task.Result, error) {
	sts, err := t.clientset.AppsV1().StatefulSets(payload.Namespace).Get(ctx, payload.Name, metav1.GetOptions{})
	if err != nil {
		return task.NewErrorResult(fmt.Sprintf("failed to get statefulset: %v", err)), nil
	}

	if sts.Annotations[NoRestartAnnotation] == "true" {
		return task.NewErrorResult(fmt.Sprintf("statefulset has %s annotation", NoRestartAnnotation)), nil
	}

	if err := t.checkPDB(ctx, payload.Namespace, sts.Spec.Selector); err != nil {
		return task.NewErrorResult(err.Error()), nil
	}

	var replicas int32 = 1
	if sts.Spec.Replicas != nil {
		replicas = *sts.Spec.Replicas
	}

	previousRestart := ""
	if sts.Spec.Template.Annotations != nil {
		previousRestart = sts.Spec.Template.Annotations["kubectl.kubernetes.io/restartedAt"]
	}

	if payload.DryRun {
		return task.NewSuccessResultWithDetails(
			fmt.Sprintf("[DRY-RUN] Would restart statefulset %s/%s", payload.Namespace, payload.Name),
			RestartDetails{DryRun: true, PreviousRestart: previousRestart, Replicas: replicas},
		), nil
	}

	patch := fmt.Sprintf(`{"spec":{"template":{"metadata":{"annotations":{"kubectl.kubernetes.io/restartedAt":"%s"}}}}}`, time.Now().Format(time.RFC3339))
	_, err = t.clientset.AppsV1().StatefulSets(payload.Namespace).Patch(ctx, payload.Name, types.StrategicMergePatchType, []byte(patch), metav1.PatchOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to patch statefulset: %w", err)
	}

	return task.NewSuccessResultWithDetails(
		fmt.Sprintf("Restarted statefulset %s/%s", payload.Namespace, payload.Name),
		RestartDetails{PreviousRestart: previousRestart, Replicas: replicas},
	), nil
}

func (t *Task) restartDaemonSet(ctx context.Context, payload *Payload) (*task.Result, error) {
	ds, err := t.clientset.AppsV1().DaemonSets(payload.Namespace).Get(ctx, payload.Name, metav1.GetOptions{})
	if err != nil {
		return task.NewErrorResult(fmt.Sprintf("failed to get daemonset: %v", err)), nil
	}

	if ds.Annotations[NoRestartAnnotation] == "true" {
		return task.NewErrorResult(fmt.Sprintf("daemonset has %s annotation", NoRestartAnnotation)), nil
	}

	previousRestart := ""
	if ds.Spec.Template.Annotations != nil {
		previousRestart = ds.Spec.Template.Annotations["kubectl.kubernetes.io/restartedAt"]
	}

	replicas := ds.Status.DesiredNumberScheduled

	if payload.DryRun {
		return task.NewSuccessResultWithDetails(
			fmt.Sprintf("[DRY-RUN] Would restart daemonset %s/%s", payload.Namespace, payload.Name),
			RestartDetails{DryRun: true, PreviousRestart: previousRestart, Replicas: replicas},
		), nil
	}

	patch := fmt.Sprintf(`{"spec":{"template":{"metadata":{"annotations":{"kubectl.kubernetes.io/restartedAt":"%s"}}}}}`, time.Now().Format(time.RFC3339))
	_, err = t.clientset.AppsV1().DaemonSets(payload.Namespace).Patch(ctx, payload.Name, types.StrategicMergePatchType, []byte(patch), metav1.PatchOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to patch daemonset: %w", err)
	}

	return task.NewSuccessResultWithDetails(
		fmt.Sprintf("Restarted daemonset %s/%s", payload.Namespace, payload.Name),
		RestartDetails{PreviousRestart: previousRestart, Replicas: replicas},
	), nil
}
```

- [ ] **Step 4: Add PDB check helper**

```go
func (t *Task) checkPDB(ctx context.Context, namespace string, selector *metav1.LabelSelector) error {
	if selector == nil {
		return nil
	}

	pdbs, err := t.clientset.PolicyV1().PodDisruptionBudgets(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil // PDB check is best-effort
	}

	for _, pdb := range pdbs.Items {
		if pdbMatchesSelector(&pdb, selector) {
			if pdb.Status.DisruptionsAllowed == 0 {
				return fmt.Errorf("PDB %s/%s has 0 disruptions allowed", namespace, pdb.Name)
			}
		}
	}
	return nil
}

func pdbMatchesSelector(pdb *policyv1.PodDisruptionBudget, workloadSelector *metav1.LabelSelector) bool {
	if pdb.Spec.Selector == nil || workloadSelector == nil {
		return false
	}
	for k, v := range pdb.Spec.Selector.MatchLabels {
		if workloadSelector.MatchLabels[k] == v {
			return true
		}
	}
	return false
}
```

- [ ] **Step 5: Verify build**

Run: `cd /Users/andy/DEV/Go/pico-agent && go build ./...`
Expected: Build succeeds

- [ ] **Step 6: Commit**

```bash
git add internal/task/workload_restart/
git commit -m "feat(workload_restart): add workload restart task"
```

---

## Task 3: Create workload_scale Task

**Files:**
- Create: `/Users/andy/DEV/Go/pico-agent/internal/task/workload_scale/task.go`

- [ ] **Step 1: Create task package with types**

```go
// Package workload_scale provides workload scaling functionality.
package workload_scale

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	autoscalingv1 "k8s.io/api/autoscaling/v1"
	autoscalingv2 "k8s.io/api/autoscaling/v2"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/loafoe/pico-agent/internal/task"
)

const (
	TaskName         = "workload_scale"
	NoScaleAnnotation = "picoclaw.io/no-scale"
)

// Payload for workload_scale task.
type Payload struct {
	Namespace        string `json:"namespace"`
	Name             string `json:"name"`
	Kind             string `json:"kind"`
	Replicas         int32  `json:"replicas"`
	AllowScaleToZero bool   `json:"allow_scale_to_zero"`
	DryRun           bool   `json:"dry_run"`
}

// ScaleDetails contains scale operation details.
type ScaleDetails struct {
	DryRun           bool   `json:"dry_run,omitempty"`
	PreviousReplicas int32  `json:"previous_replicas"`
	NewReplicas      int32  `json:"new_replicas"`
	HPAWarning       string `json:"hpa_warning,omitempty"`
}

// Task handles workload scale operations.
type Task struct {
	clientset kubernetes.Interface
}

// New creates a new workload scale task.
func New(clientset kubernetes.Interface) *Task {
	return &Task{clientset: clientset}
}

// Name returns the task type identifier.
func (t *Task) Name() string {
	return TaskName
}
```

- [ ] **Step 2: Add Execute method**

```go
// Execute performs the workload scale.
func (t *Task) Execute(ctx context.Context, rawPayload json.RawMessage) (*task.Result, error) {
	var payload Payload
	if err := json.Unmarshal(rawPayload, &payload); err != nil {
		return task.NewErrorResult(fmt.Sprintf("invalid payload: %v", err)), nil
	}

	if err := t.validatePayload(&payload); err != nil {
		return task.NewErrorResult(err.Error()), nil
	}

	payload.Kind = strings.ToLower(payload.Kind)

	// Check namespace annotation
	ns, err := t.clientset.CoreV1().Namespaces().Get(ctx, payload.Namespace, metav1.GetOptions{})
	if err != nil {
		return task.NewErrorResult(fmt.Sprintf("failed to get namespace: %v", err)), nil
	}
	if ns.Annotations[NoScaleAnnotation] == "true" {
		return task.NewErrorResult(fmt.Sprintf("namespace %s has %s annotation", payload.Namespace, NoScaleAnnotation)), nil
	}

	switch payload.Kind {
	case "deployment":
		return t.scaleDeployment(ctx, &payload)
	case "statefulset":
		return t.scaleStatefulSet(ctx, &payload)
	default:
		return task.NewErrorResult(fmt.Sprintf("unsupported kind: %s (must be deployment or statefulset)", payload.Kind)), nil
	}
}

func (t *Task) validatePayload(p *Payload) error {
	if p.Namespace == "" {
		return fmt.Errorf("namespace is required")
	}
	if p.Name == "" {
		return fmt.Errorf("name is required")
	}
	if p.Kind == "" {
		return fmt.Errorf("kind is required")
	}
	kind := strings.ToLower(p.Kind)
	if kind != "deployment" && kind != "statefulset" {
		return fmt.Errorf("kind must be deployment or statefulset")
	}
	if p.Replicas < 0 {
		return fmt.Errorf("replicas cannot be negative")
	}
	if p.Replicas == 0 && !p.AllowScaleToZero {
		return fmt.Errorf("scaling to 0 requires allow_scale_to_zero: true")
	}
	return nil
}
```

- [ ] **Step 3: Add scale methods**

```go
func (t *Task) scaleDeployment(ctx context.Context, payload *Payload) (*task.Result, error) {
	deploy, err := t.clientset.AppsV1().Deployments(payload.Namespace).Get(ctx, payload.Name, metav1.GetOptions{})
	if err != nil {
		return task.NewErrorResult(fmt.Sprintf("failed to get deployment: %v", err)), nil
	}

	if deploy.Annotations[NoScaleAnnotation] == "true" {
		return task.NewErrorResult(fmt.Sprintf("deployment has %s annotation", NoScaleAnnotation)), nil
	}

	var currentReplicas int32 = 1
	if deploy.Spec.Replicas != nil {
		currentReplicas = *deploy.Spec.Replicas
	}

	// Check 3x scale limit
	if payload.Replicas > currentReplicas*3 && currentReplicas > 0 {
		return task.NewErrorResult(fmt.Sprintf("scale-up from %d to %d exceeds 3x limit; scale incrementally", currentReplicas, payload.Replicas)), nil
	}

	// Check for HPA
	hpaWarning := t.checkHPA(ctx, payload.Namespace, "Deployment", payload.Name)

	if payload.DryRun {
		return task.NewSuccessResultWithDetails(
			fmt.Sprintf("[DRY-RUN] Would scale deployment %s/%s from %d to %d replicas", payload.Namespace, payload.Name, currentReplicas, payload.Replicas),
			ScaleDetails{DryRun: true, PreviousReplicas: currentReplicas, NewReplicas: payload.Replicas, HPAWarning: hpaWarning},
		), nil
	}

	scale := &autoscalingv1.Scale{
		ObjectMeta: metav1.ObjectMeta{Name: payload.Name, Namespace: payload.Namespace},
		Spec:       autoscalingv1.ScaleSpec{Replicas: payload.Replicas},
	}
	_, err = t.clientset.AppsV1().Deployments(payload.Namespace).UpdateScale(ctx, payload.Name, scale, metav1.UpdateOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to scale deployment: %w", err)
	}

	return task.NewSuccessResultWithDetails(
		fmt.Sprintf("Scaled deployment %s/%s from %d to %d replicas", payload.Namespace, payload.Name, currentReplicas, payload.Replicas),
		ScaleDetails{PreviousReplicas: currentReplicas, NewReplicas: payload.Replicas, HPAWarning: hpaWarning},
	), nil
}

func (t *Task) scaleStatefulSet(ctx context.Context, payload *Payload) (*task.Result, error) {
	sts, err := t.clientset.AppsV1().StatefulSets(payload.Namespace).Get(ctx, payload.Name, metav1.GetOptions{})
	if err != nil {
		return task.NewErrorResult(fmt.Sprintf("failed to get statefulset: %v", err)), nil
	}

	if sts.Annotations[NoScaleAnnotation] == "true" {
		return task.NewErrorResult(fmt.Sprintf("statefulset has %s annotation", NoScaleAnnotation)), nil
	}

	var currentReplicas int32 = 1
	if sts.Spec.Replicas != nil {
		currentReplicas = *sts.Spec.Replicas
	}

	// Check 3x scale limit
	if payload.Replicas > currentReplicas*3 && currentReplicas > 0 {
		return task.NewErrorResult(fmt.Sprintf("scale-up from %d to %d exceeds 3x limit; scale incrementally", currentReplicas, payload.Replicas)), nil
	}

	// Check for HPA
	hpaWarning := t.checkHPA(ctx, payload.Namespace, "StatefulSet", payload.Name)

	if payload.DryRun {
		return task.NewSuccessResultWithDetails(
			fmt.Sprintf("[DRY-RUN] Would scale statefulset %s/%s from %d to %d replicas", payload.Namespace, payload.Name, currentReplicas, payload.Replicas),
			ScaleDetails{DryRun: true, PreviousReplicas: currentReplicas, NewReplicas: payload.Replicas, HPAWarning: hpaWarning},
		), nil
	}

	scale := &autoscalingv1.Scale{
		ObjectMeta: metav1.ObjectMeta{Name: payload.Name, Namespace: payload.Namespace},
		Spec:       autoscalingv1.ScaleSpec{Replicas: payload.Replicas},
	}
	_, err = t.clientset.AppsV1().StatefulSets(payload.Namespace).UpdateScale(ctx, payload.Name, scale, metav1.UpdateOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to scale statefulset: %w", err)
	}

	return task.NewSuccessResultWithDetails(
		fmt.Sprintf("Scaled statefulset %s/%s from %d to %d replicas", payload.Namespace, payload.Name, currentReplicas, payload.Replicas),
		ScaleDetails{PreviousReplicas: currentReplicas, NewReplicas: payload.Replicas, HPAWarning: hpaWarning},
	), nil
}

func (t *Task) checkHPA(ctx context.Context, namespace, targetKind, targetName string) string {
	hpas, err := t.clientset.AutoscalingV2().HorizontalPodAutoscalers(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return ""
	}

	for _, hpa := range hpas.Items {
		if hpa.Spec.ScaleTargetRef.Kind == targetKind && hpa.Spec.ScaleTargetRef.Name == targetName {
			return fmt.Sprintf("HPA '%s' manages this workload and may override this scale", hpa.Name)
		}
	}
	return ""
}
```

- [ ] **Step 4: Verify build**

Run: `cd /Users/andy/DEV/Go/pico-agent && go build ./...`
Expected: Build succeeds

- [ ] **Step 5: Commit**

```bash
git add internal/task/workload_scale/
git commit -m "feat(workload_scale): add workload scale task"
```

---

## Task 4: Create pod_evict Task

**Files:**
- Create: `/Users/andy/DEV/Go/pico-agent/internal/task/pod_evict/task.go`

- [ ] **Step 1: Create task package with types**

```go
// Package pod_evict provides pod eviction functionality.
package pod_evict

import (
	"context"
	"encoding/json"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/loafoe/pico-agent/internal/task"
)

const (
	TaskName         = "pod_evict"
	NoEvictAnnotation = "picoclaw.io/no-evict"
	DefaultGracePeriod = int64(30)
)

// Payload for pod_evict task.
type Payload struct {
	Namespace          string `json:"namespace"`
	PodName            string `json:"pod_name"`
	GracePeriodSeconds *int64 `json:"grace_period_seconds"`
	Force              bool   `json:"force"`
	Immediate          bool   `json:"immediate"`
	DryRun             bool   `json:"dry_run"`
}

// EvictDetails contains eviction operation details.
type EvictDetails struct {
	DryRun       bool   `json:"dry_run,omitempty"`
	Method       string `json:"method"`
	GracePeriod  int64  `json:"grace_period_seconds"`
	OwnerKind    string `json:"owner_kind,omitempty"`
	OwnerName    string `json:"owner_name,omitempty"`
	WillRecreate bool   `json:"will_recreate"`
	Warning      string `json:"warning,omitempty"`
}

// Task handles pod eviction operations.
type Task struct {
	clientset kubernetes.Interface
}

// New creates a new pod evict task.
func New(clientset kubernetes.Interface) *Task {
	return &Task{clientset: clientset}
}

// Name returns the task type identifier.
func (t *Task) Name() string {
	return TaskName
}
```

- [ ] **Step 2: Add Execute method**

```go
// Execute performs the pod eviction.
func (t *Task) Execute(ctx context.Context, rawPayload json.RawMessage) (*task.Result, error) {
	var payload Payload
	if err := json.Unmarshal(rawPayload, &payload); err != nil {
		return task.NewErrorResult(fmt.Sprintf("invalid payload: %v", err)), nil
	}

	if err := t.validatePayload(&payload); err != nil {
		return task.NewErrorResult(err.Error()), nil
	}

	// Check namespace annotation
	ns, err := t.clientset.CoreV1().Namespaces().Get(ctx, payload.Namespace, metav1.GetOptions{})
	if err != nil {
		return task.NewErrorResult(fmt.Sprintf("failed to get namespace: %v", err)), nil
	}
	if ns.Annotations[NoEvictAnnotation] == "true" {
		return task.NewErrorResult(fmt.Sprintf("namespace %s has %s annotation", payload.Namespace, NoEvictAnnotation)), nil
	}

	// Get pod
	pod, err := t.clientset.CoreV1().Pods(payload.Namespace).Get(ctx, payload.PodName, metav1.GetOptions{})
	if err != nil {
		return task.NewErrorResult(fmt.Sprintf("failed to get pod: %v", err)), nil
	}

	// Check pod annotation
	if pod.Annotations[NoEvictAnnotation] == "true" {
		return task.NewErrorResult(fmt.Sprintf("pod has %s annotation", NoEvictAnnotation)), nil
	}

	// Extract owner info
	ownerKind, ownerName, willRecreate := t.getOwnerInfo(pod)

	// Determine grace period
	gracePeriod := DefaultGracePeriod
	if payload.GracePeriodSeconds != nil {
		gracePeriod = *payload.GracePeriodSeconds
	}
	if payload.Immediate {
		gracePeriod = 0
	}

	// Build warning for bare pods
	warning := ""
	if !willRecreate {
		warning = "Bare pod - will not be recreated after eviction"
	}

	method := "eviction"
	if payload.Force {
		method = "delete"
	}

	if payload.DryRun {
		return task.NewSuccessResultWithDetails(
			fmt.Sprintf("[DRY-RUN] Would %s pod %s/%s", method, payload.Namespace, payload.PodName),
			EvictDetails{DryRun: true, Method: method, GracePeriod: gracePeriod, OwnerKind: ownerKind, OwnerName: ownerName, WillRecreate: willRecreate, Warning: warning},
		), nil
	}

	if payload.Force {
		return t.deletePod(ctx, &payload, gracePeriod, ownerKind, ownerName, willRecreate, warning)
	}
	return t.evictPod(ctx, &payload, gracePeriod, ownerKind, ownerName, willRecreate, warning)
}

func (t *Task) validatePayload(p *Payload) error {
	if p.Namespace == "" {
		return fmt.Errorf("namespace is required")
	}
	if p.PodName == "" {
		return fmt.Errorf("pod_name is required")
	}
	if p.GracePeriodSeconds != nil && *p.GracePeriodSeconds < 0 {
		return fmt.Errorf("grace_period_seconds cannot be negative")
	}
	return nil
}
```

- [ ] **Step 3: Add evict and delete methods**

```go
func (t *Task) evictPod(ctx context.Context, payload *Payload, gracePeriod int64, ownerKind, ownerName string, willRecreate bool, warning string) (*task.Result, error) {
	eviction := &policyv1.Eviction{
		ObjectMeta: metav1.ObjectMeta{
			Name:      payload.PodName,
			Namespace: payload.Namespace,
		},
		DeleteOptions: &metav1.DeleteOptions{
			GracePeriodSeconds: &gracePeriod,
		},
	}

	err := t.clientset.CoreV1().Pods(payload.Namespace).EvictV1(ctx, eviction)
	if err != nil {
		return task.NewErrorResult(fmt.Sprintf("eviction failed (PDB may be blocking): %v", err)), nil
	}

	return task.NewSuccessResultWithDetails(
		fmt.Sprintf("Evicted pod %s/%s", payload.Namespace, payload.PodName),
		EvictDetails{Method: "eviction", GracePeriod: gracePeriod, OwnerKind: ownerKind, OwnerName: ownerName, WillRecreate: willRecreate, Warning: warning},
	), nil
}

func (t *Task) deletePod(ctx context.Context, payload *Payload, gracePeriod int64, ownerKind, ownerName string, willRecreate bool, warning string) (*task.Result, error) {
	err := t.clientset.CoreV1().Pods(payload.Namespace).Delete(ctx, payload.PodName, metav1.DeleteOptions{
		GracePeriodSeconds: &gracePeriod,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to delete pod: %w", err)
	}

	return task.NewSuccessResultWithDetails(
		fmt.Sprintf("Deleted pod %s/%s (force mode, PDB bypassed)", payload.Namespace, payload.PodName),
		EvictDetails{Method: "delete", GracePeriod: gracePeriod, OwnerKind: ownerKind, OwnerName: ownerName, WillRecreate: willRecreate, Warning: warning},
	), nil
}

func (t *Task) getOwnerInfo(pod *corev1.Pod) (kind, name string, willRecreate bool) {
	for _, ref := range pod.OwnerReferences {
		if ref.Controller != nil && *ref.Controller {
			return ref.Kind, ref.Name, true
		}
	}
	return "", "", false
}
```

- [ ] **Step 4: Verify build**

Run: `cd /Users/andy/DEV/Go/pico-agent && go build ./...`
Expected: Build succeeds

- [ ] **Step 5: Commit**

```bash
git add internal/task/pod_evict/
git commit -m "feat(pod_evict): add pod eviction task"
```

---

## Task 5: Register Tasks in main.go

**Files:**
- Modify: `/Users/andy/DEV/Go/pico-agent/cmd/pico-agent/main.go`

- [ ] **Step 1: Add imports**

Add these imports after existing task imports:

```go
"github.com/loafoe/pico-agent/internal/task/workload_restart"
"github.com/loafoe/pico-agent/internal/task/workload_scale"
"github.com/loafoe/pico-agent/internal/task/pod_evict"
```

- [ ] **Step 2: Add conditional registration after get_resource block**

Find the `if cfg.Features.GetResourceEnabled` block and add after it:

```go
// Optional: workload_restart task
if cfg.Features.WorkloadRestartEnabled {
	registry.Register(workload_restart.New(k8sClient.Clientset))
	slog.Info("workload_restart task enabled")
}

// Optional: workload_scale task
if cfg.Features.WorkloadScaleEnabled {
	registry.Register(workload_scale.New(k8sClient.Clientset))
	slog.Info("workload_scale task enabled")
}

// Optional: pod_evict task
if cfg.Features.PodEvictEnabled {
	registry.Register(pod_evict.New(k8sClient.Clientset))
	slog.Info("pod_evict task enabled")
}
```

- [ ] **Step 3: Verify build**

Run: `cd /Users/andy/DEV/Go/pico-agent && go build ./...`
Expected: Build succeeds

- [ ] **Step 4: Commit**

```bash
git add cmd/pico-agent/main.go
git commit -m "feat(main): conditionally register write operation tasks"
```

---

## Task 6: Update Helm Chart Values

**Files:**
- Modify: `/Users/andy/DEV/Personal/helm-charts/charts/pico-agent/values.yaml`

- [ ] **Step 1: Add feature flags**

Find the `features:` section and add new flags:

```yaml
features:
  getResource: false
  # Write operations (disabled by default for security)
  workloadRestart: false
  workloadScale: false
  podEvict: false
```

- [ ] **Step 2: Commit**

```bash
cd /Users/andy/DEV/Personal/helm-charts
git add charts/pico-agent/values.yaml
git commit -m "feat(pico-agent): add write operation feature flags"
```

---

## Task 7: Update Helm Deployment Template

**Files:**
- Modify: `/Users/andy/DEV/Personal/helm-charts/charts/pico-agent/templates/deployment.yaml`

- [ ] **Step 1: Add environment variables**

Find the `{{- if .Values.features.getResource }}` block and add after it:

```yaml
{{- if .Values.features.workloadRestart }}
- name: WORKLOAD_RESTART_ENABLED
  value: "true"
{{- end }}
{{- if .Values.features.workloadScale }}
- name: WORKLOAD_SCALE_ENABLED
  value: "true"
{{- end }}
{{- if .Values.features.podEvict }}
- name: POD_EVICT_ENABLED
  value: "true"
{{- end }}
```

- [ ] **Step 2: Commit**

```bash
git add charts/pico-agent/templates/deployment.yaml
git commit -m "feat(pico-agent): add env vars for write operations"
```

---

## Task 8: Update Helm ClusterRole Template

**Files:**
- Modify: `/Users/andy/DEV/Personal/helm-charts/charts/pico-agent/templates/clusterrole.yaml`

- [ ] **Step 1: Add RBAC rules before additionalRules**

Find `{{- with .Values.rbac.additionalRules }}` and add before it:

```yaml
{{- if .Values.features.workloadRestart }}
  # Workload restart (patch pod template annotation)
  - apiGroups: ["apps"]
    resources: ["deployments", "statefulsets", "daemonsets"]
    verbs: ["patch"]
  # PDB read for safety checks
  - apiGroups: ["policy"]
    resources: ["poddisruptionbudgets"]
    verbs: ["get", "list"]
{{- end }}
{{- if .Values.features.workloadScale }}
  # Workload scale subresource
  - apiGroups: ["apps"]
    resources: ["deployments/scale", "statefulsets/scale"]
    verbs: ["get", "patch", "update"]
  # HPA read for warning detection
  - apiGroups: ["autoscaling"]
    resources: ["horizontalpodautoscalers"]
    verbs: ["get", "list"]
{{- end }}
{{- if .Values.features.podEvict }}
  # Pod eviction (PDB-respecting)
  - apiGroups: [""]
    resources: ["pods/eviction"]
    verbs: ["create"]
  # Pod delete (force mode)
  - apiGroups: [""]
    resources: ["pods"]
    verbs: ["delete"]
  # PDB read for error messages
  - apiGroups: ["policy"]
    resources: ["poddisruptionbudgets"]
    verbs: ["get", "list"]
{{- end }}
```

- [ ] **Step 2: Commit**

```bash
git add charts/pico-agent/templates/clusterrole.yaml
git commit -m "feat(pico-agent): add RBAC rules for write operations"
```

---

## Task 9: Add MCP Tools to pico-mcp

**Files:**
- Modify: `/Users/andy/DEV/Go/pico-mcp/internal/mcp/server.go`

- [ ] **Step 1: Add workload_restart tool registration**

Find `s.mcpServer.AddTool(mcp.NewTool("pv_resize"` and add after the pv_resize_status tool:

```go
// Workload restart tool
s.mcpServer.AddTool(mcp.NewTool("workload_restart",
	mcp.WithDescription("Trigger a rolling restart of a Deployment, StatefulSet, or DaemonSet. Respects PDBs and opt-out annotations."),
	mcp.WithString("agent_id", mcp.Required(), mcp.Description("The ID of the target pico-agent")),
	mcp.WithString("namespace", mcp.Required(), mcp.Description("Kubernetes namespace")),
	mcp.WithString("name", mcp.Required(), mcp.Description("Workload name")),
	mcp.WithString("kind", mcp.Required(), mcp.Description("Workload kind: deployment, statefulset, or daemonset")),
	mcp.WithBoolean("dry_run", mcp.Description("Validate without performing the restart")),
	mcp.WithDestructiveHintAnnotation(true),
	mcp.WithIdempotentHintAnnotation(true),
), s.instrumentedToolHandlerWithEvents("workload_restart", s.handleWorkloadRestart))
```

- [ ] **Step 2: Add workload_scale tool registration**

```go
// Workload scale tool
s.mcpServer.AddTool(mcp.NewTool("workload_scale",
	mcp.WithDescription("Scale a Deployment or StatefulSet to a target replica count. Warns if HPA is present."),
	mcp.WithString("agent_id", mcp.Required(), mcp.Description("The ID of the target pico-agent")),
	mcp.WithString("namespace", mcp.Required(), mcp.Description("Kubernetes namespace")),
	mcp.WithString("name", mcp.Required(), mcp.Description("Workload name")),
	mcp.WithString("kind", mcp.Required(), mcp.Description("Workload kind: deployment or statefulset")),
	mcp.WithNumber("replicas", mcp.Required(), mcp.Description("Target replica count")),
	mcp.WithBoolean("allow_scale_to_zero", mcp.Description("Required to scale to 0 replicas")),
	mcp.WithBoolean("dry_run", mcp.Description("Validate without performing the scale")),
	mcp.WithDestructiveHintAnnotation(true),
	mcp.WithIdempotentHintAnnotation(false),
), s.instrumentedToolHandlerWithEvents("workload_scale", s.handleWorkloadScale))
```

- [ ] **Step 3: Add pod_evict tool registration**

```go
// Pod evict tool
s.mcpServer.AddTool(mcp.NewTool("pod_evict",
	mcp.WithDescription("Evict or delete a specific pod. Uses Eviction API by default (respects PDB), force mode bypasses PDB."),
	mcp.WithString("agent_id", mcp.Required(), mcp.Description("The ID of the target pico-agent")),
	mcp.WithString("namespace", mcp.Required(), mcp.Description("Kubernetes namespace")),
	mcp.WithString("pod_name", mcp.Required(), mcp.Description("Name of the pod to evict")),
	mcp.WithNumber("grace_period_seconds", mcp.Description("Grace period for termination (default: 30)")),
	mcp.WithBoolean("force", mcp.Description("Bypass PDB and use direct delete")),
	mcp.WithBoolean("immediate", mcp.Description("Set grace period to 0 for immediate termination")),
	mcp.WithBoolean("dry_run", mcp.Description("Validate without performing the eviction")),
	mcp.WithDestructiveHintAnnotation(true),
	mcp.WithIdempotentHintAnnotation(false),
), s.instrumentedToolHandlerWithEvents("pod_evict", s.handlePodEvict))
```

- [ ] **Step 4: Commit**

```bash
cd /Users/andy/DEV/Go/pico-mcp
git add internal/mcp/server.go
git commit -m "feat(mcp): add workload_restart, workload_scale, pod_evict tools"
```

---

## Task 10: Add MCP Tool Handlers

**Files:**
- Modify: `/Users/andy/DEV/Go/pico-mcp/internal/mcp/server.go`

- [ ] **Step 1: Add handleWorkloadRestart handler**

Add after existing handlers:

```go
func (s *Server) handleWorkloadRestart(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	agentID, err := request.RequireString("agent_id")
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("invalid agent ID: %v", err)), nil
	}

	client, err := s.getFilteredRegistry(ctx).GetClient(agentID)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	payloadBytes, err := json.Marshal(request.Params.Arguments)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to marshal payload: %v", err)), nil
	}

	result, err := client.ExecuteTask(ctx, "workload_restart", payloadBytes)
	if err != nil {
		return s.enrichTaskError(ctx, client, agentID, "workload_restart", err)
	}

	return s.formatResult(result), nil
}
```

- [ ] **Step 2: Add handleWorkloadScale handler**

```go
func (s *Server) handleWorkloadScale(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	agentID, err := request.RequireString("agent_id")
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("invalid agent ID: %v", err)), nil
	}

	client, err := s.getFilteredRegistry(ctx).GetClient(agentID)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	payloadBytes, err := json.Marshal(request.Params.Arguments)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to marshal payload: %v", err)), nil
	}

	result, err := client.ExecuteTask(ctx, "workload_scale", payloadBytes)
	if err != nil {
		return s.enrichTaskError(ctx, client, agentID, "workload_scale", err)
	}

	return s.formatResult(result), nil
}
```

- [ ] **Step 3: Add handlePodEvict handler**

```go
func (s *Server) handlePodEvict(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	agentID, err := request.RequireString("agent_id")
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("invalid agent ID: %v", err)), nil
	}

	client, err := s.getFilteredRegistry(ctx).GetClient(agentID)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	payloadBytes, err := json.Marshal(request.Params.Arguments)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to marshal payload: %v", err)), nil
	}

	result, err := client.ExecuteTask(ctx, "pod_evict", payloadBytes)
	if err != nil {
		return s.enrichTaskError(ctx, client, agentID, "pod_evict", err)
	}

	return s.formatResult(result), nil
}
```

- [ ] **Step 4: Commit**

```bash
git add internal/mcp/server.go
git commit -m "feat(mcp): add handlers for write operation tools"
```

---

## Task 11: Add Error Enrichment Helper

**Files:**
- Modify: `/Users/andy/DEV/Go/pico-mcp/internal/mcp/server.go`

- [ ] **Step 1: Add enrichTaskError helper**

Add this helper function:

```go
// enrichTaskError checks for "task not found" errors and enriches them with available tasks.
func (s *Server) enrichTaskError(ctx context.Context, client *pico.Client, agentID, taskName string, err error) (*mcp.CallToolResult, error) {
	errStr := err.Error()
	if !strings.Contains(errStr, "task not found") {
		return mcp.NewToolResultError(fmt.Sprintf("failed to execute %s: %v", taskName, err)), nil
	}

	// Fetch available tasks for better error message
	tasks, listErr := client.ListTasks(ctx)
	if listErr != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to execute %s: %v", taskName, err)), nil
	}

	return mcp.NewToolResultError(fmt.Sprintf(
		"Agent '%s' does not support '%s'.\nAvailable tasks: %s\nHint: Write operations must be enabled in the agent's helm values.",
		agentID, taskName, strings.Join(tasks, ", "),
	)), nil
}
```

- [ ] **Step 2: Verify build**

Run: `cd /Users/andy/DEV/Go/pico-mcp && go build ./...`
Expected: Build succeeds

- [ ] **Step 3: Commit**

```bash
git add internal/mcp/server.go
git commit -m "feat(mcp): add error enrichment for task not found errors"
```

---

## Task 12: Build and Tag Releases

- [ ] **Step 1: Build and tag pico-agent**

```bash
cd /Users/andy/DEV/Go/pico-agent
git tag v0.29.0
git push origin main v0.29.0
VERSION=v0.29.0 KO_DOCKER_REPO=ghcr.io/loafoe/pico-agent ko build --bare --platform=linux/amd64,linux/arm64 --tags=v0.29.0 ./cmd/pico-agent
```

- [ ] **Step 2: Build and tag pico-mcp**

```bash
cd /Users/andy/DEV/Go/pico-mcp
git tag v0.40.15
git push origin main v0.40.15
VERSION=v0.40.15 KO_DOCKER_REPO=ghcr.io/loafoe/pico-mcp ko build --bare --platform=linux/amd64,linux/arm64 --tags=v0.40.15 ./cmd/pico-mcp
```

---

## Task 13: Deploy and Test

- [ ] **Step 1: Update values for dip-ce-k3s-eu to enable one feature**

Edit `/Users/andy/DEV/Philips/innovation-day/pico-agent/dip-ce-k3s-eu/values.yaml`:

```yaml
image:
  tag: v0.29.0

# Enable workload restart for testing
features:
  workloadRestart: true
```

- [ ] **Step 2: Deploy pico-agent**

```bash
cd /Users/andy/DEV/Personal/helm-charts
KUBECONFIG=/Users/andy/DEV/Personal/pulumi/k3s-on-ec2/dip-ce-k3s-eu.yaml helm upgrade --install pico-agent ./charts/pico-agent -n pico-agent -f /Users/andy/DEV/Philips/innovation-day/pico-agent/dip-ce-k3s-eu/values.yaml
```

- [ ] **Step 3: Verify task is registered**

```bash
KUBECONFIG=/Users/andy/DEV/Personal/pulumi/k3s-on-ec2/dip-ce-k3s-eu.yaml kubectl logs -n pico-agent -l app.kubernetes.io/name=pico-agent | grep workload_restart
```

Expected: `workload_restart task enabled`

- [ ] **Step 4: Deploy pico-mcp**

Update `/Users/andy/DEV/Philips/innovation-day/pico-mcp/dip-ce-k3s-eu/values.yaml`:
```yaml
image:
  tag: v0.40.15
```

```bash
KUBECONFIG=/Users/andy/DEV/Personal/pulumi/k3s-on-ec2/dip-ce-k3s-eu.yaml helm upgrade pico-mcp ./charts/pico-mcp -n pico-mcp -f /Users/andy/DEV/Philips/innovation-day/pico-mcp/dip-ce-k3s-eu/values.yaml
```
