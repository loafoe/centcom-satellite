# Write Operations for centcom-satellite

**Date:** 2026-05-08  
**Status:** Approved

## Overview

Add three opt-in write operations to centcom-satellite for incident response: workload restart, workload scaling, and pod eviction. Each operation is individually enabled via helm chart feature flags, with fine-grained RBAC permissions per feature.

## Goals

- Enable common operational mutations through centcom-satellite (restart, scale, evict)
- Maintain security via opt-in feature flags and least-privilege RBAC
- Provide safety rails to prevent accidental outages
- Support graceful capability discovery (agents advertise what they support)

## Non-Goals

- ConfigMap/Secret mutations (high blast radius, should use GitOps)
- Node cordon/drain (platform-level operations)
- Namespace create/delete (too destructive)

## Feature Flags

### Helm Values

```yaml
features:
  getResource: false       # existing
  workloadRestart: false   # new
  workloadScale: false     # new
  podEvict: false          # new
```

### Environment Variables

- `WORKLOAD_RESTART_ENABLED` - enables workload_restart task
- `WORKLOAD_SCALE_ENABLED` - enables workload_scale task
- `POD_EVICT_ENABLED` - enables pod_evict task

### Config Struct

```go
type FeaturesConfig struct {
    GetResourceEnabled     bool
    WorkloadRestartEnabled bool
    WorkloadScaleEnabled   bool
    PodEvictEnabled        bool
}
```

## Safety Rails

### Opt-out Annotations

All write operations check for opt-out annotations at two levels (namespace takes precedence):

| Operation | Annotation |
|-----------|------------|
| workload_restart | `picoclaw.io/no-restart: "true"` |
| workload_scale | `picoclaw.io/no-scale: "true"` |
| pod_evict | `picoclaw.io/no-evict: "true"` |

### Operation-Specific Safety

**workload_restart:**
- Checks PodDisruptionBudget before restart; fails if PDB's `status.disruptionsAllowed` is 0 (no disruptions currently permitted)

**workload_scale:**
- Requires `allow_scale_to_zero: true` to scale to 0 replicas
- Rejects scale-up exceeding 3x current replicas (prevents runaway scaling)
- Warns if HPA manages the workload (but proceeds)

**pod_evict:**
- Default uses Eviction API (respects PDB)
- `force: true` bypasses PDB (direct delete)
- `immediate: true` sets grace period to 0 (separate from force)
- Warns if pod is bare (not owned by controller, won't be recreated)

## Task Specifications

### workload_restart

Triggers a rolling restart equivalent to `kubectl rollout restart`.

**Payload:**
```go
type Payload struct {
    Namespace string `json:"namespace"`      // required
    Name      string `json:"name"`           // required
    Kind      string `json:"kind"`           // required: deployment|statefulset|daemonset
    DryRun    bool   `json:"dry_run"`        // default: false
}
```

**Response:**
```go
type RestartDetails struct {
    DryRun          bool   `json:"dry_run,omitempty"`
    PreviousRestart string `json:"previous_restart,omitempty"`
    Replicas        int32  `json:"replicas"`
    Message         string `json:"message,omitempty"`
}
```

**Implementation:**
1. Validate payload
2. Get workload by kind/namespace/name
3. Check namespace annotation `picoclaw.io/no-restart`
4. Check workload annotation `picoclaw.io/no-restart`
5. Check PDB - fail if it would block all disruption
6. Patch pod template with `kubectl.kubernetes.io/restartedAt: <timestamp>`
7. Return success with rollout info

### workload_scale

Scales a Deployment or StatefulSet to a target replica count.

**Payload:**
```go
type Payload struct {
    Namespace        string `json:"namespace"`           // required
    Name             string `json:"name"`                // required
    Kind             string `json:"kind"`                // required: deployment|statefulset
    Replicas         int32  `json:"replicas"`            // required
    AllowScaleToZero bool   `json:"allow_scale_to_zero"` // required if replicas=0
    DryRun           bool   `json:"dry_run"`             // default: false
}
```

**Response:**
```go
type ScaleDetails struct {
    DryRun           bool   `json:"dry_run,omitempty"`
    PreviousReplicas int32  `json:"previous_replicas"`
    NewReplicas      int32  `json:"new_replicas"`
    HPAWarning       string `json:"hpa_warning,omitempty"`
}
```

**Implementation:**
1. Validate payload (kind must be deployment or statefulset)
2. Get workload
3. Check namespace annotation `picoclaw.io/no-scale`
4. Check workload annotation `picoclaw.io/no-scale`
5. If replicas=0 and !AllowScaleToZero, fail
6. If replicas > currentReplicas * 3, fail with "exceeds 3x" error
7. Check for HPA, set warning if found
8. Update /scale subresource
9. Return success with before/after counts

### pod_evict

Evicts or deletes a specific pod.

**Payload:**
```go
type Payload struct {
    Namespace          string `json:"namespace"`            // required
    PodName            string `json:"pod_name"`             // required
    GracePeriodSeconds *int64 `json:"grace_period_seconds"` // default: 30
    Force              bool   `json:"force"`                // default: false
    Immediate          bool   `json:"immediate"`            // default: false
    DryRun             bool   `json:"dry_run"`              // default: false
}
```

**Response:**
```go
type EvictDetails struct {
    DryRun          bool   `json:"dry_run,omitempty"`
    Method          string `json:"method"`
    GracePeriod     int64  `json:"grace_period_seconds"`
    OwnerKind       string `json:"owner_kind,omitempty"`
    OwnerName       string `json:"owner_name,omitempty"`
    WillRecreate    bool   `json:"will_recreate"`
    Warning         string `json:"warning,omitempty"`
}
```

**Implementation:**
1. Validate payload
2. Get pod
3. Check namespace annotation `picoclaw.io/no-evict`
4. Check pod annotation `picoclaw.io/no-evict`
5. Extract owner reference
6. If !Force: use Eviction API
   - On PDB rejection, return error with PDB details
7. If Force: use pod delete
   - If Immediate: GracePeriodSeconds=0
   - Else: use provided or default (30s)
8. Return success with owner info and will_recreate flag

## RBAC

### ClusterRole Rules (conditional per feature)

**workloadRestart:**
```yaml
- apiGroups: ["apps"]
  resources: ["deployments", "statefulsets", "daemonsets"]
  verbs: ["patch"]
- apiGroups: ["policy"]
  resources: ["poddisruptionbudgets"]
  verbs: ["get", "list"]
```

**workloadScale:**
```yaml
- apiGroups: ["apps"]
  resources: ["deployments/scale", "statefulsets/scale"]
  verbs: ["get", "patch", "update"]
- apiGroups: ["autoscaling"]
  resources: ["horizontalpodautoscalers"]
  verbs: ["get", "list"]
```

**podEvict:**
```yaml
- apiGroups: [""]
  resources: ["pods/eviction"]
  verbs: ["create"]
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["delete"]
- apiGroups: ["policy"]
  resources: ["poddisruptionbudgets"]
  verbs: ["get", "list"]
```

## pico-mcp Changes

### Error Enrichment

When pico-mcp receives a "task not found" error from an agent, it fetches `/tasks` and returns an enriched error:

```
Agent 'obs-us-east-ct' does not support 'workload_restart'.
Available tasks: list_namespaces, list_pods, pv_resize, list_workloads, ...
Hint: Write operations must be enabled in the agent's helm values.
```

**Implementation:** Add helper function in `internal/mcp/server.go` that checks for "task not found" in error message, calls `client.ListTasks()`, and formats enriched error.

### MCP Tool Schemas

Add three new tools mirroring the task payloads:

- `workload_restart` - with agent_id, namespace, name, kind, dry_run
- `workload_scale` - with agent_id, namespace, name, kind, replicas, allow_scale_to_zero, dry_run
- `pod_evict` - with agent_id, namespace, pod_name, grace_period_seconds, force, immediate, dry_run

## Capability Advertisement

Capabilities are advertised implicitly: disabled tasks are not registered, so they don't appear in the `/tasks` endpoint response. pico-mcp can query `/tasks` to discover what each agent supports.

## File Structure

```
centcom-satellite/
├── internal/
│   ├── config/
│   │   └── config.go                    # Add feature flags
│   └── task/
│       ├── workload_restart/
│       │   ├── task.go                  # Main implementation
│       │   └── task_test.go             # Unit tests
│       ├── workload_scale/
│       │   ├── task.go
│       │   └── task_test.go
│       └── pod_evict/
│           ├── task.go
│           └── task_test.go
├── cmd/
│   └── centcom-satellite/
│       └── main.go                      # Conditional registration

centcom-satellite helm chart/
├── values.yaml                          # Add feature flags
└── templates/
    ├── clusterrole.yaml                 # Add conditional RBAC
    └── deployment.yaml                  # Add env vars

pico-mcp/
└── internal/
    └── mcp/
        └── server.go                    # Error enrichment + new tool schemas
```

## Testing Strategy

**Unit tests:**
- Each task package has tests for payload validation, safety rail checks, and success paths
- Mock Kubernetes clientset for isolated testing

**Integration tests:**
- Test with real (test) cluster using kind/k3d
- Verify RBAC permissions are sufficient and minimal
- Verify PDB enforcement works correctly

## Rollout Plan

1. Implement centcom-satellite tasks and helm chart changes
2. Deploy to dip-ce-k3s-eu with all features disabled (verify no regression)
3. Enable one feature at a time, test in staging
4. Update pico-mcp with error enrichment and tool schemas
5. Document feature flags in helm chart README
