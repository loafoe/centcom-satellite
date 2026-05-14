# NodeClaim Delete Task Design

**Date:** 2026-05-14  
**Status:** Draft  
**Task name:** `nodeclaim_delete`

## Overview

Add a task to pico-agent for safely deleting Karpenter NodeClaims. Deleting a NodeClaim (rather than the K8s Node directly) lets Karpenter orchestrate graceful drain, PDB compliance, and clean EC2 termination.

## Use Cases

- **Incident response:** Force-recycle problematic nodes (NotReady, misbehaving)
- **Cost optimization:** Remove underutilized nodes, rotate instance types

## Requirements

| Requirement | Decision |
|-------------|----------|
| Primary identification | By NodeClaim name only |
| Do-not-disrupt handling | Soft block with `force=true` override |
| Wait behavior | Fire and forget (Karpenter handles orchestration) |
| RBAC scope | Cluster-wide |

## Architecture

```
internal/task/nodeclaim_delete/
  task.go       # Main implementation
  task_test.go  # Unit tests with fake dynamic client
```

Uses `k8s.io/client-go/dynamic` to interact with the NodeClaim CRD (`karpenter.sh/v1, NodeClaim`) without importing Karpenter's Go SDK.

### Why Dynamic Client

- No new dependency on Karpenter SDK (~20+ transitive deps)
- No version coupling with Karpenter releases
- Matches existing pico-agent patterns
- NodeClaim schema is simple and stable

## API

### Request

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

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `name` | string | yes | - | NodeClaim name |
| `dry_run` | bool | no | false | Preview without deleting |
| `force` | bool | no | false | Bypass do-not-disrupt annotation |

### Response

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

### Details Fields

| Field | Source | Description |
|-------|--------|-------------|
| `name` | payload | NodeClaim name |
| `node_name` | `status.nodeName` | Associated K8s node |
| `instance_type` | `status.instanceType` | EC2 instance type |
| `nodepool` | `metadata.labels["karpenter.sh/nodepool"]` | Parent NodePool |
| `dry_run` | payload | Whether this was a dry run |
| `force` | payload | Whether force was used |

## Safety Rails

1. **NodeClaim must exist** — returns error if not found
2. **Do-not-disrupt check** — blocks if `karpenter.sh/do-not-disrupt=true` annotation present, unless `force=true`
3. **Dry-run mode** — validates everything and returns what would happen without actually deleting
4. **Structured logging** — all operations logged with full NodeClaim context

## Error Handling

| Condition | Error Message |
|-----------|---------------|
| Empty name | `name is required` |
| NodeClaim not found | `nodeclaim not found: <name>` |
| Do-not-disrupt without force | `nodeclaim <name> has karpenter.sh/do-not-disrupt annotation; use force=true to override` |
| CRD not installed | `nodeclaim CRD not found in cluster` |
| API error | `failed to delete nodeclaim: <error>` |

## Implementation Details

### Task Constructor

```go
func New(dynamicClient dynamic.Interface) *Task
```

The dynamic client is injected at construction, allowing unit tests to use a fake client.

### Feature Flag

Add to `internal/config/config.go`:
```go
// NodeclaimDeleteEnabled enables the nodeclaim_delete task for Karpenter node management.
// Disabled by default as it requires Karpenter and can cause node termination.
NodeclaimDeleteEnabled bool
```

Load from environment:
```go
NodeclaimDeleteEnabled: getEnvBool("NODECLAIM_DELETE_ENABLED", false),
```

### Registration in main.go

```go
// Optional: nodeclaim_delete task (Karpenter node management)
if cfg.Features.NodeclaimDeleteEnabled {
    registry.Register(nodeclaim_delete.New(k8sClient.DynamicClient))
    slog.Info("nodeclaim_delete task enabled")
}
```

### GVR Definition

```go
var nodeClaimGVR = schema.GroupVersionResource{
    Group:    "karpenter.sh",
    Version:  "v1",
    Resource: "nodeclaims",
}
```

### Execution Flow

1. Parse and validate payload
2. Get NodeClaim via dynamic client
3. Extract metadata (node name, instance type, nodepool)
4. Check do-not-disrupt annotation
5. If dry_run, return success with details
6. Delete NodeClaim
7. Return success with details

## RBAC Requirements

### Helm Chart (at `/Users/andy/DEV/Personal/helm-charts/charts/pico-agent`)

Add to `values.yaml`:
```yaml
features:
  nodeclaimDelete: false  # Enable NodeClaim deletion for Karpenter node management
```

Add to `templates/clusterrole.yaml` (gated by feature flag):
```yaml
{{- if .Values.features.nodeclaimDelete }}
  # NodeClaim access for nodeclaim_delete task (Karpenter node management)
  - apiGroups: ["karpenter.sh"]
    resources: ["nodeclaims"]
    verbs: ["get", "delete"]
{{- end }}
```

Bump chart version in `Chart.yaml`.

### pico-agent deploy/rbac.yaml

Add ungated rule for clusters always using this feature:
```yaml
- apiGroups: ["karpenter.sh"]
  resources: ["nodeclaims"]
  verbs: ["get", "delete"]
```

## Testing Strategy

- Unit tests with `k8s.io/client-go/dynamic/fake`
- Test cases:
  - Successful deletion
  - NodeClaim not found
  - Do-not-disrupt blocks deletion
  - Do-not-disrupt bypassed with force
  - Dry run mode
  - Missing name validation

## Future Considerations (Out of Scope)

- Wait for deletion completion with timeout
- Lookup by node name instead of NodeClaim name
- Batch deletion of multiple NodeClaims
- Label-based restrictions
