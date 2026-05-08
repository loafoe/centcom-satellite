# Pod Resize Task Design

## Overview

In-place pod memory resize for OOMKill remediation using Kubernetes 1.27+ KEP-1287. Opt-in capability with safety rails to prevent runaway memory growth and QoS class changes.

## Design Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Safety rails | Percentage cap (50%) AND absolute cap (4Gi) | Catches both relative and absolute growth |
| Node capacity | Pre-flight check before resize | Early, actionable failure messages |
| QoS changes | Block by default | Preserves eviction priority behavior |
| Deployment drift | Pod-only resize, document limitation | Single responsibility; workload_resize is a future task |
| CPU support | Memory now, extensible schema for CPU later | OOMKill is immediate driver |
| Capability flag | Single `pod_resize: true` | Consistent with existing capability pattern |
| Opt-in granularity | Agent-level feature flag | No per-pod or per-namespace annotations required |

## Task Structure

### Payload

```go
type Payload struct {
    Namespace string `json:"namespace"`
    Pod       string `json:"pod"`
    Container string `json:"container,omitempty"` // defaults to first container
    Resources struct {
        Memory string `json:"memory,omitempty"` // e.g., "2Gi"
        // CPU string `json:"cpu,omitempty"` // future
    } `json:"resources"`
    DryRun bool `json:"dry_run,omitempty"`
}
```

### Validation Rules

1. **Percentage cap**: New memory must not exceed current memory by more than configured percentage (default 50%)
2. **Absolute cap**: New memory must not exceed absolute limit (default 4Gi)
3. **QoS preservation**: Resize must not change pod QoS class (Guaranteed stays Guaranteed)

### Response

```go
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
    Warning string `json:"warning,omitempty"` // "resize is ephemeral until pod restart"
    DryRun  bool   `json:"dry_run"`
}
```

## Safety Rails

### Percentage Cap

```go
currentMemory := container.Resources.Requests.Memory()
maxAllowed := currentMemory * (1 + percentageCap/100) // 1.5x for 50%
if requestedMemory > maxAllowed {
    return error("exceeds percentage cap: max %s, requested %s", maxAllowed, requestedMemory)
}
```

### Absolute Cap

```go
if requestedMemory > absoluteCap {
    return error("exceeds absolute cap: max %s, requested %s", absoluteCap, requestedMemory)
}
```

### QoS Preservation

```go
// Guaranteed: requests == limits for all containers
if isGuaranteed(pod) && requestedMemory != container.Resources.Limits.Memory() {
    return error("resize would change QoS class from Guaranteed to Burstable")
}
```

### Node Capacity Pre-flight

```go
node := getNode(pod.Spec.NodeName)
allocatable := node.Status.Allocatable.Memory()
currentUsage := sumPodMemoryRequests(podsOnNode)
delta := requestedMemory - currentMemory
if currentUsage + delta > allocatable {
    return error("node %s has insufficient capacity: %s available, %s needed",
        node.Name, allocatable - currentUsage, delta)
}
```

## Kubernetes API Integration

### Resize Mechanism (KEP-1287)

```go
patch := []byte(fmt.Sprintf(`{
    "spec": {
        "containers": [{
            "name": "%s",
            "resources": {
                "requests": {"memory": "%s"}
            }
        }]
    }
}`, containerName, newMemory))

_, err := clientset.CoreV1().Pods(namespace).
    Patch(ctx, podName, types.StrategicMergePatchType, patch, metav1.PatchOptions{
        DryRun: dryRunOpt,
    })
```

### Error Categories

- `validation_error`: Caps exceeded, QoS change blocked
- `capacity_error`: Node can't accommodate resize
- `api_error`: Kubernetes API failure
- `not_supported`: Cluster doesn't support in-place resize

## Configuration

### Helm Values

```yaml
podResize:
  enabled: false          # opt-in at agent level
  percentageCap: 50       # max 50% increase from current
  absoluteCap: "4Gi"      # never exceed 4Gi
```

### RBAC (Conditional)

```yaml
{{- if .Values.podResize.enabled }}
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "list", "patch"]
- apiGroups: [""]
  resources: ["nodes"]
  verbs: ["get", "list"]
{{- end }}
```

## Capability Advertising

### cluster_info Response

```go
Capabilities: Capabilities{
    WorkloadRestart: cfg.EnableWorkloadRestart,
    WorkloadScale:   cfg.EnableWorkloadScale,
    PodEvict:        cfg.EnablePodEvict,
    PodResize:       cfg.EnablePodResize,
}
```

### UI Updates

- Agents table: `pod_resize` badge (same style as existing capabilities)
- Agent overview pane: `pod_resize` in capabilities list

### Task Registration

```go
if cfg.EnablePodResize {
    registry.Register("pod_resize", podresize.New(client, cfg.PodResize))
    capabilities.PodResize = true
}
```

## Limitations

1. **Ephemeral resize**: Pod memory returns to original spec on restart (rolling update, crash, node drain)
2. **Memory only**: CPU resize not implemented in v1
3. **No workload patching**: Parent Deployment/StatefulSet spec unchanged; manual update required for persistence
4. **Kubernetes 1.27+ required**: KEP-1287 InPlacePodVerticalScaling feature gate must be enabled

## File Structure

```
internal/task/pod_resize/
├── task.go       # Task implementation
├── validation.go # Safety rail checks
├── capacity.go   # Node capacity pre-flight
└── task_test.go  # Unit tests
```
