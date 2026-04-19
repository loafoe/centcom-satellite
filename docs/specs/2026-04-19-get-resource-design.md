# get_resource Tool Design

## Overview

A new pico-agent task that retrieves any Kubernetes resource (built-in or CRD) using the dynamic client and REST mapper. Exposed via pico-mcp as an MCP tool.

## Motivation

Current pico-agent tasks use typed clients, limiting visibility to predefined resource types. Modern Kubernetes deployments rely heavily on CRDs (Crossplane, cert-manager, SPIRE, etc.). A generic `get_resource` tool enables inspection of any resource without adding task-specific code for each CRD.

## Design Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Location | pico-agent | Keep all k8s access in pico-agent, consistent with existing architecture |
| GVR resolution | Discovery + REST mapper | Standard k8s pattern, handles irregular plurals, client-go caches results |
| Default output | summary | LLM-optimized output provides more value than raw JSON |
| Namespace handling | Auto-detect via discovery | Error if namespaced resource missing namespace; don't assume "default" |
| Error format | Structured codes | Helps LLM reason about failures without parsing strings |

## Tool Definition

### MCP Tool (pico-mcp)

```
get_resource
├── agent_id (required) — target pico-agent
├── apiVersion (required) — e.g. "pkg.crossplane.io/v1beta1"
├── kind (required) — e.g. "FunctionRevision"
├── name (required) — resource name
├── namespace (optional) — empty/omit for cluster-scoped
└── output (optional) — "summary" (default) or "json"
```

### Task Payload (pico-agent)

```go
type Payload struct {
    APIVersion string `json:"apiVersion"`
    Kind       string `json:"kind"`
    Name       string `json:"name"`
    Namespace  string `json:"namespace,omitempty"`
    Output     string `json:"output,omitempty"` // "summary" or "json"
}
```

## Execution Flow

```
1. Parse payload, validate required fields
2. Parse apiVersion → schema.GroupVersion
3. REST mapper: GroupVersionKind → GroupVersionResource + scope
4. If namespaced && namespace == "": return NAMESPACE_REQUIRED error
5. If cluster-scoped: ignore any provided namespace
6. dynamic.Resource(gvr).Namespace(ns).Get(ctx, name, metav1.GetOptions{})
7. Handle API errors → structured error codes
8. Format output based on mode (summary or json)
9. Return task.Result
```

## Output Formats

### Summary (default)

Extracts common fields plus heuristic status fields:

```json
{
  "apiVersion": "pkg.crossplane.io/v1beta1",
  "kind": "FunctionRevision",
  "name": "function-auto-ready-a37a591901b6",
  "namespace": "",
  "scope": "cluster",
  "age": "3d12h",
  "createdAt": "2026-04-16T10:23:45Z",
  "generation": 1,
  "labels": {
    "pkg.crossplane.io/package": "function-auto-ready"
  },
  "annotations": ["crossplane.io/composition-resource-name"],
  "conditions": [
    {
      "type": "Healthy",
      "status": "True",
      "reason": "HealthyPackageRevision",
      "message": "",
      "lastTransitionTime": "2026-04-16T10:24:00Z",
      "age": "3d12h"
    }
  ],
  "status": {
    "phase": "Active",
    "observedGeneration": 1
  }
}
```

**Always included:**
- apiVersion, kind, name, namespace, scope
- createdAt, age, generation
- labels (key-value map)
- annotations (keys only, values often large/noisy)

**Heuristic fields (included if present in `.status`):**
- `conditions[]` — ubiquitous in modern CRDs
- `phase` — simple status string
- `observedGeneration` — staleness indicator
- `replicas`, `readyReplicas`, `availableReplicas` — workload-like resources

### JSON

Raw unstructured object as returned by the API:

```json
{
  "apiVersion": "pkg.crossplane.io/v1beta1",
  "kind": "FunctionRevision",
  "metadata": { ... },
  "spec": { ... },
  "status": { ... }
}
```

## Error Handling

Structured error response format:

```json
{
  "code": "NOT_FOUND",
  "message": "FunctionRevision \"foo\" not found",
  "hint": "Check the resource name and namespace"
}
```

### Error Codes

| Code | HTTP Status | When | Hint |
|------|-------------|------|------|
| `NOT_FOUND` | 404 | Resource doesn't exist | Check the resource name and namespace |
| `FORBIDDEN` | 403 | RBAC denies access | pico-agent needs RBAC permission for this resource |
| `API_NOT_FOUND` | 404 | CRD/API group not installed | Install the CRD or check apiVersion spelling |
| `INVALID_REQUEST` | — | Malformed apiVersion/kind | Check apiVersion format (group/version) |
| `NAMESPACE_REQUIRED` | — | Namespaced resource, no namespace given | This resource is namespaced; provide namespace parameter |
| `TIMEOUT` | — | API server didn't respond | Retry or check cluster health |

## Implementation

### pico-agent Changes

**1. Extend k8s client (`internal/k8s/client.go`):**

```go
type Client struct {
    Clientset     kubernetes.Interface
    DynamicClient dynamic.Interface
    RESTMapper    meta.RESTMapper
}
```

Initialize dynamic client and REST mapper from the same `rest.Config`.

**2. New task package (`internal/task/get_resource/task.go`):**

```go
type Task struct {
    dynamicClient dynamic.Interface
    restMapper    meta.RESTMapper
}

func (t *Task) Name() string { return "get_resource" }

func (t *Task) Execute(ctx context.Context, payload json.RawMessage) (*task.Result, error)
```

**3. Register task in main:**

Add to task registry alongside existing tasks.

### pico-mcp Changes

**1. Add MCP tool (`internal/mcp/server.go`):**

```go
s.mcpServer.AddTool(mcp.NewTool("get_resource",
    mcp.WithDescription("Get any Kubernetes resource by apiVersion, kind, and name"),
    mcp.WithString("agent_id", mcp.Required(), mcp.Description("The ID of the target pico-agent")),
    mcp.WithString("apiVersion", mcp.Required(), mcp.Description("API version (e.g. 'apps/v1', 'pkg.crossplane.io/v1beta1')")),
    mcp.WithString("kind", mcp.Required(), mcp.Description("Resource kind (e.g. 'Deployment', 'Function')")),
    mcp.WithString("name", mcp.Required(), mcp.Description("Resource name")),
    mcp.WithString("namespace", mcp.Description("Namespace (omit for cluster-scoped resources)")),
    mcp.WithString("output", mcp.Description("Output format: 'summary' (default) or 'json'")),
    mcp.WithReadOnlyHintAnnotation(true),
    mcp.WithDestructiveHintAnnotation(false),
    mcp.WithOpenWorldHintAnnotation(false),
), s.handleGetResource)
```

**2. Handler implementation:**

Forward payload to pico-agent `get_resource` task, return result.

## Testing

### Unit Tests

- GVK parsing: valid/invalid apiVersion formats
- REST mapper: namespaced vs cluster-scoped detection
- Namespace validation: error when required but missing
- Summary extraction: various `.status` shapes (with/without conditions, phase, replicas)
- Error mapping: k8s API errors to structured codes

### Integration Tests (Manual)

- Built-in resources: Deployment, ConfigMap, Node
- Crossplane resources: Function, FunctionRevision, Provider, ProviderRevision
- Cluster-scoped: ClusterRole, Namespace, PersistentVolume
- Namespaced: Pod, Service, Secret

## Future Considerations

Not in scope for v1, but potential future enhancements:

- `list_resources` — list multiple resources by GVK with label/field selectors
- Pluggable summary extractors for CRD-specific fields
- Watch mode for observing resource changes
- Field selectors for partial object retrieval
