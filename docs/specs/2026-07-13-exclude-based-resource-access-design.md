# Exclude-Based Resource Access for get_resource / list_custom_resources

## Overview

Make the generic resource-reader family (`get_resource` today, `list_custom_resources`
planned) governable by an **exclude model**: "all resources are viewable *except*
Secrets and a few other sensitive kinds." Kubernetes RBAC has no deny primitive —
a role is a union of allow rules — so an exclude model cannot be expressed in a
single ClusterRole. It is achieved instead by **three cooperating layers**, two of
which already exist in the satellite in embryonic form. The result: Secret
protection holds at three independent levels, so a bug in any one layer does not
expose secret data.

## Motivation

`get_resource` currently hardcodes a single exclusion (`internal/task/get_resource/task.go:66-69`):

```go
if strings.EqualFold(payload.Kind, "Secret") {
    return task.NewErrorResult(NewBlockedError("Secret").Error()), nil
}
```

This is correct in spirit but has three problems that a full implementation must fix:

1. **Kind-only match.** `EqualFold("Secret")` ignores the API group. A CRD
   coincidentally named `Secret` in another group would be blocked, and there is
   no way to block a *specific* group's kind (e.g. only `cert-manager.io`
   Certificates) without also blocking same-named kinds elsewhere.
2. **Not shared.** When `list_custom_resources` lands, it must consult the *same*
   exclusion set. A list tool that skips the block becomes a trivial bypass —
   `list_custom_resources(kind=Secret)` would enumerate what `get_resource`
   refuses.
3. **Not configurable.** "A few other sensitive ones" is deployment-specific and
   cannot require a code change per cluster.

Meanwhile the RBAC layer (`deploy/rbac.yaml`) is a **hand-enumerated allowlist** —
every resource the satellite can read is spelled out. That is safe but is the
opposite of an exclude model: any new CRD is invisible until an operator adds a
rule, and `get_resource`'s whole value proposition is reading *arbitrary* kinds.

## Why RBAC alone cannot do "all except Secrets"

Kubernetes RBAC is purely additive-allow. `resources: ["*"]` grants everything
**including** `secrets`; there is no `resources: ["*"] except ["secrets"]`. So the
exclude model is layered:

| Layer | Where | Exclude mechanism | Guarantee |
|-------|-------|-------------------|-----------|
| **1. K8s RBAC** | `deploy/rbac.yaml` | Bind SA to the built-in **`view`** ClusterRole (omits `secrets` by design) | Hard: API server refuses `get secrets` regardless of app logic |
| **2. GVK denylist** | `get_resource` + `list_custom_resources` task code | Config-driven group+kind denylist | Soft: task refuses before hitting the API |
| **3. Content redaction** | shared filter, generalized from `get_configmap/redact.go` | Mask secret-shaped bytes in allowed objects | Soft: catches leakage through non-secret objects |

### Layer 1 — bind to the built-in `view` ClusterRole

The native answer to "everything readable except Secrets" already ships with
Kubernetes: the built-in **`view`** ClusterRole. It grants read on the standard
resource set and **deliberately excludes `secrets`** (only `edit`/`admin`
include them). It also carries an `aggregationRule` keyed on the label
`rbac.authorization.k8s.io/aggregate-to-view: "true"`, so any operator whose CRD
ships an aggregation-labeled ClusterRole (cert-manager and many others do)
**flows into `view` automatically** — no per-CRD rule.

```yaml
# deploy/rbac.yaml — replace the enumerated read rules with:
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: view          # all standard reads + aggregated CRDs; Secrets excluded natively
```

The satellite's **write** rules (PVC patch, etc.) stay as their own small role;
only the broad *read* surface moves to `view`.

**Known gap — un-aggregated CRDs.** CRDs whose operators do *not* set the
aggregation label (some in-house CRDs) are invisible under `view`. Two options:

- **Accept it** — `get_resource` returns a clean "forbidden/not permitted" error
  for those kinds; operators add a targeted read rule when they want them.
- **Discovery-generated ClusterRole (v2)** — a small CronJob/controller walks the
  discovery API, enumerates every `(group, resource)`, and writes a ClusterRole
  containing all of them **minus `secrets`** (and any configured exclusions). This
  is the only way to get a true "everything except" RBAC surface that tracks CRDs
  as they are installed. Deferred; `view` covers the common case.

### Layer 2 — shared, config-driven GVK denylist

Promote the hardcoded block to a shared package consulted by both read tools:

```go
// internal/task/resourceaccess/denylist.go
package resourceaccess

import "k8s.io/apimachinery/pkg/runtime/schema"

// Denylist blocks specific group+kind pairs from the generic resource readers.
// An empty Group matches the core ("") group. Kind match is case-insensitive.
type Denylist struct {
    denied map[schema.GroupKind]struct{}
}

// DefaultDenied is always excluded even if config is empty — Secrets are the
// non-negotiable floor. RBAC (`view`) already blocks them; this is defense in depth.
var DefaultDenied = []schema.GroupKind{
    {Group: "", Kind: "Secret"},
}

func (d *Denylist) IsDenied(gk schema.GroupKind) bool { /* ... */ }
```

Config wiring (mirrors the existing `FeaturesConfig` env pattern in
`internal/config/config.go`):

```go
// FeaturesConfig addition
// RESOURCE_ACCESS_DENY="cert-manager.io/Certificate,/ServiceAccount,admissionregistration.k8s.io/MutatingWebhookConfiguration"
ResourceAccessDeny []schema.GroupKind
```

`get_resource.Execute` replaces its `EqualFold("Secret")` check with
`denylist.IsDenied(gvk.GroupKind())`; `list_custom_resources` calls the same
function per instance so the exclusion cannot be bypassed by listing. `Secret`
stays denied even if the operator supplies an empty list (`DefaultDenied`).

This layer is where **"a few other sensitive ones"** lives — kinds that `view`
*does* expose but the operator still wants withheld (ServiceAccounts and their
token refs, webhook configs carrying bearer tokens, SPIRE `ClusterSPIFFEID`,
org-specific CRDs).

### Layer 3 — shared content redaction

`get_configmap/redact.go` already implements a good secret-shaped-content
detector (secret-like key names, PEM blocks, inline `password=`/`token:` patterns,
Shannon entropy > 4.0 bits/char over ≥20 chars). Lift it into a shared
`internal/redact` package and apply it to `get_resource`/`list_custom_resources`
**summary and JSON output**, so an inline password in a Pod's `env`, a webhook's
`clientConfig`, or a ServiceAccount annotation is masked as `[REDACTED]` even when
the enclosing object is legitimately viewable.

## Defense in depth — why all three

- **RBAC is the boundary that actually holds.** Even with a denylist bug, binding
  to `view` means the SA token cannot `get secrets` — the API server refuses. App
  checks are best-effort; this is the guarantee.
- **The denylist gives flexibility** RBAC can't: non-secret sensitive kinds, and
  cheap per-request refusal without re-issuing cluster RBAC.
- **Redaction handles the residual** — secrets that leak *through* an allowed
  object rather than as a Secret resource.

## Feature gating

`get_resource` is already gated by `GET_RESOURCE_ENABLED` (off by default,
`config.go:47`). `list_custom_resources` should share a gate — reuse
`GetResourceEnabled` or add `LIST_CUSTOM_RESOURCES_ENABLED` following the same
"off by default, requires expanded RBAC" convention. The `view` binding is only
installed when a generic-read tool is enabled, keeping least-privilege for
deployments that don't use them.

## Scope

| Repo | Change |
|------|--------|
| **centcom-satellite** (this repo) | `internal/task/resourceaccess` denylist pkg; `get_resource` uses it; `list_custom_resources` task; `internal/redact` shared from `get_configmap`; `ResourceAccessDeny` config. |
| **centcom-satellite helm chart** | `roleRef` → built-in `view` for reads when a generic-read tool is enabled; `RESOURCE_ACCESS_DENY` env; keep write rules separate. |
| **centcom** (proxy) | Register `list_custom_resources` thin proxy tool + handler; audit logging; capability reporting. No k8s access here. |

## Open questions

1. **Discovery-generated ClusterRole** — build the v2 controller, or is `view` +
   targeted rules for un-aggregated CRDs enough in practice?
2. **Redaction on `output=json`** — masking inside an arbitrary object graph is
   harder than the flat `.data` map of a ConfigMap. Walk all string leaves, or
   only known-risky paths (`spec.template.spec.containers[].env`, webhook
   `clientConfig`, SA annotations)? Leaning: walk all string leaves through the
   shared entropy/pattern filter, same as ConfigMaps.
3. **Denied vs. filtered in list output** — should `list_custom_resources` omit
   denied kinds silently, or return them with a `blocked: true` marker so the
   caller knows they exist? Leaning: omit from data, note the count in the summary.
