# Cross-account AWS AssumeRole support

**Status**: Approved for planning
**Date**: 2026-08-25

## Problem

centcom-satellite's AWS-facing tasks (`cw_*`, `cost_explorer`, `guardduty_*`,
`securityhub_*`) currently only ever use the pod's own IRSA identity —
whatever AWS account the cluster's IRSA role lives in. There's no way to
point a deployment at a *different* AWS account's Security Hub / GuardDuty /
CloudWatch data.

Kubernetes-bound tasks (`pv_resize`, `list_pods`, etc.) are inherently
single-cluster/single-account — a remote account has no control plane this
satellite can reach — so those are explicitly out of scope and untouched.

## Deployment model

**One fixed target AWS account per deployment.** To reach a new account, you
deploy a *dedicated* centcom-satellite Helm release with its own hostname
(via the chart's existing `httpRoute.hostname` value) and its own
`AWS_ASSUME_ROLE_ARN`. This is the same pattern already used for per-cluster
SPIRE trust domains — nothing new architecturally, just a new per-release
value.

Each such release runs in **mixed mode**: Kubernetes tasks keep using the
in-cluster credentials/K8s client exactly as today (talking to *this*
cluster), while the AWS task families switch to the assumed-role identity and
talk to the *remote* account. The two credential domains are independent and
don't interact.

Backward compatibility is total: when `AWS_ASSUME_ROLE_ARN` is unset (the
default), every code path behaves byte-for-byte as it does today.

## Non-goals

- Per-request/dynamic target account selection (caller specifies a role ARN
  in the payload). Would require a new authz model — see below — and isn't
  needed by the dedicated-deployment-per-account model.
- Per-caller authorization mapping (SPIFFE ID → allowed account/role). SPIFFE
  identity is currently validated at the HTTP layer but never propagated into
  task `Execute()` context; all authenticated callers have equal access to
  whatever tasks are registered. Changing that is a separate, bigger effort
  and isn't needed here since account scoping happens at the deployment
  level, not per-caller.
- AWS SDK request metrics/tracing parity with the k8s transport
  (`k8s_requests_total` etc.). This is a pre-existing gap for all AWS tasks
  today, not something this change introduces or needs to fix.
- Per-task opt-out (e.g. "cost_explorer stays local, securityhub goes
  remote"). All AWS task families switch together when AssumeRole is
  configured.

## Design

### Config surface (`internal/config/config.go`)

New `Config.AWSAssumeRole` struct (not `FeaturesConfig` — this is a
credential-routing setting, not a task toggle):

| Env var | Default | Notes |
|---|---|---|
| `AWS_ASSUME_ROLE_ARN` | `""` | Target role ARN in the remote account. Empty = feature off, no behavior change. |
| `AWS_ASSUME_ROLE_EXTERNAL_ID` | `""` | Optional. Passed to `AssumeRole` for confused-deputy protection. |
| `AWS_ASSUME_ROLE_SESSION_NAME` | `centcom-satellite` | STS session name; shows up in the target account's CloudTrail. |

### `internal/aws` package

- New `Init(ctx context.Context, opts AssumeRoleOptions) error`, called once
  from `main.go` after config load, before task registration:
  1. Loads the base config once via `config.LoadDefaultConfig` (the pod's own
     IRSA identity).
  2. Builds `stscreds.NewAssumeRoleProvider(sts.NewFromConfig(baseCfg), opts.ARN, ...)`
     — with `ExternalID` set via the provider's functional option when
     configured — wrapped in `aws.NewCredentialsCache(...)`.
  3. Stores the cached provider in a package-level var, set once before the
     HTTP server starts accepting requests (no locking needed — same
     initialization-before-serving guarantee the codebase already relies on
     for `k8sClient`).
  4. Calls `sts.GetCallerIdentity` once through those credentials and logs the
     resolved remote account ID. Returns an error if this fails — see
     fail-fast below.
- `LoadConfig(ctx, Options{Region})` — called by all 17 existing AWS task
  files, **signature unchanged** — now checks that package var after loading
  the default per-call config: if set, it overrides `cfg.Credentials` with
  the shared cached provider before returning. If `Init` was never called
  (ARN unset), `LoadConfig` behaves exactly as it does today. This means
  **zero changes to any of the 17 task files** — the switch happens entirely
  inside the shared helper they already call.
- `cluster_info/aws.go`'s `detectAccountFromSTS` calls
  `config.LoadDefaultConfig` directly (not `awshelper.LoadConfig`) and stays
  that way — it must keep reporting the satellite's own local cluster
  account, not the assumed-role target. No change needed; this isolation
  already exists structurally.

### Startup: fail fast

`main.go`, immediately after `awshelper.Init(...)` (when `AWS_ASSUME_ROLE_ARN`
is set): the `GetCallerIdentity` check in `Init` must succeed or the process
exits with a clear error, consistent with how SPIRE config validation already
fails hard at startup. `/readyz` never reports ready with broken cross-account
credentials — misconfigured trust policies or external IDs are caught before
any traffic is served, not on the first caller's task request.

### IAM & deploy artifacts (this repo)

New `deploy/iam-policy-assumerole.json` — reference policy for the *source*
account's IRSA role: `sts:AssumeRole` scoped to the specific target role ARN
only (never `"*"`), matching the existing
`deploy/iam-policy-{cloudwatch-rca,guardduty,securityhub,securityhub-write}.json`
convention.

The *target* account's role trust policy (in the remote account, outside this
repo's deploy scope) needs `Principal` = the source IRSA role ARN and, when
`AWS_ASSUME_ROLE_EXTERNAL_ID` is used, a
`Condition.StringEquals."sts:ExternalId"` clause. Document this as a worked
example in the same doc, since it's the other half of the trust relationship
and avoids a support round-trip even though this repo can't provision it.

### Helm chart (companion change, separate repo:
`philips-software/helm-charts`, chart `centcom-satellite`)

Confirmed no blockers:

- **Dedicated URL per deployment** is already supported —
  `httpRoute.hostname` is a per-release value today. No chart change needed
  for this part; it's just a new release with a different hostname.
- **Source-account IAM** is Crossplane-managed
  (`templates/crossplane-iam-{role,policy,attachment}.yaml`), following an
  established per-feature pattern: one `Policy` + `RolePolicyAttachment` per
  task group, gated on a `.Values.features.*` flag, all attached to one
  generic role. The AssumeRole permission follows the same shape: a new
  `Policy`/`RolePolicyAttachment` pair gated on
  `.Values.aws.assumeRole.roleArn != ""`, granting `sts:AssumeRole` on that
  ARN — consistent with `cw-rca`/`guardduty`/`securityhub`, and usable
  immediately via the chart's existing `aws.irsa.extraPolicyArns` escape
  hatch if the templated version lags behind.
- Three new chart values map straight to the new env vars:
  `aws.assumeRole.roleArn`, `.externalId`, `.sessionName` — same shape as the
  existing `spire.*` per-release values.

This chart-side work is tracked as a companion task in the helm-charts repo,
not part of this spec's implementation plan.

### Observability

No new metrics needed — existing `task_duration_seconds` /
`tasks_total{type,status}` already cover AWS task execution outcomes, and the
credential layer itself isn't a new failure surface worth instrumenting
separately (fail-fast startup already catches misconfiguration). The one
addition is the startup log line with the resolved remote account ID
(described above) — cheap, high operational value.

### Testing

- `internal/aws`: unit tests for `LoadConfig` with/without `Init` called,
  using a fake STS client following the existing `NewWithClientFactory` test
  pattern used across the task packages.
- One test asserting that repeated `LoadConfig` calls after a successful
  `Init` don't trigger repeated `AssumeRole` STS calls — this is the
  behavior the caching design hinges on.
- No changes needed to any of the 17 AWS task packages' own tests, since
  their client-factory interfaces are untouched.
