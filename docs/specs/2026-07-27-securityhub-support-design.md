# Opt-in AWS Security Hub support for centcom-satellite

Date: 2026-07-27
Status: Approved (recommended options accepted)

## Goal

Extend centcom-satellite with opt-in AWS Security Hub support as a broader,
better-permissioned complement to the existing GuardDuty tasks:

- Read API surface to retrieve and triage Security Hub findings (which
  aggregate GuardDuty, Inspector, Macie, IAM Access Analyzer, Config
  compliance checks, and third-party/custom products).
- Write API surface to update a finding's investigation `Workflow.Status`
  (NEW/NOTIFIED/RESOLVED/SUPPRESSED) and attach a `Note` — the capability
  GuardDuty's API doesn't offer, and the main motivation for adding Security
  Hub alongside it.
- The RBAC (IAM) needed to do all of this from a satellite.

GuardDuty support is not being removed or replaced; Security Hub is additive.
Where a cluster has both enabled, Security Hub's `GetFindings` will also
surface GuardDuty-sourced findings (they flow into Security Hub automatically
when both services are enabled), giving a superset view.

## Scope

- **Satellite API only.** Build the tasks on centcom-satellite so a dashboard
  *could* be rendered and findings triaged. The centcom UI + API passthrough
  is a separate follow-up.
- **Read tasks + one write task.** Unlike GuardDuty (read-only), Security Hub
  adds a `BatchUpdateFindings`-backed task. Read and write are gated by
  separate feature flags with separate IAM policies, so a cluster can enable
  read-only triage visibility without granting write access.
- **Single account.** No cross-account/member aggregation. Findings are
  queried from the account centcom-satellite runs in via IRSA, matching the
  GuardDuty tasks' posture.
- **Product-agnostic filtering.** `GetFindings` filters work over all Security
  Hub findings regardless of source product — no GuardDuty-only narrowing.
  Callers filter by `product_name`/`type`/etc. themselves.
- **Workflow.Status + Note only for updates.** `BatchUpdateFindings` can also
  set `Severity`, `Confidence`, `Criticality`, `VerificationState`, `Types`,
  and `UserDefinedFields`; only `Workflow.Status` and `Note` are exposed in
  this pass. Extending the payload later is a non-breaking addition to the
  same task.

## Architecture

Security Hub support reuses the established GuardDuty pattern exactly — no
new architectural concepts:

- **Gating:** two new env vars, `SECURITYHUB_ENABLED` (read tasks) and
  `SECURITYHUB_WRITE_ENABLED` (update task) → `cfg.Features.SecurityHubEnabled`
  / `SecurityHubWriteEnabled` → two registration blocks in
  `cmd/centcom-satellite/main.go` mirroring the `GuardDutyEnabled` block. Both
  off by default. The write flag has no effect unless the read flag is also
  set (the update task still needs `GetFindings`-style lookups to be useful
  in practice, though it does not itself call `GetFindings`).
- **Dispatch:** each Security Hub operation is a `task.Task` in its own
  `internal/task/securityhub_*` package, dispatched via the existing `/task`
  endpoint. No new HTTP routes, no new middleware, no streaming.
- **Credentials:** reuse `internal/aws/client.go` as-is (IRSA default chain +
  per-request region + optional assume-role). The Security Hub SDK client is
  built per request from `awshelper.LoadConfig`.
- **Capability advertisement:** add `SecurityHub` and `SecurityHubWrite` bool
  fields to `cluster_info.Capabilities` so centcom can detect which mode is
  live.
- **New dependency:** `github.com/aws/aws-sdk-go-v2/service/securityhub`
  (latest v1.x at implementation time).

## Task surface

| Task | Security Hub API | Purpose | Gate |
|------|-------------------|---------|------|
| `securityhub_list_standards` | `DescribeHub` + `GetEnabledStandards` + `DescribeStandards` | Hub subscription status + enabled compliance standards (CIS/PCI-DSS/FSBP) — dashboard header | `SECURITYHUB_ENABLED` |
| `securityhub_get_findings` | `GetFindings` | Filtered, paginated, sorted findings — the core read task, full normalized records in one call (no list-then-hydrate split, unlike GuardDuty) | `SECURITYHUB_ENABLED` |
| `securityhub_get_findings_statistics` | `GetFindings` (paginated, aggregated client-side) | Counts-by-severity / by-workflow-status / by-type / by-product summary widgets | `SECURITYHUB_ENABLED` |
| `securityhub_update_findings` | `BatchUpdateFindings` | Set `Workflow.Status` + `Note` on up to 100 findings at once — triage/remediation action | `SECURITYHUB_WRITE_ENABLED` |

### Cross-cutting task decisions

- **Region:** taken from the payload (`awshelper.Options{Region: payload.Region}`),
  like the GuardDuty/CloudWatch tasks. Security Hub is regional.
- **Filtering (`get_findings`, `get_findings_statistics`):** a pragmatic
  subset of `AwsSecurityFindingFilters` (YAGNI, same spirit as GuardDuty's
  `Filter`):
  - `severity_labels` (list; equals on `SeverityLabel` — INFORMATIONAL/LOW/MEDIUM/HIGH/CRITICAL)
  - `types` (list; equals on `Type`)
  - `product_name` (equals on `ProductName`, e.g. "GuardDuty", "Macie", "Security Hub")
  - `workflow_status` (list; equals on `WorkflowStatus` — NEW/NOTIFIED/RESOLVED/SUPPRESSED)
  - `record_state` (equals on `RecordState` — ACTIVE/ARCHIVED; default ACTIVE
    only, matching the console default, mirroring GuardDuty's `archived`
    default)
  - `resource_type` (equals on `ResourceType`)
  - `aws_account_id` (equals on `AwsAccountId`)
  - `updated_after` / `updated_before` (RFC3339 range on `UpdatedAt`, using
    `DateFilter`)
  - `sort` field + order (default `SeverityNormalized` desc, matching the
    console's default "most severe first")
- **Statistics:** `get_findings_statistics` accepts a `group_by`
  (SEVERITY, TYPE, WORKFLOW_STATUS, PRODUCT; default SEVERITY) and the same
  filter subset. Since Security Hub has no server-side groupBy/statistics
  API (unlike GuardDuty's `GetFindingsStatistics`), this task paginates
  `GetFindings` internally (capped at 10 pages / up to ~1000 findings) and
  aggregates counts client-side. The result reports `truncated: true` and the
  last `next_token` if the page cap was hit, so callers know the counts are a
  lower bound rather than silently presenting partial data as complete.
- **Updates (`update_findings`):** payload takes a list of
  `{id, product_arn}` pairs (max 100 per AWS's own limit — enforced with a
  clear task-level error rather than letting the raw AWS `InvalidInputException`
  through) plus optional `workflow_status` and `note` (note text + an
  `updated_by` string identifying the caller/automation). At least one of
  `workflow_status` or `note` must be set. There is **no** same-`product_arn`
  constraint on `BatchUpdateFindings` — AWS explicitly supports batching
  findings from different products in one call — so no cross-validation
  beyond the count cap is needed. The task surfaces `ProcessedFindings` and
  `UnprocessedFindings` (with AWS's per-finding `ErrorCode`/`ErrorMessage`)
  separately in the result so partial failures are visible.
- **Normalized output:** each task returns its own structs rather than raw
  SDK types, keeping the wire contract stable for centcom, following
  `guardduty_common`'s pattern of preserving the full raw finding in a
  `detail json.RawMessage` field for dashboards that need everything.

### Normalized models (summary)

- `Standard`: `standards_arn, name, description, enabled_by_default,
  status` (from `DescribeStandards` cross-referenced with `GetEnabledStandards`).
- `HubStatus`: `hub_arn, subscribed_at, auto_enable_controls,
  control_finding_generator`.
- `Finding` (from `get_findings`): normalized header fields `id, product_arn,
  product_name, title, description, severity_label, severity_normalized,
  types[], workflow_status, record_state, compliance_status, resource_type,
  resource_id, aws_account_id, region, created_at, updated_at` plus `detail`
  carrying the marshaled full SDK finding.
- `Statistics`: `group_by` echo, `counts` (`{key, count}` list), `total`,
  `truncated` bool, `next_token` (set when `truncated` is true).
- `UpdateResult`: `processed[]{id, product_arn}`,
  `unprocessed[]{id, product_arn, error_code, error_message}`.

## RBAC / IAM

New `deploy/iam-policy-securityhub.json` (read, sibling to
`iam-policy-guardduty.json`), `Resource: "*"`:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "CentcomSecurityHubRead",
      "Effect": "Allow",
      "Action": [
        "securityhub:DescribeHub",
        "securityhub:GetEnabledStandards",
        "securityhub:DescribeStandards",
        "securityhub:GetFindings"
      ],
      "Resource": "*"
    }
  ]
}
```

New `deploy/iam-policy-securityhub-write.json` (write, additive):

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "CentcomSecurityHubWrite",
      "Effect": "Allow",
      "Action": [
        "securityhub:BatchUpdateFindings"
      ],
      "Resource": "*"
    }
  ]
}
```

Both are attached to the satellite's IRSA role independently of the
GuardDuty/CloudWatch RCA policies, so a cluster can enable Security Hub
read-only triage visibility without granting write access, and without
requiring GuardDuty or CloudWatch RCA to be enabled.

## Config

Add to `FeaturesConfig`:

```go
SecurityHubEnabled      bool // SECURITYHUB_ENABLED, default false
SecurityHubWriteEnabled bool // SECURITYHUB_WRITE_ENABLED, default false
```

Wired in `Load()` as `getEnvBool("SECURITYHUB_ENABLED", false)` and
`getEnvBool("SECURITYHUB_WRITE_ENABLED", false)`.

## Testing

Each new package gets a `task_test.go` using an injected fake client via
`NewWithClientFactory`, mirroring `internal/task/guardduty_list_findings/task_test.go`.
Coverage per task:

- `securityhub_list_standards`: happy-path normalization, empty-standards case.
- `securityhub_get_findings`: filter mapping (severity/type/workflow/record-state
  → `AwsSecurityFindingFilters`), pagination, invalid-payload error result.
- `securityhub_get_findings_statistics`: aggregation correctness per `group_by`,
  page-cap truncation reporting.
- `securityhub_update_findings`: happy-path `BatchUpdateFindings` call shape,
  >100-identifiers rejected with a clear error, partial-failure
  (`UnprocessedFindings`) surfaced in the result, missing both
  `workflow_status` and `note` rejected.

## Docs

- Feature-flag rows (`SECURITYHUB_ENABLED`, `SECURITYHUB_WRITE_ENABLED`) in
  `README.md` and `CLAUDE.md`.
- Task table rows in `README.md` (mirroring the `guardduty_*` rows).
- Env entries in `deploy/deployment.yaml` (commented, default off).
- `CLAUDE.md` "Current Tasks" section gets a new Security Hub subsection with
  request/response examples for `securityhub_update_findings` (the one
  mutating task, so it needs the same documentation treatment as
  `nodeclaim_delete`/`pv_resize`).

## Files touched

- `internal/config/config.go` — add both flags + env wiring
- `cmd/centcom-satellite/main.go` — register tasks (two blocks, read/write) +
  advertise capabilities
- `internal/task/cluster_info/task.go` — add `SecurityHub`/`SecurityHubWrite`
  capability fields
- `internal/task/securityhub_common/` — shared filter/normalization helpers
  + models
- `internal/task/securityhub_list_standards/`
- `internal/task/securityhub_get_findings/`
- `internal/task/securityhub_get_findings_statistics/`
- `internal/task/securityhub_update_findings/`
- `internal/aws/client.go` — reused as-is
- `deploy/iam-policy-securityhub.json` — new
- `deploy/iam-policy-securityhub-write.json` — new
- `deploy/deployment.yaml`, `README.md`, `CLAUDE.md` — docs

## Non-goals

- centcom UI / API passthrough (separate spec).
- Multi-account / organization admin aggregation.
- The Insights API (`CreateInsight`/`GetInsightResults`) — would require
  pre-provisioning stateful AWS-side resources outside the task model.
- `BatchUpdateFindings` fields beyond `Workflow.Status` and `Note`
  (`Severity`, `Confidence`, `Criticality`, `VerificationState`, `Types`,
  `UserDefinedFields`).
- Removing or superseding the existing `guardduty_*` tasks — Security Hub is
  additive; GuardDuty tasks remain useful for clusters that only need
  GuardDuty-native detector/threat-detection views.
- Automation Rules, Configuration Policies, Connectors, or any other
  Security Hub administrative surface.
