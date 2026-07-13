# Opt-in GuardDuty support for centcom-satellite

Date: 2026-07-13
Status: Approved (recommended options accepted)

## Goal

Extend centcom-satellite with opt-in AWS GuardDuty support:

- Enough read API surface for centcom to recreate the standard GuardDuty dashboard.
- Ability to retrieve Findings (list + full detail).
- The RBAC (IAM) needed to do all of this from a satellite.

## Scope

- **Satellite API only.** Build the read tasks on centcom-satellite so a dashboard
  *could* be rendered. The centcom UI + API passthrough is a separate follow-up.
- **Read-only.** No archive/feedback/threat-list mutations. IAM stays read-only,
  matching the CloudWatch RCA posture.
- **Separate opt-in flag.** A dedicated `GUARDDUTY_ENABLED` feature flag and a
  dedicated IAM policy file, independently toggleable from CloudWatch RCA.

## Architecture

GuardDuty support reuses the established CloudWatch-RCA pattern exactly — no new
architectural concepts:

- **Gating:** new env var `GUARDDUTY_ENABLED` → `cfg.Features.GuardDutyEnabled`
  → a registration block in `cmd/centcom-satellite/main.go` that mirrors the
  `CloudWatchRCAEnabled` block. Off by default.
- **Dispatch:** each GuardDuty operation is a `task.Task` in its own
  `internal/task/guardduty_*` package, dispatched via the existing `/task`
  endpoint. No new HTTP routes, no new middleware, no streaming. Findings are
  paginated in-handler and returned as normalized JSON in `Result.Details`,
  exactly like `cw_list_alarms`.
- **Credentials:** reuse `internal/aws/client.go` as-is (IRSA default chain +
  per-request region + optional assume-role). The GuardDuty SDK client is built
  per request from `awshelper.LoadConfig`.
- **Capability advertisement:** add `GuardDuty bool` to `cluster_info.Capabilities`
  so centcom can detect the feature is live.
- **New dependency:** `github.com/aws/aws-sdk-go-v2/service/guardduty` (v1.82.0,
  already added to `go.mod`).

## Task surface

The AWS console GuardDuty summary/findings view is driven by four read
operations. We expose five tasks (the fifth is a convenience composite):

| Task | GuardDuty API | Dashboard purpose |
|------|---------------|-------------------|
| `guardduty_list_detectors` | `ListDetectors` + `GetDetector` | Detector status/health header; resolves the detector ID |
| `guardduty_get_findings_statistics` | `GetFindingsStatistics` (GroupBy) | Counts-by-severity / by-type / by-date summary widgets |
| `guardduty_list_findings` | `ListFindings` | Finding IDs matching a filter + sort (paginated) |
| `guardduty_get_findings` | `GetFindings` | Full detail for a batch of finding IDs |
| `guardduty_findings` | `ListFindings` → `GetFindings` | Composite: filtered, fully-hydrated findings in one call |

### Cross-cutting task decisions

- **Detector ID:** every task accepts optional `detector_id`. If omitted, the
  task calls `ListDetectors` and uses the first detector (single-detector-per-region
  is the norm). If none exists, return a clear error result.
- **Region:** taken from the payload (`awshelper.Options{Region: payload.Region}`),
  like `cw_list_alarms`. GuardDuty is regional.
- **Filtering:** `list_findings` / `findings` accept a pragmatic subset of
  `FindingCriteria`, not the full grammar (YAGNI):
  - `severity` (minimum severity, `>=` on `severity`)
  - `type` (list of finding types, `equals` on `type`)
  - `resource_type` (`equals` on `resource.resourceType`)
  - `archived` (bool; maps to `service.archived` equals true/false — default: only
    unarchived, matching the console default)
  - `updated_after` / `updated_before` (epoch-ms range on `updatedAt`)
  - `sort` field + order (default `severity` desc, then the console default)
- **Statistics:** `get_findings_statistics` accepts a `group_by` (SEVERITY,
  FINDING_TYPE, DATE, RESOURCE, ACCOUNT; default SEVERITY) and the same filter
  subset, using the non-deprecated `GroupBy` API.
- **Normalized output:** each task returns its own structs (`Detector`,
  `FindingSummary`, `Finding`, `FindingStatistics`) rather than raw SDK
  `types.Finding`, keeping the wire contract stable for centcom. The full raw
  finding detail is preserved via a passthrough `Raw json.RawMessage`-style field
  where fidelity matters (see below).

### Normalized models (summary)

- `Detector`: `id, status, service_role, finding_publishing_frequency, created_at,
  updated_at, features[]{name,status}`.
- `FindingSummary` (from `guardduty_list_findings`): just the IDs plus `count` and
  `next_token` (list endpoint returns IDs only).
- `Finding` (from `guardduty_get_findings` / `guardduty_findings`): normalized
  header fields `id, arn, type, title, description, severity, severity_label,
  confidence, account_id, region, resource_type, created_at, updated_at, count`
  plus `detail` carrying the marshaled full SDK finding for dashboards that need
  everything. `severity_label` derives High/Medium/Low from the numeric severity
  using GuardDuty's documented thresholds (Low 1.0–3.9, Medium 4.0–6.9,
  High 7.0–8.9; ≥7 shown as High in the console).
- `FindingStatistics`: `group_by` echo plus `counts` — a list of
  `{key, count}` entries (e.g. key `"7"`/`"8"` for severity buckets, or type
  strings), normalized from whichever `GroupedBy*` field the API populated.

## RBAC / IAM

New `deploy/iam-policy-guardduty.json` (sibling to `iam-policy-cloudwatch-rca.json`),
read-only, `Resource: "*"`:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "CentcomGuardDutyRead",
      "Effect": "Allow",
      "Action": [
        "guardduty:ListDetectors",
        "guardduty:GetDetector",
        "guardduty:ListFindings",
        "guardduty:GetFindings",
        "guardduty:GetFindingsStatistics"
      ],
      "Resource": "*"
    }
  ]
}
```

This policy is attached to the satellite's IRSA role independently of the
CloudWatch RCA policy, so a cluster can enable GuardDuty without CloudWatch
access (least privilege).

## Config

Add to `FeaturesConfig`:

```go
GuardDutyEnabled bool // GUARDDUTY_ENABLED, default false
```

Wired in `Load()` as `getEnvBool("GUARDDUTY_ENABLED", false)`.

## Testing

Each new package gets a `task_test.go` using an injected fake client via
`NewWithClientFactory`, mirroring `internal/task/cw_list_alarms/task_test.go`.
Coverage per task: happy-path normalization, invalid-payload error result,
detector-id auto-resolution (uses `ListDetectors` when omitted / errors when no
detector), filter mapping (severity/type/archived → `FindingCriteria`),
pagination where applicable, and severity-label derivation.

## Docs

- Feature-flag row (`GUARDDUTY_ENABLED`) in `README.md`.
- Env entry in `deploy/deployment.yaml` (commented, default off).
- Note in project `CLAUDE.md` (tasks list + IAM policy reference).

## Files touched

- `internal/config/config.go` — add flag + env wiring
- `cmd/centcom-satellite/main.go` — register tasks + advertise capability
- `internal/task/cluster_info/task.go` — add `GuardDuty` capability field
- `internal/task/guardduty_common/` — shared payload/filter/detector helpers + models
- `internal/task/guardduty_list_detectors/`
- `internal/task/guardduty_get_findings_statistics/`
- `internal/task/guardduty_list_findings/`
- `internal/task/guardduty_get_findings/`
- `internal/task/guardduty_findings/` (composite)
- `internal/aws/client.go` — reused as-is
- `deploy/iam-policy-guardduty.json` — new
- `deploy/deployment.yaml`, `README.md`, `CLAUDE.md` — docs

## Non-goals

- centcom UI / API passthrough (separate spec).
- Any mutating GuardDuty operation (archive, feedback, threat/IP lists).
- Multi-detector fan-out within one region.
- Full `FindingCriteria` grammar.
