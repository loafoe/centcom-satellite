# CloudWatch RCA Data-Retrieval Tasks Design

**Date:** 2026-07-02
**Status:** Draft
**Task names:** `cw_list_alarms`, `cw_alarm_history`, `cw_get_metrics`, `cw_logs_query`, `cost_explorer`

## Overview

Port the **read-only AWS data-retrieval layer** of the `ai-powered-cw-alarms-rca`
prototype into centcom-satellite as a set of standard tasks. The prototype is a
Python/FastAPI + React tool that performs AI-powered Root Cause Analysis on AWS
CloudWatch alarms: an operator picks a firing alarm, a Bedrock Claude agent
investigates via CloudWatch metrics/logs, and streams back a Markdown RCA report.

In the target architecture, **centcom-satellite becomes the data-retrieval
executor**. The AI agent (Bedrock) and the React UI remain upstream (in
`pico-mcp` / the AI layer) and call these new tasks over `POST /task`. Only the
deterministic AWS calls are ported here — no LLM, no UI, no state-changing
actions.

### Source → target mapping

The prototype retrieves data in two layers, both authenticated via
`boto3.Session(profile, region)`:

- **Layer A — direct boto3 calls** (`backend/main.py`, `backend/skills.py`):
  `describe_alarms`, `describe_alarm_history`, Cost Explorer `get_cost_and_usage`.
- **Layer B — agentic metrics/logs** (`backend/agent.py`): delegated to the
  external `awslabs.cloudwatch-mcp-server` subprocess, driven by the LLM. Under
  the hood this is CloudWatch `GetMetricData` + Logs Insights.

We reimplement both layers natively in Go using **AWS SDK for Go v2** (already a
dependency of the module via `cluster_info`). We do **not** shell out to the
Python MCP server — that would drag a Python/`uv` runtime into a hardened,
distroless Go container and fight the project's design.

### Goal: full `cloudwatch-mcp-server` parity (eliminate the Python dependency)

A primary objective is that **centcom** (the MCP server, formerly `pico-mcp`) can
expose equivalent tools backed entirely by centcom-satellite tasks, so the
upstream stack no longer depends on the awslabs
[`cloudwatch-mcp-server`](https://awslabs.github.io/mcp/servers/cloudwatch-mcp-server)
at all. The satellite provides the data-retrieval tasks; centcom wraps them as
MCP tools. To achieve parity we cover the cloudwatch-mcp-server tool surface, not
just the prototype's subset:

| cloudwatch-mcp-server capability | centcom-satellite task |
|----------------------------------|------------------------|
| Get active alarms | `cw_list_alarms` |
| Get alarm history | `cw_alarm_history` |
| Describe / list log groups | `cw_describe_log_groups` |
| Execute Logs Insights query (start + poll + cancel) | `cw_logs_query` |
| Get metric data | `cw_get_metrics` |
| List metrics / metric metadata | `cw_list_metrics` |
| Metrics Insights (SQL) query | `cw_get_metrics` (via `expression`) |
| Cost & usage (prototype extra) | `cost_explorer` |

**Note on "PromQL":** CloudWatch does not support PromQL. Its query languages are
**Logs Insights** (logs) and **Metrics Insights** (a SQL dialect for metrics,
issued through `GetMetricData` expressions). Both are covered above. If a genuine
Prometheus/Amazon-Managed-Prometheus (AMP) `query`/`query_range` endpoint is
required, that is a separate `prom_query` task — tracked as an open item, not in
this scope.

## Scope

**In scope (read-only):**

| New task | Prototype source | AWS SDK Go v2 API |
|----------|------------------|-------------------|
| `cw_list_alarms` | `main.get_alarms` | `cloudwatch.DescribeAlarms` (paginated; Metric + Composite) |
| `cw_alarm_history` | `skills.get_incident_timeline` | `cloudwatch.DescribeAlarmHistory` |
| `cw_get_metrics` | Layer B (metrics) | `cloudwatch.GetMetricData` (metric query or Metrics Insights `expression`) |
| `cw_list_metrics` | mcp-server parity | `cloudwatch.ListMetrics` |
| `cw_describe_log_groups` | mcp-server parity | `cloudwatchlogs.DescribeLogGroups` |
| `cw_logs_query` | Layer B (Logs Insights) | `cloudwatchlogs.StartQuery` + `GetQueryResults` (+ `StopQuery`) |
| `cost_explorer` | `skills.analyze_cost` | `costexplorer.GetCostAndUsage` |

**Explicitly out of scope** (state-changing / AI / UI — excluded per stakeholder
decision):

- `ssm.send_command` (runs shell on EC2) — remediation execution
- Alarm threshold tuning, remediation-command generation, runbook lookup
- The Bedrock RCA agent loop and React frontend (stay upstream)

## Delivery Phases

- **Phase 1 — alarms & cost (pure request/response):** `internal/aws/` helper,
  `cw_list_alarms`, `cw_alarm_history`, `cost_explorer`. No async mechanics.
- **Phase 2 — metrics & logs (cloudwatch-mcp-server parity):** `cw_get_metrics`
  (incl. Metrics Insights `expression`), `cw_list_metrics`,
  `cw_describe_log_groups`, and `cw_logs_query` (the only task with async poll
  mechanics).

Both phases ship behind the same feature flag; Phase 2 tasks simply register
additionally once implemented.

## Architecture

```
internal/aws/
  client.go        # config.LoadDefaultConfig + optional AssumeRole; builds service clients
  client_test.go
internal/task/cw_list_alarms/{task.go,task_test.go}
internal/task/cw_alarm_history/{task.go,task_test.go}
internal/task/cw_get_metrics/{task.go,task_test.go}
internal/task/cw_list_metrics/{task.go,task_test.go}
internal/task/cw_describe_log_groups/{task.go,task_test.go}
internal/task/cw_logs_query/{task.go,task_test.go}
internal/task/cost_explorer/{task.go,task_test.go}
```

### Shared AWS helper (`internal/aws/`)

A thin helper so every task builds AWS clients identically and stays
unit-testable. It follows the existing pattern in
`internal/task/cluster_info/aws.go` (which already uses
`config.LoadDefaultConfig(ctx)` + `hasAWSCredentials()` for IRSA detection).

Each task defines a **narrow interface** for the AWS API it needs (e.g. a
`describeAlarmsAPI` interface with the single method it calls) and accepts it via
its `New(...)` constructor. Production wiring passes the real SDK client; tests
pass a fake. This mirrors how `http_request` injects its `httpClient`/`resolver`
functions for testability.

```go
// internal/aws/client.go (illustrative)
type Config struct {
    Region      string // optional per-request override; falls back to AWS_REGION
    AssumeRole  string // optional role ARN for cross-account (future/optional)
}

func LoadAWSConfig(ctx context.Context, c Config) (aws.Config, error) { ... }
```

### Credentials

Uses the **AWS SDK default credential chain** — in EKS this resolves to
**IRSA / Pod Identity** (web-identity token on the ServiceAccount). No secrets
mounted in the pod. Payloads may optionally carry a `region` (and, as a future
extension, an account/role for cross-account `AssumeRole`) to match the
prototype's multi-profile cross-account inspection model.

### Observability

Inbound HTTP metrics, the `task.execute <type>` dispatch span, and `tasks_total`
counters are automatic for every task. The k8s metrics-transport does **not**
cover outbound AWS calls; instrumenting the AWS SDK with OTel middleware is noted
as a **future** enhancement, not part of this scope.

## API

All tasks are invoked via `POST /task` with `{ "type": "<name>", "payload": {...} }`
and return the standard `task.Result` (`success`, `message`, `details`).
Validation failures return `NewErrorResult(...)` with a **nil** Go error
(HTTP 200, `success:false`); only infrastructure failures (AWS call errors)
return a non-nil error (HTTP 500) — per existing convention.

### `cw_list_alarms`

```json
{ "type": "cw_list_alarms",
  "payload": { "state_filter": ["ALARM","INSUFFICIENT_DATA"], "alarm_name_prefix": "", "region": "eu-west-1" } }
```

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `state_filter` | []string | no | `["ALARM","INSUFFICIENT_DATA"]` | Alarm states to include |
| `alarm_name_prefix` | string | no | — | Filter by name prefix |
| `region` | string | no | `AWS_REGION` | Region override |

Reads both `MetricAlarms` and `CompositeAlarms` (paginated). **Output preserves
the prototype's `Alarm` model** so upstream consumers are unchanged:
`{name, arn, metric, namespace, state, reason, dimensions, updated}`.

### `cw_alarm_history`

```json
{ "type": "cw_alarm_history",
  "payload": { "alarm_name": "my-alarm", "start": "2026-06-18T00:00:00Z", "max_records": 50 } }
```

Wraps `DescribeAlarmHistory` (`HistoryItemType=StateUpdate`). Parses each item's
`HistoryData` JSON into `{timestamp, old_state, new_state, reason}`, sorted
chronologically (matches `skills.get_incident_timeline`). Default window: last
14 days; default `max_records`: 50.

### `cw_get_metrics`

```json
{ "type": "cw_get_metrics",
  "payload": { "namespace":"AWS/EC2", "metric_name":"CPUUtilization",
               "dimensions":{"InstanceId":"i-123"}, "period":300, "stat":"Average",
               "start":"...", "end":"..." } }
```

Wraps `GetMetricData`. Supports two payload modes: (a) a **metric query**
(`namespace`+`metric_name`+`dimensions`+`stat`), or (b) a **Metrics Insights
`expression`** (SQL dialect) via the `MetricDataQuery.Expression` field. Returns
timestamp/value series.

### `cw_list_metrics`

```json
{ "type": "cw_list_metrics",
  "payload": { "namespace":"AWS/EC2", "metric_name":"CPUUtilization",
               "dimensions":{"InstanceId":"i-123"}, "region":"eu-west-1" } }
```

Wraps `ListMetrics` (paginated). All fields optional; returns metric metadata
`{namespace, metric_name, dimensions}` — the discovery capability the
cloudwatch-mcp-server exposes for finding available metrics.

### `cw_describe_log_groups`

```json
{ "type": "cw_describe_log_groups",
  "payload": { "name_prefix":"/aws/lambda/", "limit":50, "region":"eu-west-1" } }
```

Wraps `DescribeLogGroups` (paginated). Returns
`{name, arn, stored_bytes, retention_days, created}`. Needed so callers can
discover which log groups to pass to `cw_logs_query`.

### `cw_logs_query`

```json
{ "type": "cw_logs_query",
  "payload": { "log_groups":["/aws/lambda/fn"], "query":"fields @timestamp,@message | limit 20",
               "start":"...", "end":"...", "limit":100 } }
```

Logs Insights: `StartQuery` → poll `GetQueryResults` until status `Complete`
(bounded timeout, e.g. 30s, with context cancellation). Modeled on the existing
`pv_resize` wait pattern. Returns result rows.

### `cost_explorer`

```json
{ "type": "cost_explorer",
  "payload": { "namespace":"AWS/EC2", "start":"...", "end":"...", "granularity":"MONTHLY" } }
```

Wraps `GetCostAndUsage` (client pinned to `us-east-1`, as CE is global — matches
prototype). Optional `namespace` maps to a SERVICE filter via the prototype's
`namespace→service` map (AWS/EC2→Amazon EC2, AWS/RDS, AWS/Lambda,
AWS/StorageGateway, AWS/ECS). Default window: last 30 days, `MONTHLY`, metrics
`UnblendedCost`/`UsageQuantity`.

## Configuration

- **Feature flag:** `CLOUDWATCH_RCA_ENABLED` → `FeaturesConfig.CloudWatchRCAEnabled`
  (default `false`). Gates registration of all five tasks in `main.go` as a block
  (like the `pv_resize` pair). A single flag is chosen over per-task flags because
  they share one credential + IAM concern.
- **Region:** default `AWS_REGION`; per-request `region` override in payload.
- **Capabilities:** add `CloudWatchRCA bool` to `cluster_info.Capabilities` and
  wire it in `main.go`'s `WithCapabilities(...)` so `pico-mcp` can discover it.

## IAM (not Kubernetes RBAC)

These tasks call AWS, not kube-apiserver, so `deploy/rbac.yaml` is **not**
extended. Instead, document the required IAM policy attached to the pod's IRSA
role:

```json
{
  "Effect": "Allow",
  "Action": [
    "cloudwatch:DescribeAlarms",
    "cloudwatch:DescribeAlarmHistory",
    "cloudwatch:GetMetricData",
    "cloudwatch:ListMetrics",
    "logs:DescribeLogGroups",
    "logs:StartQuery",
    "logs:GetQueryResults",
    "logs:StopQuery",
    "ce:GetCostAndUsage"
  ],
  "Resource": "*"
}
```

## Testing

Each task gets `task_test.go` with the AWS API behind a narrow interface and a
fake implementation (table-driven, `testify`). No live AWS calls in tests —
matching how existing tasks are tested. The `internal/aws/` helper gets a test
for region/AssumeRole resolution.

## Deliverables

- `internal/aws/` shared helper + test
- 7 task packages (`cw_list_alarms`, `cw_alarm_history`, `cw_get_metrics`,
  `cw_list_metrics`, `cw_describe_log_groups`, `cw_logs_query`, `cost_explorer`)
  + tests
- `config.go`: `CloudWatchRCAEnabled` flag
- `cluster_info`: `CloudWatchRCA` capability
- `main.go`: flag-gated registration block
- `go.mod`: add `aws-sdk-go-v2/service/cloudwatch`, `cloudwatchlogs`, `costexplorer`
- README "Available Tasks" table + CLAUDE.md updates; IAM policy doc

## Open Questions / Assumptions

These defaults were chosen in the stakeholder's absence and are easily revisited:

1. **All 7 tasks** (in 2 phases) vs. only the 3 pure-request tasks — assumed all 7
   to reach cloudwatch-mcp-server parity.
2. **Single feature flag** vs. per-task flags — assumed single.
3. **IRSA / SDK default chain** for credentials — assumed; cross-account
   `AssumeRole` designed as an optional payload extension for later.
4. **PromQL / Amazon Managed Prometheus:** CloudWatch has no PromQL; assumed the
   requirement is satisfied by Logs Insights + Metrics Insights. A dedicated
   `prom_query` task against an AMP/Prometheus endpoint is deferred unless
   confirmed needed.
