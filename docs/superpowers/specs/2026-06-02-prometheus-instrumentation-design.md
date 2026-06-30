# Prometheus Instrumentation for centcom-satellite

**Date**: 2026-06-02
**Status**: Approved (goal-driven)

## Goal

Fully instrument centcom-satellite with useful, low-cardinality Prometheus metrics. Identify the
highest-value signals and set up initial support, building on the existing metrics foundation.

## Current State

The default Prometheus registry already exposes Go runtime + process collectors via
`promhttp.Handler()` on the metrics port. Four application metrics exist in
`internal/observability/metrics.go`:

- `centcom_satellite_http_requests_total{method, path, status}`
- `centcom_satellite_http_request_duration_seconds{method, path}`
- `centcom_satellite_tasks_total{type, status}`
- `centcom_satellite_task_duration_seconds{type}`

These are kept. The work below adds coverage at **low-touch instrumentation points** — no edits
to the ~35 individual task files.

## New Metrics

### 1. Auth outcomes
```
centcom_satellite_auth_attempts_total{method, result}
```
- `method`: `mtls | jwt | dev | none`
- `result`: `success | rejected | unauthenticated`

Wired into `Handlers.authenticate` and `StreamHandlers.authenticate`. Bounded labels.

### 2. In-flight requests + build info
```
centcom_satellite_http_requests_in_flight              (gauge)
centcom_satellite_build_info{version, goversion} = 1   (gauge)
```
In-flight inc/dec in `MetricsMiddleware`. `build_info` set once at startup from the binary
`Version` and `runtime.Version()`.

### 3. Kubernetes API calls (via rest.Config.WrapTransport)
```
centcom_satellite_k8s_request_duration_seconds{verb, resource, status_class}
centcom_satellite_k8s_requests_total{verb, resource, status_class}
```
- `verb`: derived from HTTP method (`get`, `list/watch` collapse to method-level `get`, plus
  `post`, `put`, `patch`, `delete`)
- `resource`: parsed from the API path; bucketed to a known allow-list (else `other`) to bound
  cardinality
- `status_class`: `2xx | 4xx | 5xx | error`

A single `RoundTripper` wrapper installed via `rest.Config.WrapTransport` covers the clientset,
dynamic, and discovery clients automatically — every current and future task is covered with zero
per-task code. This is the key move that keeps "all tasks covered" pragmatic.

### 4. Log-stream metrics (handlers_stream.go)
```
centcom_satellite_log_streams_active             (gauge)
centcom_satellite_log_stream_duration_seconds    (histogram)
centcom_satellite_log_stream_lines_total         (counter)
```
The long-lived SSE endpoint is poorly captured by the generic HTTP duration histogram; these
record its real behavior.

## Cardinality Hardening

The existing HTTP metrics use a raw `path` label, which is unbounded (404-probing, path params).
`MetricsMiddleware` will map the request path to the **matched route pattern** from a fixed
allow-list (`/task`, `/tasks`, `/healthz`, `/readyz`, `/version`, `/logs/stream`, `/metrics`),
bucketing anything else to `other`. Same approach bounds the k8s `resource` label.

## Design Principles

- Reuse the existing `Metrics` struct + `NewMetricsWithRegistry` test seam. All new metrics
  registered there.
- New record helpers follow the existing `RecordHTTPRequest` / `RecordTask` method style.
- No new feature flag — metrics are always on (cheap, no RBAC impact). The metrics server already
  exists.
- Default histogram buckets (`prometheus.DefBuckets`) reused unless a signal needs different ones.

## Testing

- Unit tests in `internal/observability/metrics_test.go` verifying registration + record helpers
  using `prometheus/testutil`.
- Route-normalization unit test in the server package.
- k8s RoundTripper test verifying label extraction from sample request paths.

## Out of Scope (follow-ups)

- Per-task k8s call attribution (which task issued which API call) — requires context plumbing.
- Exemplars / trace-to-metric linking.
- SPIRE SVID rotation/expiry gauges.
