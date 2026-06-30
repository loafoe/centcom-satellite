# CLAUDE.md - centcom-satellite

## Project Overview

**centcom-satellite** is a lightweight Kubernetes helper service that receives webhook-style task requests and executes cluster operations. It's designed for AI agent integration, allowing automated cluster management through a secure webhook interface.

**Repository**: github.com/loafoe/centcom-satellite  
**Module**: github.com/loafoe/centcom-satellite  
**License**: MIT (c) 2026 Andy Lo-A-Foe

## Architecture

```
cmd/centcom-satellite/main.go          # Entry point
internal/
  config/config.go              # Environment-based configuration
  server/
    server.go                   # HTTP server (plain or SPIRE mTLS)
    handlers.go                 # /task, /tasks, /healthz, /readyz
    middleware.go               # Logging, metrics, tracing, recovery
  task/
    registry.go                 # Task registration and dispatch
    types.go                    # TaskRequest, TaskResult, Task interface
    pv_resize/task.go           # PV resize implementation with wait support
  spire/
    client.go                   # SPIRE workload API client (X.509 mTLS + JWT-SVID)
    config.go                   # SPIRE configuration and validation
  k8s/client.go                 # Kubernetes client initialization
  observability/
    metrics.go                  # Prometheus metrics (promauto)
    tracing.go                  # OpenTelemetry OTLP tracing
    logging.go                  # slog JSON/text logging
```

## Authentication

The agent uses SPIFFE/SPIRE for workload identity authentication:

1. **SPIRE X.509 mTLS**: X.509 SVID-based mutual TLS authentication
2. **SPIRE JWT-SVID**: JWT token in `Authorization: Bearer <token>` header

Authentication is checked in order: mTLS → JWT-SVID. For local development, set `ALLOW_UNAUTHENTICATED=true`.

## Current Tasks

### Implemented: `pv_resize`

Resizes PersistentVolumeClaims in Kubernetes clusters.

**Request**:
```json
{
  "type": "pv_resize",
  "payload": {
    "namespace": "default",
    "pvc_name": "my-pvc",
    "new_size": "20Gi",
    "wait": true,
    "timeout": "5m"
  }
}
```

**Response** (with wait=true):
```json
{
  "success": true,
  "message": "PVC resized successfully",
  "details": {
    "namespace": "default",
    "pvc_name": "my-pvc",
    "previous_size": "10Gi",
    "requested_size": "20Gi",
    "final_size": "20Gi",
    "duration": "45s"
  }
}
```

### Implemented: `nodeclaim_delete`

Deletes Karpenter NodeClaims for safe node recycling.

**Request**:
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

**Response**:
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

**Safety**: Blocks deletion if `karpenter.sh/do-not-disrupt=true` annotation present (use `force=true` to override).

## Configuration

Environment variables:
- `PORT` (default: 8080) - Main HTTP server port
- `METRICS_PORT` (default: 9090) - Prometheus metrics port
- `ALLOW_UNAUTHENTICATED` (default: false) - Allow unauthenticated requests (dev mode only)
- `LOG_LEVEL` (default: info) - debug, info, warn, error
- `LOG_FORMAT` (default: json) - json, text
- `OTEL_EXPORTER_OTLP_ENDPOINT` - OpenTelemetry collector endpoint (span export). When empty, spans are not exported but trace context is still propagated.
- `OTEL_EXPORTER_OTLP_INSECURE` / `OTEL_EXPORTER_OTLP_TRACES_INSECURE` - set to `false` to use TLS for the OTLP exporter (default: insecure/plaintext)
- `OTEL_SERVICE_NAME` (default: centcom-satellite) - Service name for tracing
- `NODECLAIM_DELETE_ENABLED` (default: false) - Enable nodeclaim_delete task

SPIRE configuration:
- `SPIRE_ENABLED` (default: false) - Enable SPIRE authentication
- `SPIRE_AGENT_SOCKET` (default: unix:///run/spire/agent/sockets/spire-agent.sock)
- `SPIRE_TRUST_DOMAINS` - Comma-separated list of SPIFFE trust domains (supports federation)
- `SPIRE_TRUST_DOMAIN` - Single trust domain (backward compat, use SPIRE_TRUST_DOMAINS for new deployments)
- `SPIRE_ALLOWED_SPIFFE_IDS` - Comma-separated list of allowed SPIFFE IDs
- `SPIRE_JWT_ENABLED` (default: false) - Enable JWT-SVID authentication
- `SPIRE_JWT_AUDIENCES` - Comma-separated list of expected JWT audiences (required when JWT enabled)

## Metrics

Prometheus metrics are exposed on `METRICS_PORT` (default 9090) at `/metrics`, alongside the
standard Go runtime and process collectors. Application metrics (all prefixed `centcom_satellite_`):

| Metric | Type | Labels | Notes |
|--------|------|--------|-------|
| `http_requests_total` | counter | `method`, `path`, `status` | `path` is the matched route; unknown paths bucket to `other` |
| `http_request_duration_seconds` | histogram | `method`, `path` | |
| `http_requests_in_flight` | gauge | — | concurrent requests being served |
| `tasks_total` | counter | `type`, `status` | `status`: `success` / `failure` / `error` |
| `task_duration_seconds` | histogram | `type` | |
| `auth_attempts_total` | counter | `method`, `result` | `method`: `mtls`/`jwt`/`dev`/`none`; `result`: `success`/`rejected`/`unauthenticated` |
| `k8s_requests_total` | counter | `verb`, `resource`, `status_class` | recorded via a client-go transport wrapper; covers all tasks |
| `k8s_request_duration_seconds` | histogram | `verb`, `resource`, `status_class` | `resource` bucketed to a known allow-list, else `other` |
| `log_streams_active` | gauge | — | active `/logs/stream` SSE connections |
| `log_stream_duration_seconds` | histogram | — | wide buckets (1s–30m) for long-lived streams |
| `log_stream_lines_total` | counter | — | lines streamed to clients |
| `build_info` | gauge | `version`, `goversion` | constant `1`; build provenance |

Cardinality is bounded by normalizing the HTTP `path` label (`internal/server/middleware.go`)
and the k8s `resource` label (`internal/k8s/metrics_transport.go`). All metrics live in
`internal/observability/metrics.go`. K8s API instrumentation is installed via
`rest.Config.WrapTransport` in `internal/k8s/client.go`, so new tasks are covered automatically.

## Tracing & End-to-End Traceability

centcom-satellite participates in distributed traces that originate in **pico-mcp** (the
caller). The full chain is: `pico-mcp → [HTTP /task] → centcom-satellite → [client-go] → kube-apiserver`,
all stitched into one trace via **W3C Trace Context** (`traceparent`/`tracestate`)
plus baggage.

Note: centcom-satellite is a plain HTTP/JSON webhook receiver, **not** an MCP server, so
the MCP-specific instrumentation conventions (e.g. grafana's `mcpconv`, which
encode `tools/call`/MCP method semantics) do not apply here. The relevant standard
for this hop is W3C Trace Context over HTTP + OTel HTTP/k8s semantic conventions.

**Propagation is always on.** The global OTel propagator is installed in
`SetupTracing` even when `OTEL_EXPORTER_OTLP_ENDPOINT` is unset — so trace context
flows through centcom-satellite regardless of whether this process exports its own spans.
Span export (to the OTLP collector) is the only thing gated by the endpoint.

Instrumentation points:

| Hop | Mechanism | File |
|-----|-----------|------|
| Inbound HTTP | `otelhttp.NewHandler` server span; extracts `traceparent` from pico-mcp; span named `METHOD <route>` (normalized, low-cardinality) | `internal/server/middleware.go` (`TracingMiddleware`) |
| Task dispatch | child span `task.execute <type>` with `centcom_satellite.task.type` / `centcom_satellite.task.success` attributes; `RecordError` + Error status on failure. Payloads are **not** recorded (may hold secrets) | `internal/server/handlers.go` |
| Outbound k8s API | `otelhttp.NewTransport` wraps the metrics transport; creates `k8s <verb> <resource>` child spans and injects `traceparent` into every client-go request | `internal/k8s/metrics_transport.go` (`wrapTransport`) |
| Logs | slog handler injects `trace_id`/`span_id` from context into records (`*Context` log calls); access logs include them too | `internal/observability/logging.go`, `internal/server/middleware.go` |

The OTLP exporter uses `ParentBased(AlwaysSample)` so sampling decisions made
upstream by pico-mcp are honoured. `RecordError`/span helpers live in
`internal/observability/tracing.go`. Because k8s tracing rides on
`rest.Config.WrapTransport` (same place as the metrics transport), **new tasks are
traced automatically** — no per-task wiring needed.

## Build & Deploy

**Build image** (uses ko):
```bash
make docker-build
```

**CI/CD**: GitHub Actions builds and signs images on push to main and tags:
- `ghcr.io/loafoe/centcom-satellite:latest` (main branch)
- `ghcr.io/loafoe/centcom-satellite:vX.Y.Z` (tagged releases)

**Verify image signature** (keyless cosign):
```bash
cosign verify ghcr.io/loafoe/centcom-satellite:v0.4.0 \
  --certificate-identity-regexp='https://github.com/loafoe/centcom-satellite/.*' \
  --certificate-oidc-issuer='https://token.actions.githubusercontent.com'
```

## Helm Chart

**Repository**: oci://ghcr.io/loafoe/helm-charts/centcom-satellite  
**Source**: /Users/andy/DEV/Personal/helm-charts/charts/centcom-satellite

**Install**:
```bash
helm install centcom-satellite oci://ghcr.io/loafoe/helm-charts/centcom-satellite \
  --namespace centcom-satellite --create-namespace
```

The chart uses SPIRE for authentication by default. For mTLS with federated trust domains:
```bash
helm install centcom-satellite oci://ghcr.io/loafoe/helm-charts/centcom-satellite \
  --set 'spire.trustDomains[0]=example.org' \
  --set 'spire.trustDomains[1]=partner.com' \
  --set 'spire.allowedSPIFFEIDs[0]=spiffe://example.org/ai-agent' \
  --set 'spire.allowedSPIFFEIDs[1]=spiffe://partner.com/service'
```

For JWT-SVID authentication (useful when mTLS is not feasible):
```bash
helm install centcom-satellite oci://ghcr.io/loafoe/helm-charts/centcom-satellite \
  --set 'spire.trustDomains[0]=example.org' \
  --set spire.jwt.enabled=true \
  --set 'spire.jwt.audiences[0]=centcom-satellite'
```

For NodeClaim deletion (Karpenter node management):
```bash
helm install centcom-satellite oci://ghcr.io/loafoe/helm-charts/centcom-satellite \
  --set features.nodeclaimDelete=true
```

## Development

```bash
# Run tests
make test

# Run locally (requires kubeconfig)
export ALLOW_UNAUTHENTICATED=true
go run ./cmd/centcom-satellite

# Send test request (no signature needed in dev mode)
curl -X POST http://localhost:8080/task \
  -H "Content-Type: application/json" \
  -d '{"type":"cluster_info","payload":{}}'
```

## Adding New Tasks

1. Create `internal/task/<task_name>/task.go` implementing the `task.Task` interface:
   ```go
   type Task interface {
       Name() string
       Execute(ctx context.Context, payload json.RawMessage) (*TaskResult, error)
   }
   ```

2. Register in `cmd/centcom-satellite/main.go`:
   ```go
   registry.Register(new_task.New(dependencies))
   ```

3. Add RBAC permissions in `deploy/rbac.yaml` and Helm chart

## Current Version

- **centcom-satellite**: v0.41.0
- **Helm chart**: 0.42.0

## Key Dependencies

- `k8s.io/client-go` - Kubernetes client
- `go.opentelemetry.io/otel` - Tracing
- `github.com/prometheus/client_golang` - Metrics
- `github.com/spiffe/go-spiffe/v2` - SPIRE workload API (optional)
