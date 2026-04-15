# CLAUDE.md - pico-agent

## Project Overview

**pico-agent** is a lightweight Kubernetes helper service that receives webhook-style task requests and executes cluster operations. It's designed for AI agent integration, allowing automated cluster management through a secure webhook interface.

**Repository**: github.com/loafoe/pico-agent  
**Module**: github.com/loafoe/pico-agent  
**License**: MIT (c) 2026 Andy Lo-A-Foe

## Architecture

```
cmd/pico-agent/main.go          # Entry point
internal/
  config/config.go              # Environment-based configuration
  server/
    server.go                   # HTTP server (plain or SPIRE mTLS)
    handlers.go                 # /task, /tasks, /healthz, /readyz
    middleware.go               # Logging, metrics, tracing, recovery
  webhook/signature.go          # HMAC-SHA256 verification (Grafana Alertmanager compatible)
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

## Authentication Modes

The agent supports multiple authentication modes (can be combined):

1. **Webhook Signature** (default): HMAC-SHA256 signature in `X-Grafana-Alertmanager-Signature` header
2. **SPIRE X.509 mTLS**: X.509 SVID-based mutual TLS authentication
3. **SPIRE JWT-SVID**: JWT token in `Authorization: Bearer <token>` header

Authentication is checked in order: mTLS → JWT-SVID → Webhook signature. The first successful method authenticates the request.

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

## Configuration

Environment variables:
- `PORT` (default: 8080) - Main HTTP server port
- `METRICS_PORT` (default: 9090) - Prometheus metrics port
- `WEBHOOK_SECRET` - HMAC secret for signature verification (required unless SPIRE enabled)
- `LOG_LEVEL` (default: info) - debug, info, warn, error
- `LOG_FORMAT` (default: json) - json, text
- `OTEL_EXPORTER_OTLP_ENDPOINT` - OpenTelemetry collector endpoint
- `OTEL_SERVICE_NAME` (default: pico-agent) - Service name for tracing

SPIRE configuration:
- `SPIRE_ENABLED` (default: false) - Enable SPIRE authentication
- `SPIRE_AGENT_SOCKET` (default: unix:///run/spire/agent/sockets/spire-agent.sock)
- `SPIRE_TRUST_DOMAINS` - Comma-separated list of SPIFFE trust domains (supports federation)
- `SPIRE_TRUST_DOMAIN` - Single trust domain (backward compat, use SPIRE_TRUST_DOMAINS for new deployments)
- `SPIRE_ALLOWED_SPIFFE_IDS` - Comma-separated list of allowed SPIFFE IDs
- `SPIRE_JWT_ENABLED` (default: false) - Enable JWT-SVID authentication
- `SPIRE_JWT_AUDIENCES` - Comma-separated list of expected JWT audiences (required when JWT enabled)

## Build & Deploy

**Build image** (uses ko):
```bash
make docker-build
```

**CI/CD**: GitHub Actions builds and signs images on push to main and tags:
- `ghcr.io/loafoe/pico-agent:latest` (main branch)
- `ghcr.io/loafoe/pico-agent:vX.Y.Z` (tagged releases)

**Verify image signature** (keyless cosign):
```bash
cosign verify ghcr.io/loafoe/pico-agent:v0.4.0 \
  --certificate-identity-regexp='https://github.com/loafoe/pico-agent/.*' \
  --certificate-oidc-issuer='https://token.actions.githubusercontent.com'
```

## Helm Chart

**Repository**: oci://ghcr.io/loafoe/helm-charts/pico-agent  
**Source**: /Users/andy/DEV/Personal/helm-charts/charts/pico-agent

**Install**:
```bash
helm install pico-agent oci://ghcr.io/loafoe/helm-charts/pico-agent \
  --namespace pico-agent --create-namespace
```

The chart auto-generates webhook secrets if not provided. For SPIRE mTLS with federated trust domains:
```bash
helm install pico-agent oci://ghcr.io/loafoe/helm-charts/pico-agent \
  --set spire.enabled=true \
  --set 'spire.trustDomains[0]=example.org' \
  --set 'spire.trustDomains[1]=partner.com' \
  --set 'spire.allowedSPIFFEIDs[0]=spiffe://example.org/ai-agent' \
  --set 'spire.allowedSPIFFEIDs[1]=spiffe://partner.com/service'
```

For JWT-SVID authentication (useful when mTLS is not feasible):
```bash
helm install pico-agent oci://ghcr.io/loafoe/helm-charts/pico-agent \
  --set spire.enabled=true \
  --set 'spire.trustDomains[0]=example.org' \
  --set spire.jwt.enabled=true \
  --set 'spire.jwt.audiences[0]=pico-agent'
```

## Development

```bash
# Run tests
make test

# Run locally (requires kubeconfig)
export WEBHOOK_SECRET=test-secret
go run ./cmd/pico-agent

# Send test request
curl -X POST http://localhost:8080/task \
  -H "Content-Type: application/json" \
  -H "X-Grafana-Alertmanager-Signature: sha256=$(echo -n '{"type":"pv_resize","payload":{"namespace":"default","pvc_name":"test","new_size":"10Gi"}}' | openssl dgst -sha256 -hmac 'test-secret' | cut -d' ' -f2)" \
  -d '{"type":"pv_resize","payload":{"namespace":"default","pvc_name":"test","new_size":"10Gi"}}'
```

## Adding New Tasks

1. Create `internal/task/<task_name>/task.go` implementing the `task.Task` interface:
   ```go
   type Task interface {
       Name() string
       Execute(ctx context.Context, payload json.RawMessage) (*TaskResult, error)
   }
   ```

2. Register in `cmd/pico-agent/main.go`:
   ```go
   registry.Register(new_task.New(dependencies))
   ```

3. Add RBAC permissions in `deploy/rbac.yaml` and Helm chart

## Current Version

- **pico-agent**: v0.8.0
- **Helm chart**: 0.8.0

## Key Dependencies

- `k8s.io/client-go` - Kubernetes client
- `go.opentelemetry.io/otel` - Tracing
- `github.com/prometheus/client_golang` - Metrics
- `github.com/spiffe/go-spiffe/v2` - SPIRE workload API (optional)
