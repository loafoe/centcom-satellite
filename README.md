# pico-agent

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A lightweight Kubernetes helper service that receives webhook-style task requests and executes cluster operations.

## Features

- **Webhook Authentication**: Grafana Alertmanager-compatible HMAC-SHA256 signature verification
- **Modular Task System**: Easy to extend with new task types
- **Full Observability**: Prometheus metrics, OpenTelemetry tracing, structured JSON logging
- **Security First**: Non-root container, read-only filesystem, RBAC-scoped permissions
- **SPIFFE/SPIRE Integration**: Workload identity with X.509 mTLS and JWT-SVID authentication
- **Supply Chain Security**: Images signed with [cosign](https://github.com/sigstore/cosign) keyless signing

## Available Tasks

| Task | Description |
|------|-------------|
| `cluster_health` | Get cluster health status |
| `cluster_info` | Get cluster information (version, nodes) |
| `get_events` | Get Kubernetes events with filtering by type, object, and time range |
| `get_logs` | Retrieve pod container logs with tail/since filtering |
| `list_namespaces` | List namespaces in the cluster |
| `list_pods` | List pods with status, containers, and resource details |
| `list_workloads` | List deployments, statefulsets, and daemonsets |
| `pv_resize` | Resize PersistentVolumeClaims |
| `pv_resize_status` | Check PVC resize operation status |
| `pv_usage` | Get PersistentVolume usage statistics |
| `resource_pressure` | Check node resource pressure conditions |
| `storage_status` | Get storage class and PV/PVC status |

## Container Image

Images are published to GitHub Container Registry:

```bash
docker pull ghcr.io/loafoe/pico-agent:latest
docker pull ghcr.io/loafoe/pico-agent:v0.1.0  # specific version
```

### Verifying Image Signatures

All released images are signed using [cosign](https://github.com/sigstore/cosign) keyless signing with GitHub Actions OIDC.

```bash
# Install cosign: https://docs.sigstore.dev/cosign/system_config/installation/

# Verify the image signature
cosign verify ghcr.io/loafoe/pico-agent:latest \
  --certificate-identity-regexp="https://github.com/loafoe/pico-agent/*" \
  --certificate-oidc-issuer="https://token.actions.githubusercontent.com"
```

Expected output on success:
```
Verification for ghcr.io/loafoe/pico-agent:latest --
The following checks were performed on each of these signatures:
  - The cosign claims were validated
  - Existence of the claims in the transparency log was verified offline
  - The code-signing certificate was verified using trusted certificate authority certificates
```

## Quick Start

### Build

```bash
make build          # Build binary
make test           # Run tests
make ko-build       # Build container image locally with ko
make ko-push        # Build and push to registry
```

### Deploy to Kubernetes

```bash
# Create the webhook secret first
kubectl create namespace pico-agent
kubectl create secret generic pico-agent-webhook \
  --namespace pico-agent \
  --from-literal=secret=your-secure-secret-here

# Deploy
kubectl apply -k deploy/
```

### Configuration

| Environment Variable | Default | Description |
|---------------------|---------|-------------|
| `WEBHOOK_SECRET` | (required) | HMAC secret for signature verification |
| `PORT` | 8080 | HTTP server port |
| `METRICS_PORT` | 9090 | Prometheus metrics port |
| `LOG_LEVEL` | info | Log level (debug, info, warn, error) |
| `LOG_FORMAT` | json | Log format (json, text) |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | (disabled) | OpenTelemetry collector endpoint |
| `OTEL_SERVICE_NAME` | pico-agent | Service name for tracing |

### SPIFFE/SPIRE Configuration

| Environment Variable | Default | Description |
|---------------------|---------|-------------|
| `SPIRE_ENABLED` | false | Enable SPIFFE/SPIRE workload identity |
| `SPIRE_AGENT_SOCKET` | (required if enabled) | Path to SPIRE agent socket |
| `SPIRE_TRUST_DOMAINS` | (required if enabled) | Comma-separated list of trusted SPIFFE trust domains |
| `SPIRE_ALLOWED_SPIFFE_IDS` | (all from trust domains) | Comma-separated list of allowed SPIFFE IDs |
| `SPIRE_MTLS_ENABLED` | true | Enable X.509 mTLS for transport security |
| `SPIRE_JWT_ENABLED` | false | Enable JWT-SVID authentication |
| `SPIRE_JWT_AUDIENCES` | (required if JWT enabled) | Comma-separated list of expected JWT audiences |

## SPIFFE/SPIRE Authentication

pico-agent supports [SPIFFE](https://spiffe.io/) workload identity via SPIRE for secure, certificate-based authentication between services.

### Authentication Modes

**X.509 mTLS** (default when SPIRE enabled):
- Server presents its SVID as the TLS certificate
- Clients must present valid SVIDs from configured trust domains
- Mutual TLS ensures both parties are authenticated

**JWT-SVID** (can be used alongside or instead of mTLS):
- Clients present JWT-SVID tokens in the `Authorization: Bearer <token>` header
- Useful when running behind a load balancer that terminates TLS
- Tokens are validated against configured audiences and trust domains

### Federation Support

pico-agent supports federated SPIFFE deployments with multiple trust domains:

```yaml
# Example: Accept SVIDs from multiple trust domains
SPIRE_TRUST_DOMAINS: "cluster-a.example.org,cluster-b.example.org"
SPIRE_ALLOWED_SPIFFE_IDS: "spiffe://cluster-a.example.org/ns/default/sa/pico-mcp"
```

### Kubernetes Deployment with SPIRE

```yaml
# Example values for Helm chart
spire:
  enabled: true
  csi:
    enabled: true
  className: spire-system-spire
  trustDomains:
    - cluster.example.org
  allowedSPIFFEIDs:
    - spiffe://cluster.example.org/ns/pico-mcp/sa/pico-mcp
  jwt:
    enabled: true
    audiences:
      - pico-agent
```

## API

### POST /task

Execute a task. Requires signature verification.

**Headers:**
- `X-Grafana-Alertmanager-Signature: sha256=<hex-encoded-hmac>`

**Request Body:**
```json
{
  "type": "pv_resize",
  "payload": {
    "namespace": "default",
    "pvc_name": "my-pvc",
    "new_size": "20Gi"
  }
}
```

**Response:**
```json
{
  "success": true,
  "message": "PVC default/my-pvc resize from 10Gi to 20Gi initiated"
}
```

### GET /tasks

List registered task types.

### GET /healthz

Liveness probe.

### GET /readyz

Readiness probe.

### GET /metrics (port 9090)

Prometheus metrics endpoint.

## Adding New Tasks

1. Create a new package under `internal/task/`:
   ```go
   package my_task

   import (
       "context"
       "encoding/json"
       "github.com/loafoe/pico-agent/internal/task"
   )

   type Task struct{}

   func New() *Task { return &Task{} }

   func (t *Task) Name() string { return "my_task" }

   func (t *Task) Execute(ctx context.Context, payload json.RawMessage) (*task.Result, error) {
       // Implementation
       return task.NewSuccessResult("done"), nil
   }
   ```

2. Register in `cmd/pico-agent/main.go`:
   ```go
   registry.Register(my_task.New())
   ```

## Generating Signatures

```bash
# Generate signature for testing
SECRET="your-secret"
PAYLOAD='{"type":"pv_resize","payload":{"namespace":"default","pvc_name":"test","new_size":"20Gi"}}'
echo -n "$PAYLOAD" | openssl dgst -sha256 -hmac "$SECRET" | awk '{print "sha256="$2}'
```

## License

MIT License - Copyright (c) 2026 Andy Lo-A-Foe

See [LICENSE](LICENSE) for details.
