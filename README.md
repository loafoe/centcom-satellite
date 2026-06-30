# centcom-satellite

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A lightweight Kubernetes helper service that receives task requests and executes cluster operations. Designed for AI agent integration with secure SPIFFE/SPIRE authentication.

## Features

- **SPIFFE/SPIRE Authentication**: Workload identity with X.509 mTLS and JWT-SVID authentication
- **Modular Task System**: Easy to extend with new task types
- **Full Observability**: Prometheus metrics, OpenTelemetry tracing, structured JSON logging
- **Security First**: Non-root container, read-only filesystem, RBAC-scoped permissions
- **Supply Chain Security**: Images signed with [cosign](https://github.com/sigstore/cosign) keyless signing

## Available Tasks

| Task | Description |
|------|-------------|
| `cluster_health` | Get cluster health status |
| `cluster_info` | Get cluster information (version, nodes) |
| `connectivity_test` | Test TCP/HTTP connectivity to endpoints |
| `dns_check` | Test DNS resolution for hostnames |
| `get_events` | Get Kubernetes events with filtering |
| `get_logs` | Retrieve pod container logs |
| `get_resource` | Get a specific Kubernetes resource |
| `list_endpoints` | List service endpoints |
| `list_gateways` | List Gateway API gateways |
| `list_ingresses` | List ingress resources |
| `list_namespaces` | List namespaces in the cluster |
| `list_network_policies` | List network policies |
| `list_pods` | List pods with status and resource details |
| `list_routes` | List OpenShift routes |
| `list_services` | List services in namespace |
| `list_workloads` | List deployments, statefulsets, daemonsets |
| `pod_evict` | Evict a pod from a node |
| `pod_resize` | Resize pod resource requests/limits |
| `pod_resource_usage` | Get pod resource usage metrics |
| `pv_resize` | Resize PersistentVolumeClaims |
| `pv_resize_status` | Check PVC resize operation status |
| `pv_usage` | Get PersistentVolume usage statistics |
| `resource_pressure` | Check node resource pressure conditions |
| `storage_status` | Get storage class and PV/PVC status |
| `workload_restart` | Restart a deployment/statefulset/daemonset |
| `workload_scale` | Scale workload replicas |

## Container Image

Images are published to GitHub Container Registry:

```bash
docker pull ghcr.io/loafoe/centcom-satellite:latest
docker pull ghcr.io/loafoe/centcom-satellite:v0.32.0  # specific version
```

### Verifying Image Signatures

All released images are signed using [cosign](https://github.com/sigstore/cosign) keyless signing with GitHub Actions OIDC.

```bash
# Install cosign: https://docs.sigstore.dev/cosign/system_config/installation/

# Verify the image signature
cosign verify ghcr.io/loafoe/centcom-satellite:latest \
  --certificate-identity-regexp="https://github.com/loafoe/centcom-satellite/*" \
  --certificate-oidc-issuer="https://token.actions.githubusercontent.com"
```

Expected output on success:
```
Verification for ghcr.io/loafoe/centcom-satellite:latest --
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
# Using Helm (recommended)
helm install centcom-satellite oci://ghcr.io/loafoe/helm-charts/centcom-satellite \
  --namespace centcom-satellite --create-namespace \
  --set 'spire.trustDomains[0]=example.org' \
  --set 'spire.allowedSPIFFEIDs[0]=spiffe://example.org/ai-agent'

# Or using kustomize
kubectl apply -k deploy/
```

### Configuration

| Environment Variable | Default | Description |
|---------------------|---------|-------------|
| `PORT` | 8080 | HTTP server port |
| `METRICS_PORT` | 9090 | Prometheus metrics port |
| `LOG_LEVEL` | info | Log level (debug, info, warn, error) |
| `LOG_FORMAT` | json | Log format (json, text) |
| `ALLOW_UNAUTHENTICATED` | false | Allow unauthenticated requests (dev mode only) |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | (disabled) | OpenTelemetry collector endpoint |
| `OTEL_SERVICE_NAME` | centcom-satellite | Service name for tracing |

### SPIFFE/SPIRE Configuration

SPIRE authentication is enabled by default. For local development without SPIRE, set `ALLOW_UNAUTHENTICATED=true`.

| Environment Variable | Default | Description |
|---------------------|---------|-------------|
| `SPIRE_AGENT_SOCKET` | unix:///run/spire/agent/sockets/spire-agent.sock | Path to SPIRE agent socket |
| `SPIRE_TRUST_DOMAINS` | (required) | Comma-separated list of trusted SPIFFE trust domains |
| `SPIRE_ALLOWED_SPIFFE_IDS` | (all from trust domains) | Comma-separated list of allowed SPIFFE IDs |
| `SPIRE_JWT_ENABLED` | false | Enable JWT-SVID authentication |
| `SPIRE_JWT_AUDIENCES` | (required if JWT enabled) | Comma-separated list of expected JWT audiences |

## SPIFFE/SPIRE Authentication

centcom-satellite uses [SPIFFE](https://spiffe.io/) workload identity via SPIRE for secure, certificate-based authentication between services.

### Authentication Modes

**X.509 mTLS** (default):
- Server presents its SVID as the TLS certificate
- Clients must present valid SVIDs from configured trust domains
- Mutual TLS ensures both parties are authenticated

**JWT-SVID** (can be used alongside or instead of mTLS):
- Clients present JWT-SVID tokens in the `Authorization: Bearer <token>` header
- Useful when running behind a load balancer that terminates TLS
- Tokens are validated against configured audiences and trust domains

### Federation Support

centcom-satellite supports federated SPIFFE deployments with multiple trust domains:

```yaml
# Example: Accept SVIDs from multiple trust domains
SPIRE_TRUST_DOMAINS: "cluster-a.example.org,cluster-b.example.org"
SPIRE_ALLOWED_SPIFFE_IDS: "spiffe://cluster-a.example.org/ns/default/sa/pico-mcp"
```

## Helm Chart

The recommended way to deploy centcom-satellite is via the Helm chart:

```bash
helm install centcom-satellite oci://ghcr.io/loafoe/helm-charts/centcom-satellite \
  --namespace centcom-satellite --create-namespace \
  --set 'spire.trustDomains[0]=example.org' \
  --set 'spire.allowedSPIFFEIDs[0]=spiffe://example.org/ai-agent'
```

### Example values.yaml

```yaml
image:
  tag: v0.32.0

spire:
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
      - centcom-satellite
```

See [ONBOARD.md](ONBOARD.md) for detailed deployment instructions.

## API

### POST /task

Execute a task. Requires SPIFFE/SPIRE authentication (mTLS or JWT-SVID).

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
       "github.com/loafoe/centcom-satellite/internal/task"
   )

   type Task struct{}

   func New() *Task { return &Task{} }

   func (t *Task) Name() string { return "my_task" }

   func (t *Task) Execute(ctx context.Context, payload json.RawMessage) (*task.Result, error) {
       // Implementation
       return task.NewSuccessResult("done"), nil
   }
   ```

2. Register in `cmd/centcom-satellite/main.go`:
   ```go
   registry.Register(my_task.New())
   ```

## License

MIT License - Copyright (c) 2026 Andy Lo-A-Foe

See [LICENSE](LICENSE) for details.
