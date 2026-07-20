# SPIRE Healthz & Readiness Integration Design

## Overview
Currently, `/healthz` and `/readyz` endpoints in `centcom-satellite` return `200 OK` statically without checking whether the SPIFFE/SPIRE workload API connection is healthy or whether SVIDs have been acquired. Furthermore, in the Helm chart deployment template, the probes were conditionally routed to `/metrics` when SPIRE was enabled to avoid mTLS probe failures.

This design introduces active SPIFFE/SPIRE health checks to the `/healthz` and `/readyz` handlers, exposes these probe endpoints on the unauthenticated metrics port (9090), and updates the Helm chart to properly utilize `/healthz` and `/readyz` for liveness and readiness probes.

## Architecture & Data Flow

```
Kubelet Probe (HTTP) ---> [ Port 9090 (metricsMux) ] ---> HandleHealthz / HandleReadyz
                                                                  |
                                                         spireClient.HealthCheck(ctx)
                                                                  |
                                                 +----------------+----------------+
                                                 |                                 |
                                       X.509 SVID Check                    JWT Source Check
                                    (source.GetX509SVID())            (jwtSource.GetJWTBundleSet())
```

## Changes

### 1. `internal/spire/client.go`
- Add method `HealthCheck(ctx context.Context) error`:
  - If `c == nil` or `!c.config.Enabled`: returns `nil`.
  - If SPIRE is enabled (mTLS): verifies `source.GetX509SVID()` returns a valid, non-expired X.509 SVID.
  - If JWT is enabled: verifies `jwtSource.GetJWTBundleSet()` returns a valid bundle set.

### 2. `internal/server/handlers.go`
- Update `HandleHealthz` and `HandleReadyz`:
  - Call `h.spireClient.HealthCheck(r.Context())`.
  - On error: respond with HTTP `503 Service Unavailable` and JSON:
    ```json
    {
      "status": "unhealthy",
      "error": "<error string>"
    }
    ```
  - On success: respond with HTTP `200 OK` and plain text `"ok"`.

### 3. `internal/server/server.go`
- Register `/healthz` and `/readyz` on `metricsMux` (port 9090) as well as `mainMux` (port 8080):
  - Kubelet probes require an HTTP endpoint without client cert (mTLS) requirements.
  - Exposing `/healthz` and `/readyz` on port 9090 ensures Kubernetes probes can query liveness and readiness without TLS errors.

### 4. Helm Chart (`/Users/andy/DEV/Philips/philips-software/helm-charts/charts/centcom-satellite/templates/deployment.yaml`)
- Update container probes:
  - `livenessProbe`: `path: /healthz`, `port: metrics`
  - `readinessProbe`: `path: /readyz`, `port: metrics`
- Remove conditional `{{ if .Values.spire.enabled }}/metrics{{ else }}...` check.

## Testing Strategy
- Add unit tests in `internal/spire/client_test.go` and `internal/server/handlers_test.go` for `HealthCheck` when SPIRE is disabled vs enabled.
- Verify `HandleHealthz` and `HandleReadyz` return 200 when healthy and 503 when unhealthy.
- Execute unit tests using `go test ./...`.
