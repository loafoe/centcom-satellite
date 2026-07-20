# SPIRE Healthz & Readiness Integration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement active SPIFFE/SPIRE health checks in `/healthz` and `/readyz`, expose probe endpoints on the metrics port (9090), and update the Helm chart deployment template to use these endpoints for Kubernetes probes.

**Architecture:** Add `spire.Client.HealthCheck(ctx)` to validate X.509 SVIDs and JWT bundles. Update `HandleHealthz` and `HandleReadyz` in `handlers.go` to invoke `HealthCheck`. Register `/healthz` and `/readyz` handlers on `metricsMux` (port 9090) in addition to `mainMux` (port 8080). Update `templates/deployment.yaml` in the Helm chart to probe port `metrics` at `/healthz` and `/readyz`.

**Tech Stack:** Go 1.23, Kubernetes client-go, Helm 3.

## Global Constraints
- Keep SPIRE health checks non-blocking and safe when SPIRE is disabled (`SPIRE_ENABLED=false`).
- Respond with 503 Service Unavailable when SPIRE check fails, 200 OK when healthy or SPIRE disabled.
- Helm chart located at `/Users/andy/DEV/Philips/philips-software/helm-charts/charts/centcom-satellite`.

---

### Task 1: SPIRE Client `HealthCheck` Method

**Files:**
- Modify: `internal/spire/client.go`
- Test: `internal/spire/client_test.go`

**Interfaces:**
- Produces: `func (c *Client) HealthCheck(ctx context.Context) error`

- [ ] **Step 1: Write failing test for SPIRE HealthCheck**

Add tests in `internal/spire/client_test.go` verifying `HealthCheck`:
- Returns `nil` when `c == nil` or SPIRE is disabled.
- Returns error when SPIRE is enabled but sources (`source` or `jwtSource`) are not initialized or SVID is missing.

```go
func TestClient_HealthCheck_Disabled(t *testing.T) {
	cfg := &Config{Enabled: false}
	client := NewClient(cfg)

	err := client.HealthCheck(context.Background())
	if err != nil {
		t.Fatalf("expected nil error when SPIRE is disabled, got %v", err)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test -v ./internal/spire`
Expected: FAIL due to `client.HealthCheck` undefined.

- [ ] **Step 3: Implement `HealthCheck` in `internal/spire/client.go`**

```go
// HealthCheck checks if SPIRE is healthy (workload API connected and SVID/bundles fetched).
func (c *Client) HealthCheck(ctx context.Context) error {
	if c == nil || !c.config.Enabled {
		return nil
	}

	c.mu.RLock()
	source := c.source
	jwtSource := c.jwtSource
	c.mu.RUnlock()

	if source == nil {
		return fmt.Errorf("SPIRE X509 source not initialized")
	}

	svid, err := source.GetX509SVID()
	if err != nil {
		return fmt.Errorf("SPIRE X509 SVID error: %w", err)
	}
	if svid == nil {
		return fmt.Errorf("SPIRE X509 SVID is nil")
	}

	if c.config.JWT.Enabled {
		if jwtSource == nil {
			return fmt.Errorf("SPIRE JWT source not initialized")
		}
		if _, err := jwtSource.GetJWTBundleSet(); err != nil {
			return fmt.Errorf("SPIRE JWT bundle error: %w", err)
		}
	}

	return nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test -v ./internal/spire`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/spire/client.go internal/spire/client_test.go
git commit -m "feat(spire): add HealthCheck method to spire.Client"
```

---

### Task 2: Server Probe Handlers & Route Registration

**Files:**
- Modify: `internal/server/handlers.go:164-188`
- Modify: `internal/server/server.go:82-90`
- Test: `internal/server/handlers_test.go`

**Interfaces:**
- Consumes: `spireClient.HealthCheck(ctx)`
- Produces: Updated `HandleHealthz` and `HandleReadyz` handlers, plus registration on `metricsMux`.

- [ ] **Step 1: Write failing tests for Healthz & Readyz handlers**

In `internal/server/handlers_test.go`, test `HandleHealthz` and `HandleReadyz`:
- Returns `200 OK` when SPIRE is disabled.
- Returns `503 Service Unavailable` with JSON `{"status":"unhealthy","error":"..."}` when SPIRE health check fails.

```go
func TestHandleHealthz_DisabledSPIRE(t *testing.T) {
	registry := task.NewRegistry()
	metrics := observability.NewMetrics(prometheus.NewRegistry())
	h := NewHandlers(registry, nil, metrics, "v1.0.0", true)

	req := httptest.NewRequest("GET", "/healthz", nil)
	rr := httptest.NewRecorder()

	h.HandleHealthz(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rr.Code)
	}
	if rr.Body.String() != "ok" {
		t.Errorf("expected body 'ok', got %q", rr.Body.String())
	}
}
```

- [ ] **Step 2: Run test to verify initial state**

Run: `go test -v ./internal/server -run TestHandleHealthz`
Expected: PASS for disabled SPIRE.

- [ ] **Step 3: Update `HandleHealthz` and `HandleReadyz` in `internal/server/handlers.go`**

```go
// HandleHealthz handles liveness probe requests.
func (h *Handlers) HandleHealthz(w http.ResponseWriter, r *http.Request) {
	if h.spireClient != nil {
		if err := h.spireClient.HealthCheck(r.Context()); err != nil {
			slog.Warn("healthz probe failed", "error", err)
			h.writeJSON(w, http.StatusServiceUnavailable, map[string]string{
				"status": "unhealthy",
				"error":  err.Error(),
			})
			return
		}
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

// HandleReadyz handles readiness probe requests.
func (h *Handlers) HandleReadyz(w http.ResponseWriter, r *http.Request) {
	if h.spireClient != nil {
		if err := h.spireClient.HealthCheck(r.Context()); err != nil {
			slog.Warn("readyz probe failed", "error", err)
			h.writeJSON(w, http.StatusServiceUnavailable, map[string]string{
				"status": "unhealthy",
				"error":  err.Error(),
			})
			return
		}
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}
```

- [ ] **Step 4: Register probe endpoints on `metricsMux` in `internal/server/server.go`**

In `internal/server/server.go`:
```go
	// Metrics server
	metricsMux := http.NewServeMux()
	metricsMux.Handle("/metrics", promhttp.Handler())
	metricsMux.HandleFunc("/healthz", s.handlers.HandleHealthz)
	metricsMux.HandleFunc("/readyz", s.handlers.HandleReadyz)
```

- [ ] **Step 5: Run all server package unit tests**

Run: `go test -v ./internal/server`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add internal/server/handlers.go internal/server/server.go internal/server/handlers_test.go
git commit -m "feat(server): check SPIRE health in /healthz and /readyz, register on metrics port"
```

---

### Task 3: Helm Chart Deployment Template Update

**Files:**
- Modify: `/Users/andy/DEV/Philips/philips-software/helm-charts/charts/centcom-satellite/templates/deployment.yaml:146-161`

- [ ] **Step 1: Update `livenessProbe` and `readinessProbe` in `deployment.yaml`**

In `/Users/andy/DEV/Philips/philips-software/helm-charts/charts/centcom-satellite/templates/deployment.yaml`:

Replace lines 146-161:
```yaml
          livenessProbe:
            httpGet:
              path: /healthz
              port: metrics
            initialDelaySeconds: 5
            periodSeconds: 10
            timeoutSeconds: 3
            failureThreshold: 3
          readinessProbe:
            httpGet:
              path: /readyz
              port: metrics
            initialDelaySeconds: 3
            periodSeconds: 5
            timeoutSeconds: 2
            failureThreshold: 2
```

- [ ] **Step 2: Test Helm chart template rendering**

Run: `helm template centcom-satellite /Users/andy/DEV/Philips/philips-software/helm-charts/charts/centcom-satellite --set spire.enabled=true`
Expected: Rendered manifest contains `path: /healthz` and `path: /readyz` under `livenessProbe` and `readinessProbe` with `port: metrics`.

Run: `helm template centcom-satellite /Users/andy/DEV/Philips/philips-software/helm-charts/charts/centcom-satellite --set spire.enabled=false`
Expected: Rendered manifest contains `path: /healthz` and `path: /readyz` under `livenessProbe` and `readinessProbe` with `port: metrics`.

- [ ] **Step 3: Commit Helm chart changes**

```bash
cd /Users/andy/DEV/Philips/philips-software/helm-charts
git add charts/centcom-satellite/templates/deployment.yaml
git commit -m "fix(helm): update centcom-satellite liveness and readiness probes to use /healthz and /readyz on metrics port"
```
