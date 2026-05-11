# Remove Webhook Auth Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Remove webhook signature auth, keep SPIRE-only with `ALLOW_UNAUTHENTICATED` dev mode.

**Architecture:** Delete webhook package, update config validation to require SPIRE or explicit dev flag, update handlers to check the flag when no SPIRE auth present.

**Tech Stack:** Go, Helm

---

### Task 1: Update Config - Add AllowUnauthenticated, Remove WebhookSecret

**Files:**
- Modify: `internal/config/config.go`
- Modify: `internal/config/config_test.go`

- [ ] **Step 1: Update config_test.go with new validation tests**

Replace the test cases in `TestLoad` to use the new auth model:

```go
func TestLoad(t *testing.T) {
	tests := []struct {
		name    string
		envVars map[string]string
		wantErr bool
	}{
		{
			name: "valid with SPIRE enabled",
			envVars: map[string]string{
				"SPIRE_ENABLED":   "true",
				"SPIRE_TRUST_DOMAINS": "example.org",
				"PORT":            "8080",
				"METRICS_PORT":    "9090",
			},
			wantErr: false,
		},
		{
			name: "valid with allow unauthenticated",
			envVars: map[string]string{
				"ALLOW_UNAUTHENTICATED": "true",
				"PORT":                  "8080",
				"METRICS_PORT":          "9090",
			},
			wantErr: false,
		},
		{
			name: "invalid - no auth configured",
			envVars: map[string]string{
				"PORT":         "8080",
				"METRICS_PORT": "9090",
			},
			wantErr: true,
		},
		{
			name: "same port and metrics port",
			envVars: map[string]string{
				"ALLOW_UNAUTHENTICATED": "true",
				"PORT":                  "8080",
				"METRICS_PORT":          "8080",
			},
			wantErr: true,
		},
		{
			name: "invalid log level",
			envVars: map[string]string{
				"ALLOW_UNAUTHENTICATED": "true",
				"LOG_LEVEL":             "invalid",
			},
			wantErr: true,
		},
		{
			name: "invalid log format",
			envVars: map[string]string{
				"ALLOW_UNAUTHENTICATED": "true",
				"LOG_FORMAT":            "invalid",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			os.Clearenv()
			for k, v := range tt.envVars {
				_ = os.Setenv(k, v)
			}

			cfg, err := Load()
			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if cfg == nil {
				t.Error("expected config, got nil")
			}
		})
	}
}
```

Also update `TestConfigDefaults`:

```go
func TestConfigDefaults(t *testing.T) {
	os.Clearenv()
	_ = os.Setenv("ALLOW_UNAUTHENTICATED", "true")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.Port != 8080 {
		t.Errorf("expected default Port 8080, got %d", cfg.Port)
	}

	if cfg.MetricsPort != 9090 {
		t.Errorf("expected default MetricsPort 9090, got %d", cfg.MetricsPort)
	}

	if cfg.LogLevel != "info" {
		t.Errorf("expected default LogLevel 'info', got %s", cfg.LogLevel)
	}

	if cfg.LogFormat != "json" {
		t.Errorf("expected default LogFormat 'json', got %s", cfg.LogFormat)
	}

	if cfg.OTelServiceName != "pico-agent" {
		t.Errorf("expected default OTelServiceName 'pico-agent', got %s", cfg.OTelServiceName)
	}

	if cfg.AllowUnauthenticated != true {
		t.Error("expected AllowUnauthenticated to be true")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /Users/andy/DEV/Go/pico-agent && go test ./internal/config/... -v`
Expected: FAIL - `AllowUnauthenticated` field doesn't exist

- [ ] **Step 3: Update config.go**

In `Config` struct, remove `WebhookSecret` and add `AllowUnauthenticated`:

```go
type Config struct {
	Port        int
	MetricsPort int
	// Remove: WebhookSecret string
	AllowUnauthenticated bool
	LogLevel             string
	LogFormat            string
	OTelEndpoint         string
	OTelServiceName      string
	SPIRE                spire.Config
	Features             FeaturesConfig
}
```

In `Load()`, remove the `WebhookSecret` line and add:

```go
AllowUnauthenticated: getEnvBool("ALLOW_UNAUTHENTICATED", false),
```

In `Validate()`, replace the webhook secret check:

```go
// Replace this:
// if c.WebhookSecret == "" && !c.SPIRE.Enabled {
//     errs = append(errs, "WEBHOOK_SECRET is required (or enable SPIRE for mTLS auth)")
// }

// With this:
if !c.SPIRE.Enabled && !c.AllowUnauthenticated {
	errs = append(errs, "SPIRE must be enabled or ALLOW_UNAUTHENTICATED must be set to true")
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /Users/andy/DEV/Go/pico-agent && go test ./internal/config/... -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
cd /Users/andy/DEV/Go/pico-agent
git add internal/config/
git commit -m "feat(config): replace WebhookSecret with AllowUnauthenticated

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>"
```

---

### Task 2: Delete Webhook Package

**Files:**
- Delete: `internal/webhook/signature.go`
- Delete: `internal/webhook/signature_test.go`

- [ ] **Step 1: Delete the webhook directory**

```bash
cd /Users/andy/DEV/Go/pico-agent
rm -rf internal/webhook
```

- [ ] **Step 2: Verify build still works (expect failures in dependent files)**

Run: `cd /Users/andy/DEV/Go/pico-agent && go build ./...`
Expected: FAIL - imports of `internal/webhook` will fail in handlers.go, server.go, main.go

- [ ] **Step 3: Commit deletion**

```bash
cd /Users/andy/DEV/Go/pico-agent
git add -A internal/webhook
git commit -m "refactor: delete webhook signature package

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>"
```

---

### Task 3: Update Handlers - Remove Verifier, Add AllowUnauthenticated

**Files:**
- Modify: `internal/server/handlers.go`

- [ ] **Step 1: Update Handlers struct and NewHandlers**

Remove `verifier` field and add `allowUnauthenticated`:

```go
type Handlers struct {
	registry             *task.Registry
	spireClient          *spire.Client
	metrics              *observability.Metrics
	version              string
	allowUnauthenticated bool
}

func NewHandlers(registry *task.Registry, spireClient *spire.Client, metrics *observability.Metrics, version string, allowUnauthenticated bool) *Handlers {
	return &Handlers{
		registry:             registry,
		spireClient:          spireClient,
		metrics:              metrics,
		version:              version,
		allowUnauthenticated: allowUnauthenticated,
	}
}
```

- [ ] **Step 2: Update authenticate() - remove webhook check, add dev mode**

Remove the webhook import and update `authenticate()`:

```go
func (h *Handlers) authenticate(w http.ResponseWriter, r *http.Request, body []byte) authResult {
	ctx := r.Context()

	// 1. Check for mTLS (SPIRE X.509 SVID)
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		slog.Debug("authenticated via mTLS", "remote_addr", r.RemoteAddr)
		return authResult{authenticated: true}
	}

	// 2. Check for JWT-SVID in Authorization header
	if h.spireClient != nil && h.spireClient.IsJWTEnabled() {
		authHeader := r.Header.Get("Authorization")
		if strings.HasPrefix(authHeader, "Bearer ") || strings.HasPrefix(authHeader, "bearer ") {
			spiffeID, err := h.spireClient.ValidateJWTToken(ctx, authHeader)
			if err != nil {
				slog.Warn("JWT-SVID validation failed", "error", err, "remote_addr", r.RemoteAddr)
				h.writeError(w, http.StatusUnauthorized, "invalid JWT-SVID")
				return authResult{rejected: true}
			}
			slog.Debug("authenticated via JWT-SVID", "spiffe_id", spiffeID.String(), "remote_addr", r.RemoteAddr)
			return authResult{authenticated: true}
		}
	}

	// 3. Dev mode - allow unauthenticated if configured
	if h.allowUnauthenticated {
		slog.Debug("allowing unauthenticated request (dev mode)", "remote_addr", r.RemoteAddr)
		return authResult{authenticated: true}
	}

	return authResult{}
}
```

- [ ] **Step 3: Remove webhook import**

Remove from imports:
```go
// Remove this line:
// "github.com/loafoe/pico-agent/internal/webhook"
```

- [ ] **Step 4: Verify handlers.go compiles**

Run: `cd /Users/andy/DEV/Go/pico-agent && go build ./internal/server/`
Expected: FAIL - server.go still references old signature

- [ ] **Step 5: Commit**

```bash
cd /Users/andy/DEV/Go/pico-agent
git add internal/server/handlers.go
git commit -m "refactor(handlers): remove webhook verifier, add allowUnauthenticated

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>"
```

---

### Task 4: Update Server - Remove Verifier Parameter

**Files:**
- Modify: `internal/server/server.go`

- [ ] **Step 1: Update New() function signature**

```go
func New(cfg Config, registry *task.Registry, metrics *observability.Metrics, spireClient *spire.Client, version string, allowUnauthenticated bool) *Server {
	handlers := NewHandlers(registry, spireClient, metrics, version, allowUnauthenticated)

	return &Server{
		config:      cfg,
		handlers:    handlers,
		metrics:     metrics,
		spireClient: spireClient,
		version:     version,
	}
}
```

- [ ] **Step 2: Remove webhook import**

Remove from imports:
```go
// Remove this line:
// "github.com/loafoe/pico-agent/internal/webhook"
```

- [ ] **Step 3: Verify server package compiles**

Run: `cd /Users/andy/DEV/Go/pico-agent && go build ./internal/server/`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
cd /Users/andy/DEV/Go/pico-agent
git add internal/server/server.go
git commit -m "refactor(server): remove webhook verifier parameter

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>"
```

---

### Task 5: Update Main - Remove Webhook, Add Warning

**Files:**
- Modify: `cmd/pico-agent/main.go`

- [ ] **Step 1: Remove webhook import and verifier creation**

Remove from imports:
```go
// Remove this line:
// "github.com/loafoe/pico-agent/internal/webhook"
```

Remove the verifier creation block (around lines 151-154):
```go
// Remove these lines:
// var verifier *webhook.Verifier
// if cfg.WebhookSecret != "" {
//     verifier = webhook.NewVerifier(cfg.WebhookSecret)
// }
```

- [ ] **Step 2: Update server.New() call**

```go
srv := server.New(
	server.Config{
		Port:        cfg.Port,
		MetricsPort: cfg.MetricsPort,
	},
	registry,
	metrics,
	spireClient,
	Version,
	cfg.AllowUnauthenticated,
)
```

- [ ] **Step 3: Add startup warning for dev mode**

After loading config, add:

```go
if cfg.AllowUnauthenticated {
	slog.Warn("running without authentication - development mode only")
}
```

- [ ] **Step 4: Verify full build and tests pass**

Run: `cd /Users/andy/DEV/Go/pico-agent && go build ./... && go test ./... -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
cd /Users/andy/DEV/Go/pico-agent
git add cmd/pico-agent/main.go
git commit -m "refactor(main): remove webhook, add unauthenticated warning

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>"
```

---

### Task 6: Update Helm Chart - Remove Webhook Resources

**Files:**
- Delete: `/Users/andy/DEV/Personal/helm-charts/charts/pico-agent/templates/secret.yaml`
- Delete: `/Users/andy/DEV/Personal/helm-charts/charts/pico-agent/templates/secret-init-job.yaml`
- Modify: `/Users/andy/DEV/Personal/helm-charts/charts/pico-agent/templates/_helpers.tpl`

- [ ] **Step 1: Delete secret templates**

```bash
rm /Users/andy/DEV/Personal/helm-charts/charts/pico-agent/templates/secret.yaml
rm /Users/andy/DEV/Personal/helm-charts/charts/pico-agent/templates/secret-init-job.yaml
```

- [ ] **Step 2: Remove helper functions from _helpers.tpl**

Remove these template definitions from `_helpers.tpl`:
- `pico-agent.secretName`
- `pico-agent.createSecret`
- `pico-agent.needsInitJob`

The file should end after `pico-agent.serviceAccountName`.

- [ ] **Step 3: Commit**

```bash
cd /Users/andy/DEV/Personal/helm-charts
git add charts/pico-agent/templates/
git commit -m "refactor(pico-agent): remove webhook secret templates

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>"
```

---

### Task 7: Update Helm Chart - values.yaml and deployment.yaml

**Files:**
- Modify: `/Users/andy/DEV/Personal/helm-charts/charts/pico-agent/values.yaml`
- Modify: `/Users/andy/DEV/Personal/helm-charts/charts/pico-agent/templates/deployment.yaml`

- [ ] **Step 1: Update values.yaml**

Remove the `webhook` section (lines 15-21):
```yaml
# Remove:
# webhook:
#   secret: ""
#   existingSecret: ""
```

Remove the `initJob` section (lines 171-180):
```yaml
# Remove:
# initJob:
#   image:
#     repository: bitnami/kubectl
#     tag: latest
#     pullPolicy: IfNotPresent
#   resources:
#     ...
```

Change `spire.enabled` default from `false` to `true`:
```yaml
spire:
  enabled: true
```

- [ ] **Step 2: Update deployment.yaml**

Remove the WEBHOOK_SECRET env var block (lines 51-57):
```yaml
# Remove:
# {{- if not .Values.spire.enabled }}
# - name: WEBHOOK_SECRET
#   valueFrom:
#     secretKeyRef:
#       name: {{ include "pico-agent.secretName" . }}
#       key: secret
# {{- end }}
```

- [ ] **Step 3: Verify Helm template renders**

```bash
cd /Users/andy/DEV/Personal/helm-charts
helm template test charts/pico-agent --set spire.trustDomains[0]=example.org
```
Expected: Valid YAML output without webhook references

- [ ] **Step 4: Commit**

```bash
cd /Users/andy/DEV/Personal/helm-charts
git add charts/pico-agent/
git commit -m "refactor(pico-agent): remove webhook config, default spire.enabled=true

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>"
```

---

### Task 8: Update Helm Chart - NOTES.txt

**Files:**
- Modify: `/Users/andy/DEV/Personal/helm-charts/charts/pico-agent/templates/NOTES.txt`

- [ ] **Step 1: Rewrite NOTES.txt for SPIRE-only auth**

```
Thank you for installing {{ .Chart.Name }}!

Your release is named: {{ .Release.Name }}

Endpoint URL (from within the cluster):
  http://{{ include "pico-agent.fullname" . }}.{{ .Release.Namespace }}.svc.cluster.local:{{ .Values.service.port }}/task

Authentication:
  This deployment uses SPIFFE/SPIRE for workload identity authentication.
{{- if .Values.spire.mtlsEnabled }}
  Mode: mTLS (X.509 SVID)
{{- else if .Values.spire.jwt.enabled }}
  Mode: JWT-SVID
  Audiences: {{ .Values.spire.jwt.audiences | join ", " }}
{{- else }}
  Mode: SPIRE enabled (configure mTLS or JWT as needed)
{{- end }}
{{- if .Values.spire.trustDomains }}
  Trust domains: {{ .Values.spire.trustDomains | join ", " }}
{{- end }}
{{- if .Values.spire.allowedSPIFFEIDs }}
  Allowed SPIFFE IDs: {{ .Values.spire.allowedSPIFFEIDs | join ", " }}
{{- end }}

Example payload for PV resize:
{
  "type": "pv_resize",
  "payload": {
    "namespace": "default",
    "pvc_name": "my-pvc",
    "new_size": "20Gi"
  }
}

To verify the installation:
  kubectl get pods -n {{ .Release.Namespace }} -l "app.kubernetes.io/name={{ include "pico-agent.name" . }},app.kubernetes.io/instance={{ .Release.Name }}"

For more information, visit: https://github.com/loafoe/pico-agent
```

- [ ] **Step 2: Commit**

```bash
cd /Users/andy/DEV/Personal/helm-charts
git add charts/pico-agent/templates/NOTES.txt
git commit -m "docs(pico-agent): update NOTES.txt for SPIRE-only auth

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>"
```

---

### Task 9: Update CLAUDE.md and Bump Versions

**Files:**
- Modify: `/Users/andy/DEV/Go/pico-agent/CLAUDE.md`
- Modify: `/Users/andy/DEV/Personal/helm-charts/charts/pico-agent/Chart.yaml`

- [ ] **Step 1: Update CLAUDE.md**

Remove `WEBHOOK_SECRET` from the Configuration section. Update the Development section to use `ALLOW_UNAUTHENTICATED`:

```markdown
## Development

```bash
# Run tests
make test

# Run locally (requires kubeconfig)
export ALLOW_UNAUTHENTICATED=true
go run ./cmd/pico-agent

# Send test request (no signature needed in dev mode)
curl -X POST http://localhost:8080/task \
  -H "Content-Type: application/json" \
  -d '{"type":"cluster_info","payload":{}}'
```
```

Update version to v0.9.0.

- [ ] **Step 2: Update Helm Chart.yaml version**

Bump `version` and `appVersion` to 0.9.0.

- [ ] **Step 3: Commit**

```bash
cd /Users/andy/DEV/Go/pico-agent
git add CLAUDE.md
git commit -m "docs: update CLAUDE.md for SPIRE-only auth

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>"
```

```bash
cd /Users/andy/DEV/Personal/helm-charts
git add charts/pico-agent/Chart.yaml
git commit -m "chore(pico-agent): bump version to 0.9.0

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>"
```

---

### Task 10: Final Verification

- [ ] **Step 1: Run full test suite**

```bash
cd /Users/andy/DEV/Go/pico-agent
go test ./... -v
```
Expected: All tests pass

- [ ] **Step 2: Test local dev mode**

```bash
cd /Users/andy/DEV/Go/pico-agent
ALLOW_UNAUTHENTICATED=true go run ./cmd/pico-agent &
sleep 2
curl -s http://localhost:8080/task -X POST -H "Content-Type: application/json" -d '{"type":"cluster_info","payload":{}}'
kill %1
```
Expected: Response (may fail due to no k8s, but auth should pass)

- [ ] **Step 3: Verify Helm chart**

```bash
cd /Users/andy/DEV/Personal/helm-charts
helm lint charts/pico-agent
helm template test charts/pico-agent --set spire.trustDomains[0]=example.org | head -100
```
Expected: No errors, valid YAML
