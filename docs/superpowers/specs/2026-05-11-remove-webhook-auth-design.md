# Remove Webhook Auth, SPIRE-Only Authentication

**Date:** 2026-05-11  
**Status:** Approved

## Summary

Remove webhook signature (HMAC-SHA256) authentication from centcom-satellite. The agent will authenticate via SPIRE (mTLS or JWT-SVID) in production, with an explicit `ALLOW_UNAUTHENTICATED` env var for local development.

## Motivation

The codebase currently supports three auth modes: webhook signature, SPIRE mTLS, and SPIRE JWT-SVID. We want to standardize on SPIFFE/SPIRE for workload identity, removing the legacy webhook approach to simplify the codebase and reduce attack surface.

## Design

### Authentication Flow (After Change)

```
Request arrives
    │
    ├─► mTLS present? ──yes──► Authenticated (SPIRE X.509 SVID)
    │
    ├─► JWT Bearer token? ──yes──► Validate JWT-SVID
    │                                 │
    │                                 ├─► Valid ──► Authenticated
    │                                 └─► Invalid ──► 401 Unauthorized
    │
    └─► No credentials
            │
            ├─► AllowUnauthenticated=true ──► Allowed (dev mode)
            └─► AllowUnauthenticated=false ──► 401 Unauthorized
```

### Code Changes

#### Delete

| Path | Reason |
|------|--------|
| `internal/webhook/signature.go` | Webhook auth removed |
| `internal/webhook/signature_test.go` | Tests for removed code |

#### Modify: `internal/config/config.go`

- Remove `WebhookSecret string` field from `Config` struct
- Add `AllowUnauthenticated bool` field to `Config` struct
- Update `Load()`:
  - Remove `WEBHOOK_SECRET` env var handling
  - Add `ALLOW_UNAUTHENTICATED` env var (default: false)
- Update `Validate()`:
  - Remove webhook secret validation
  - Add rule: fail if `!SPIRE.Enabled && !AllowUnauthenticated`

#### Modify: `internal/server/handlers.go`

- Remove `verifier *webhook.Verifier` field from `Handlers` struct
- Remove `verifier` parameter from `NewHandlers()`
- Remove `"github.com/loafoe/centcom-satellite/internal/webhook"` import
- Update `authenticate()`:
  - Remove webhook signature verification block (lines 71-83)
  - Add `allowUnauthenticated bool` field to `Handlers` or pass via config
  - When no auth method succeeds: check `allowUnauthenticated` flag

#### Modify: `internal/server/server.go`

- Remove `verifier *webhook.Verifier` parameter from `New()`
- Remove `"github.com/loafoe/centcom-satellite/internal/webhook"` import
- Pass `allowUnauthenticated` config to handlers

#### Modify: `cmd/centcom-satellite/main.go`

- Remove `"github.com/loafoe/centcom-satellite/internal/webhook"` import
- Remove verifier creation block (lines 151-154)
- Remove `verifier` from `server.New()` call
- Add startup warning when `AllowUnauthenticated` is true:
  ```
  slog.Warn("running without authentication - development mode only")
  ```

### Helm Chart Changes

#### Delete

| Path | Reason |
|------|--------|
| `templates/secret.yaml` | Webhook secret no longer used |
| `templates/secret-init-job.yaml` | Secret auto-generation no longer needed |

#### Modify: `templates/_helpers.tpl`

Remove these template functions:
- `centcom-satellite.secretName`
- `centcom-satellite.createSecret`
- `centcom-satellite.needsInitJob`

#### Modify: `values.yaml`

Remove:
```yaml
webhook:
  secret: ""
  existingSecret: ""

initJob:
  image:
    repository: bitnami/kubectl
    tag: latest
    pullPolicy: IfNotPresent
  resources:
    ...
```

Change default:
```yaml
spire:
  enabled: true  # was: false
```

#### Modify: `templates/deployment.yaml`

Remove the webhook secret env var block (lines 51-57):
```yaml
{{- if not .Values.spire.enabled }}
- name: WEBHOOK_SECRET
  valueFrom:
    secretKeyRef:
      name: {{ include "centcom-satellite.secretName" . }}
      key: secret
{{- end }}
```

The SPIRE env vars remain but the conditional can be simplified since spire.enabled now defaults to true.

#### Modify: `templates/NOTES.txt`

Update to remove webhook secret references and document SPIRE-only auth.

### Configuration

#### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SPIRE_ENABLED` | false | Enable SPIRE authentication |
| `ALLOW_UNAUTHENTICATED` | false | Allow requests without auth (dev only) |

**Removed:** `WEBHOOK_SECRET`

#### Validation Matrix

| SPIRE Enabled | AllowUnauthenticated | Result |
|---------------|---------------------|--------|
| true | any | OK - SPIRE auth enforced |
| false | true | OK - Warning logged, no auth |
| false | false | ERROR - Startup fails |

### Breaking Changes

1. `WEBHOOK_SECRET` env var no longer recognized (ignored, not error)
2. Helm values removed: `webhook.secret`, `webhook.existingSecret`, `initJob.*`
3. Helm chart now defaults to `spire.enabled: true`
4. Deployments without SPIRE must explicitly set `ALLOW_UNAUTHENTICATED=true`

### Migration Path

**For SPIRE users:** No changes needed. Continue using SPIRE mTLS or JWT-SVID.

**For webhook users:** 
1. Deploy SPIRE infrastructure
2. Configure `spire.enabled=true` with appropriate trust domains and allowed SPIFFE IDs
3. Update clients to use SPIRE workload identity instead of HMAC signatures

**For local development:**
```bash
export ALLOW_UNAUTHENTICATED=true
go run ./cmd/centcom-satellite
```

## Testing

- Verify SPIRE mTLS authentication still works
- Verify SPIRE JWT-SVID authentication still works
- Verify unauthenticated requests rejected when `ALLOW_UNAUTHENTICATED=false`
- Verify unauthenticated requests allowed when `ALLOW_UNAUTHENTICATED=true`
- Verify startup fails when neither SPIRE nor `ALLOW_UNAUTHENTICATED` configured
- Verify Helm chart deploys successfully with new defaults
