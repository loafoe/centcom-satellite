# Security Review — centcom-satellite

**Scope:** Full source review — `internal/server`, `internal/spire`, `internal/aws`, `internal/k8s`, `internal/observability`, `internal/config`, `cmd/centcom-satellite`, all 60+ task packages, `deploy/` IAM policies, `.github/workflows`, `.ko.yaml`, plus a `govulncheck` run.
**Date:** 2026-11-12
**Version reviewed:** working tree @ `3572c32` (post-v0.62.0)
**Method:** manual code review + `go vet` (clean) + `govulncheck` (1 stdlib finding)

**Status update (same day):** F-1, F-3, F-5 and F-14 are **remediated** — see the "Status: REMEDIATED" notes on each. Full suite (`go test -race ./...`, 66 packages), `go vet`, and `govulncheck` are clean after the fixes. Remaining open findings: F-2, F-4, F-6 through F-13, F-15.

---

## Executive Summary

Overall this is a **well-hardened codebase**. The security posture shows deliberate, repeated attention: feature-flag gating of every write capability, a defense-in-depth Secret denylist, an SSRF-guarded `http_request` dialer, DNS-rebinding protection, per-IP rate limiting with spoofing-resistant `RemoteAddr` keying, body-size caps, bounded cardinality on all metric labels, distroless/nonroot images, and keyless cosign signing in CI. Several recent commits (`88501ae`, `6929450`) closed genuinely subtle attack paths (SSRF redirect-chasing, dependency CVEs).

That said, the review found **5 Medium**, **6 Low**, and **5 informational** findings, plus one patch-level CVE in the toolchain. None are critical. The most significant themes:

1. ~~**`connectivity_test` is an unthrottled SSRF primitive**~~ **(remediated)** — the task now enforces the same cluster-internal address guard as `http_request`, via the new shared `internal/clusteraddr` package.
2. **Unauthenticated `/healthz`, `/readyz`, `/info` on both servers** — the metrics server binding `:9090` with no auth is the standard concern, and `/info` leaks JWT audiences to anyone. (The healthz/readyz *error-detail* leak is fixed; the `/info` disclosure and metrics-server exposure remain open.)
3. **Plain-HTTP default** makes the SPIFFE story only as strong as the network layer in JWT-only deployments.
4. **Dependency drift** — `go-spiffe/v2` v2.7.0 is several minor versions behind (v2.9.0 current), and ~~Go 1.27.3 is one patch below the fix for GO-2026-6859~~ **(Go bumped to 1.27.4; govulncheck clean)**.

Findings are ordered by severity within each section.

---

## Findings

### F-1 — MEDIUM — SSRF: `connectivity_test` probes arbitrary TCP endpoints with no address guard — **Status: REMEDIATED**

> **Remediation (2026-11-12):** the cluster-internal allowlist and guarded dialer were extracted into a new shared package, **`internal/clusteraddr`**, and `connectivity_test` now enforces them on both its TCP and HTTP paths: the `GuardDialer` `Control` hook rejects non-cluster IPs (RFC1918 + RFC 6598) on the address actually connected to (covers DNS rebinding), HTTP targets get `Proxy: nil` + `CheckRedirect: ErrUseLastResponse` (no redirect-chasing to metadata/internet), and the scheme check was hardened to `http`/`https` only. `http_request` was refactored onto the same shared package, so the two tasks can never drift apart. New tests lock the contract in: `TestGuardDialerBlocksNonCluster` (metadata service, ECS credentials endpoint, loopback, public internet, public DNS names all refused), `TestTask_Execute_HTTPRedirectNotFollowed`, and `TestTask_Execute_GuardBlocksNonClusterTargets`. The README task table was updated to advertise the guard.

*Original finding (for the record):*

`internal/task/connectivity_test/task.go` — `testTCP` (`:117`) called `t.dialer(ctx, "tcp", target)` with the raw caller-supplied `target` and **no IP-range restriction whatsoever**. `testHTTP` (`:141`) likewise accepted any URL scheme `http://`/`https://` and followed redirects (default `http.Client`, `CheckRedirect` unset).

This is a textbook SSRF primitive:

- **Cloud metadata service**: `{"target": "169.254.169.254:80"}` → confirms reachability of the node/pod IMDS endpoint (a pre-requisite for credential theft on clusters without IMDSv2 hop limits).
- **Internal network mapping**: port-scan arbitrary in-cluster and VPC hosts (`10.0.x.x:22`, `10.0.x.x:6379`, …) with a boolean success/fail oracle plus RTT.
- **Internet exfiltration channel**: connect to attacker-controlled external hosts (a blind but effective "is this pod egress-restricted?" oracle).

Contrast with `http_request` (`internal/task/http_request/task.go`), which was **specifically fixed for this class of bug** (commit `6929450`: "http_request only ever connects to cluster addresses") — dual-layer protection with a `Control` dialer hook rejecting non-RFC1918/100.64 addresses, and `CheckRedirect: http.ErrUseLastResponse`. `connectivity_test` got none of that.

**Impact:** Network reconnaissance from a privileged pod position; reachable-IMDS oracle for credential-theft pre-work; internal service discovery.
**Recommendation:** Apply the same `isClusterIP`-guarded dialer (or at minimum a deny-list for link-local/loopback/metadata IPs) from `http_request` to `connectivity_test`'s TCP and HTTP paths; consider whether the "test from inside the cluster" use case genuinely needs unrestricted targets. Reuse `newGuardedClient`'s `Control` hook verbatim.

---

### F-2 — MEDIUM — Unauthenticated endpoints on the metrics server; `:9090` binds all interfaces with no auth of any kind

`internal/server/server.go:86-108`: the metrics mux serves `/metrics`, `/healthz`, `/readyz` with **no authentication middleware at all** — not even the `allowUnauthenticated=false` rejection the main server applies to unauthenticated callers. There is no way to disable this: the metrics server always starts, always binds `:PORT` on all interfaces.

Prometheus content here is information-dense: per-task execution counts and durations (`centcom_satellite_tasks_total`), auth-attempt breakdowns by method and result (`auth_attempts_total` — an attacker can watch failed-JWT-rejection counters climb as they probe), log-stream counts, k8s API verb/resource usage, and build version. On a cluster without a strict NetworkPolicy for port 9090, **any pod or node-level process can read all of it**.

Mitigating factor: standard practice is a NetworkPolicy limiting 9090 to the Prometheus scraper; the chart may already do this (not verifiable from this repo). The finding stands because the *code* imposes no floor.

**Recommendation:** (a) bind the metrics server to a configurable address (default remains `:9090`, operators can set `127.0.0.1:9090`); (b) if the deploy model allows it, require an optional bearer token on `/metrics`; (c) at minimum, document the NetworkPolicy requirement next to `METRICS_PORT` in the chart's values.

---

### F-3 — MEDIUM — `/healthz`, `/readyz`, `/info` are unauthenticated on the *main* server too — **Status: PARTIALLY REMEDIATED (error-detail leak fixed; `/info` unchanged)**

> **Remediation (2026-11-12):** `HandleHealthz`/`HandleReadyz` now return a fixed, detail-free message (`"health check failed"`) to unauthenticated callers; the specific SPIRE failure text goes to server-side logs only. Tests were updated to assert the fixed message and explicitly assert that no SPIRE internals leak. The remaining parts of this finding — `/info` disclosure and the rate-limit exemption on the probes — are **still open** and fall under the original recommendation below.

`internal/server/handlers.go:181-228`:

- `HandleHealthz` / `HandleReadyz` — no auth check, by design for kubelet probes. The error path (`writeJSON 503` with `err.Error()`) **leaked SPIRE health-check internals** (e.g. "SPIRE X509 source not initialized", bundle fetch failure details) to unauthenticated callers. Minor, but it's free reconnaissance about the auth backend's state.
- `HandleInfo` — deliberately unauthenticated, returns configured JWT audiences. The comment explains why (callers need the audiences to request tokens), and audiences alone are low-value. **But combined with F-1's port-scan oracle and this disclosure, an attacker learns exactly which auth mode and trust-domain posture a satellite runs** — useful targeting data for a fleet-wide campaign.

Rate limiting exempts `/healthz` and `/readyz` entirely (correct, kubelet would otherwise kill the pod) — which also means those endpoints are an **unlimited-bandwidth CPU-pressure vector**: unauthenticated, no rate limit, each triggers a live `spireClient.HealthCheck()` (which for mTLS mode does `GetX509SVID()` and for JWT mode iterates trust domains fetching bundles). `HandleInfo` is rate-limited but unauthenticated.

**Recommendation:** Keep the probes unauthenticated but truncate the error message in the 503 body to a fixed string (log the detail server-side). Consider whether `/info` should be behind auth (the comment's justification is reasonable, but it's worth re-examining now that it also implies "this satellite is probeable").

---

### F-4 — MEDIUM — Dependency drift: `go-spiffe/v2` v2.7.0 (v2.9.0 current); no update policy for auth-critical deps

`go.mod:23` pins `github.com/spiffe/go-spiffe/v2 v2.7.0` — the entire security model of the service. The module cache shows v2.8.0 through v2.9.0 present locally; the repo is on v2.7.0. This review checked the v2.7.0 federation-fetch source directly (see F-5) and found the relevant code sound, but:

- There is no Dependabot/Renovate config in-repo (`.github/dependabot.yml` absent).
- The CI runs `go test` + `golangci-lint` but **no scheduled dependency or vuln scan job**.

Given that the caller-authentication path is the single most attack-relevant code in this service, dependency drift here is qualitatively different from drift in a metrics library.

**Recommendation:** Add Dependabot with grouped minor/patch updates for `go-spiffe/v2` specifically; add a scheduled `govulncheck ./...` job that opens an issue on findings. Bump to v2.9.0 as part of the fix.

---

### F-5 — MEDIUM — CVE in toolchain: GO-2026-6859 (net/http MaxBytesReader race, fixed in Go 1.27.4) — **Status: REMEDIATED**

> **Remediation (2026-11-12):** `go.mod` bumped `go 1.27.3` → `go 1.27.4`; the full suite was rebuilt and re-run on the new toolchain, and a fresh `govulncheck ./...` reports **"No vulnerabilities found."** CI uses `go-version-file: go.mod`, so the bump propagates to CI automatically.

`govulncheck ./...` reported:

```
Vulnerability #1: GO-2026-6859
  HTTP/1 server crash due to MaxBytesReader header race in net/http
  Found in: net/http@go1.27.3
  Fixed in: net/http@go1.27.4
```

`go.mod:3` was `go 1.27.3`, toolchain 1.27.3. The vulnerability is a **server crash** (DoS) via the `http.MaxBytesReader` header race — directly reachable from every unauthenticated connection to the main or metrics server. Note the handlers use `io.LimitReader` (not `MaxBytesReader`), but the affected code is in the stdlib `net/http` machinery reachable via the normal request path (traces #19–#21 point at `server.go`'s `ListenAndServe`/`Serve`).

**Recommendation (done):** Bump Go toolchain to 1.27.4+ in `go.mod` and CI's `go-version-file` (already reads go.mod, so the bump propagates). Low-effort, eliminates the only concrete CVE found.

---

### F-6 — LOW — Authentication method confusion: any client certificate, no `spire` check in `authenticate`

`internal/server/handlers.go:52-57` and `handlers_stream.go:48-53`:

```go
if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
    h.metrics.RecordAuthAttempt("mtls", "success")
    return authResult{authenticated: true}
}
```

The mTLS branch trusts `r.TLS.PeerCertificates` presence alone. In the normal deployment this is safe — the TLS listener is only ever constructed by `spireClient.WrapListener` with `tlsconfig.MTLSServerConfig`, which enforces SPIFFE validation via `VerifyPeerCertificate` + `ClientAuth = RequireAnyClientCert` + the wrapped authorizer (verified: go-spiffe v2.7.0 `spiffetls/tlsconfig/config.go` — `WrapVerifyPeerCertificate` runs `x509svid.ParseAndVerify` then `authorizer`, and only then the satellite's own allowed-IDs hook).

However, if the deployment model ever changes — e.g. TLS terminated at an ingress that re-encrypts with its own client cert, or a future refactor adds a non-SPIRE TLS listener — this check is **presentation-of-any-cert = full auth**, with no defense-in-depth check that the SVID belongs to a configured trust domain.

**Recommendation:** In the mTLS branch, additionally parse the leaf cert's URI SAN and run the same `IsIDAllowed`/`IsTrustDomainAllowed` checks the JWT path enforces (the custom `VerifyPeerCertificate` already does this for SPIRE-listener connections — this would make the *handler* self-sufficient rather than relying on the listener configuration). Cheap, removes an architectural coupling.

---

### F-7 — LOW — Plain-HTTP default mode: JWT-SVID bearer tokens transit unencrypted

`internal/server/server.go:122-128` (`startPlain`) runs the main server on plain HTTP whenever SPIRE mTLS is disabled — including the legitimate JWT-only + gateway-TLS pattern documented in AGENTS.md, and the `SPIRE_JWT_BUNDLE_SOURCE=federation` ECS/Fargate mode.

When a deployment runs `startPlain` **without** a TLS-terminating gateway in front (misconfiguration, or a dev/staging port accidentally exposed), bearer JWT-SVIDs are sent in cleartext and are trivially interceptable. `config.Validate()` accepts this silently: `SPIRE_ENABLED=true, SPIRE_MTLS_ENABLED=false, SPIRE_JWT_ENABLED=true` with no enforcement of "there must be TLS somewhere."

**Recommendation:** Not a code change so much as an operational guardrail: log a prominent warning at startup when JWT auth is enabled and the server is plain-HTTP ("bearer tokens will transit unencrypted unless TLS terminates upstream"); consider an env var like `REQUIRE_UPSTREAM_TLS` that makes the satellite refuse to start otherwise, for deployments that know they're behind an ALB.

---

### F-8 — LOW — `dns_check` hostname resolution reflects caller-supplied DNS queries (mild blind-SSRF/amplification surface)

`internal/task/dns_check/task.go:58` — always registered, accepts any hostname, resolves via `net.DefaultResolver.LookupHost` (5s timeout), and returns the resolved addresses and error text to the caller. No restriction on hostname (can be any external domain), no cap on result count.

Value-wise this is much weaker than F-1 (no connection, just resolution), but it does provide: (a) an internal-DNS-view oracle (resolving attacker-chosen names through the pod's resolver, useful to probe `*.svc.cluster.local` names); (b) error-message-based DNS recon (`SERVFAIL` vs `NXDOMAIN` distinctions leak resolver configuration).

**Recommendation:** Low priority. Consider restricting to cluster-internal suffixes (`.svc.cluster.local`, `.svc`, single-label) or at least suppressing detailed error messages for external hostnames.

---

### F-9 — LOW — `isCRDNotInstalled` / error-string matching is brittle; `grep`-style heuristics can mis-bucket real API errors

`internal/task/nodeclaim_delete/task.go` (and the same `strings.Contains(errStr, "the server could not find the requested resource")` pattern elsewhere):

```go
func isCRDNotInstalled(err error) bool {
	errStr := err.Error()
	return strings.Contains(errStr, "the server could not find the requested resource") ||
		strings.Contains(errStr, "no matches for kind")
}
```

This is not a direct vuln, but it's a **correctness-of-security-decision** issue: classification of "CRD absent" vs "genuine API error" is based on substring matching of error text, which can change across Kubernetes versions. If a future apiserver rephrases the message, a real failure could be reported as a benign `ErrCRDNotInstalled`, or vice versa.

**Recommendation:** Prefer `apierrors.IsNotFound(err)` / `meta.IsNoMatchError(err)` / `runtime.IsNotRegisteredError(err)` typed checks (the code already imports `apierrors` for the NotFound path — just extend it).

---

### F-10 — LOW — `/logs/stream` leak risk: all namespaces' pod logs reachable by any authenticated caller

`internal/server/handlers_stream.go:88-230` — the log-stream endpoint takes an arbitrary `namespace`/`pod`, so any caller passing the single-satellite auth check can follow logs of any pod in the cluster (RBAC permitting at the service-account level, which the chart grants `pods/log get` cluster-wide per the base role). This matches the design (single-privileged-credential, all callers equal), but it concentrates blast radius: log contents across all namespaces (secrets-in-logs included) are one `curl` away for any trusted SPIFFE ID in the allowlist.

This is a design trade-off, not a bug — but worth surfacing in a security review because the allowlist (`SPIRE_ALLOWED_SPIFFE_IDS`) is the *only* authorization boundary between a caller and every pod's logs.

**Recommendation:** Consider a per-caller authorization concept if the fleet ever grows (e.g. map SPIFFE ID → allowed namespaces); at minimum, document in AGENTS.md that `pods/log get` is cluster-scoped and that the allowlist is the sole control. Secrets-in-logs is worth a periodic reminder to operators: anything a workload prints is retrievable here.

---

### F-11 — LOW — Retryable write paths: no idempotency guards on mutating tasks

Write tasks (`workload_restart`, `pod_evict`, `nodeclaim_delete`, `pv_resize`, `helm_application_*`, `securityhub_update_findings`, `workload_scale`, `pod_resize`) perform their mutation with no client-supplied idempotency token. A caller that times out and retries the same payload re-triggers the mutation (e.g. double PVC resize → size inflation, double eviction → two pods churned instead of one, double NodeClaim delete → node recycling twice).

For an AI-agent-driven caller (pico-mcp, per the docs) retry-on-timeout is an expected failure mode. The tasks are individually small and mostly idempotent *in effect*, but not *in cost* (double restarts are visible to users; the PVC task's `new size must be larger` check does make double-resize fail safely — good).

**Recommendation:** Not urgent. If agent-driven retries become an operational problem, add an optional `idempotency_key` to write payloads, deduped in-process with a short TTL, or lean on the existing `DryRun` flag pattern for agent workflows.

---

### F-12 — INFO — Federation bundle endpoint URLs are not scheme-validated

`internal/spire/federation_source.go:101-107` and `config.go`: `SPIRE_FEDERATION_BUNDLE_ENDPOINTS` entries are passed verbatim to `federation.FetchBundle`. The go-spiffe v2.7.0 implementation uses the URL as-is with `http.DefaultTransport` (cloned) and system/WebPKI roots — there's no scheme enforcement, so an operator who configures `trustdomain=http://...` (instead of `https://`) gets a **plaintext bundle fetch** whose response is then trusted as JWT key material. That's a MITM-to-full-auth-compromise path, but it requires operator misconfiguration at deploy time (a deliberate `http://` in the env var).

Mitigations in place: `Validate()` requires the env var to be non-empty and to have one entry per trust domain, and `WithWebPKIRoots` is applied when `SPIRE_FEDERATION_CA_BUNDLE_PATH` is set (proper `MinVersion: TLS1.2`, `RootCAs: pool`).

**Recommendation:** Reject non-`https` federation endpoint URLs in `spire.Config.Validate()` — one line, closes the misconfiguration class entirely. (Upstream go-spiffe leaves scheme choice open; the satellite can be stricter.)

---

### F-13 — INFO — `GetAllowedIDs` logs `c.config.JWT.FederationBundleEndpoints` map as `trust_domains`

`internal/spire/client.go:104-108`:

```go
slog.Info("JWT-SVID validation enabled (federation bundle source, no local SPIRE Agent required)",
	"audiences", c.config.JWT.Audiences,
	"trust_domains", c.config.JWT.FederationBundleEndpoints,
)
```

The label says `trust_domains` but the value is the endpoint **URLs** (internal infra hostnames). Minor log-hygiene/information-leak issue; logs are often shipped to central aggregators with broader readership than intended.

**Recommendation:** Log just the keys (`slices.Collect(maps.Keys(...))`) or the count.

---

### F-14 — INFO — `.git.bak.20260922074247/` full git backup directory present in working tree — **Status: REMEDIATED**

> **Remediation (2026-11-12):** the directory was deleted after confirming it was a stale copy (HEAD pointed at `ca67e10`, a pre-`3572c32` commit, matching a September-dated backup name). No secrets were present in the tracked history it contained; `git status` is clean of it now. A `.git.bak*` ignore rule was considered but not added — a one-off backup shouldn't recur, and ignoring it would hide a future one.

`git status` showed `?? .git.bak.20260922074207/` — an entire copy of the git directory (objects, logs, hooks, config) sitting in the checkout, not ignored. Two concerns: (a) if it was made at a moment when anything sensitive was committed (even later removed), that history persists in a second location; (b) tools like `grep -r` over the repo can pick up `.git.bak` content unexpectedly.

**Recommendation (done):** Delete it or add `.git.bak*` to `.gitignore`.

---

### F-15 — INFO — CI: SBOM generation uses `|| true` (silent failure acceptable)

`.github/workflows/release.yaml`:

```yaml
cosign attach sbom --sbom <(ko sbom ./cmd/centcom-satellite) "${IMAGE}" || true
```

The SBOM attachment silently succeeds on failure. Supply-chain attestation is a security property; letting it fail silently weakens the provenance story the cosign signing otherwise establishes.

**Recommendation:** Drop the `|| true` (fail the release on SBOM failure) or add a warning step.

---

## Positive observations (things done well)

These are worth calling out explicitly because they're load-bearing for the good posture and future contributors should preserve them:

- **`http_request`'s dual-layer SSRF guard** (`internal/task/http_request/task.go:149-192`): pre-flight resolve validation *plus* a `net.Dialer.Control` hook on the actual connect address (defeats DNS rebinding), `CheckRedirect` returning the 3xx instead of chasing redirects (blocks bounce-to-metadata attacks), and `Proxy: nil` (environment proxy can't redirect the checked address). This is textbook-correct hardening.
- **Rate limiter uses `RemoteAddr`, not `X-Forwarded-For`** (`internal/server/ratelimit.go:63-72`, with a comment explaining exactly why) — defeats bucket-spoofing via header injection. Idle-limiter eviction prevents map growth. `Retry-After` + RFC-style rate-limit headers on 429.
- **Write-capable tasks are all flag-gated and off by default** (`registerTasks` in `cmd/centcom-satellite/main.go`, with a test `TestRegisterTasks_*` locking it in). The comment correcting the earlier "apply is less dangerous than delete" mistake is honest and important.
- **Secret denylist is defense-in-depth and shared** (`internal/task/resourceaccess`): non-negotiable `DefaultDenied` (core/Secret) always applied, `list_resources` shares the *same* `Denylist` instance as `get_resource` so exclusion can't be bypassed by listing. Layer 1 (RBAC `view` role) + Layer 2 (denylist).
- **`helm_application_delete` hard-codes a protected-name rail** ("bootstrap") in the task itself, not just in a caller-side gate — comment explicitly notes this is "so it can't be bypassed by any caller including the unauthenticated call_task path."
- **1MB request-body cap** on `/task` (`io.LimitReader(r.Body, 1<<20)`); `aws_read` has a 5MB per-response cap with an OOM-driven rationale (real 2026-10-27 incident: 23MB page amplified to 183MB, killed the 384Mi container) and a refusal-before-amplification strategy.
- **Metrics label cardinality bounded everywhere**: route normalization to a known set, k8s resource allow-list, `status` from `http.StatusText`. Prevents Prometheus DoS via label explosion.
- **Panic recovery middleware** wraps the whole chain; handler timeouts (`ReadTimeout: 15s`, `WriteTimeout: 60s`) with a documented rationale.
- **`workload_restart`/`pod_evict` respect opt-out annotations** (`centcom.io/no-restart`, `centcom.io/no-evict`) at both namespace and workload/pod level, plus PDB checks before restart.
- **`pod_resize` has an absolute cap** (default 20Gi/2 CPU), a shrink buffer, QoS-preservation checks, and node-capacity verification before applying.
- **JWT-SVID validation is correct in the details that matter**: `jwtsvid.ParseAndValidate` against a `jwtbundle.Source` (audience validated inside), then explicit trust-domain and allowed-ID checks *on top*, with `bearer`-case tolerance handled.
- **Fail-fast AssumeRole verification at startup** (`verifyCallerIdentity`), so a broken trust policy kills the process before serving traffic, not on first call.
- **Distroless nonroot base image**, CGO disabled, `-trimpath -s -w`, cosign keyless signing verified in the release workflow itself.
- **Federation bundle fetch keeps last-known-good bundle on endpoint error** rather than blanking trusted keys.

---

## Suggested remediation order

| Priority | Finding | Effort |
|----------|---------|--------|
| ~~1~~ | ~~F-5 Go 1.27.4 bump~~ **done 2026-11-12** | ~~trivial~~ |
| 2 | F-12 reject non-https federation endpoints | one-line validation |
| ~~3~~ | ~~F-1 `connectivity_test` address guard~~ **done 2026-11-12** (new `internal/clusteraddr` shared with `http_request`) | ~~moderate~~ |
| 3 | F-2/F-3 metrics-server bind address (`/info` and probe rate-limit exemption still open from F-3) | small |
| 5 | F-4 Dependabot + scheduled govulncheck | small config |
| 6 | F-6 self-sufficient mTLS auth check | small |
| 7 | F-13 log label fix, F-15 SBOM `|| true` | trivial |

---

## Changes applied 2026-11-12 (F-1, F-3, F-5, F-14)

| Change | Files |
|--------|-------|
| **F-5** Go 1.27.3 → 1.27.4 (GO-2026-6859 fixed) | `go.mod` (CI reads `go-version-file: go.mod`, no workflow change needed) |
| **F-1** new shared SSRF-guard package; `http_request` refactored onto it | `internal/clusteraddr/clusteraddr.go`, `internal/clusteraddr/clusteraddr_test.go` (new), `internal/task/http_request/task.go` |
| **F-1** `connectivity_test` TCP + HTTP paths now guarded (cluster-internal only, no redirects, http/https only); new security-contract tests | `internal/task/connectivity_test/task.go`, `internal/task/connectivity_test/task_test.go`, `README.md` |
| **F-3** healthz/readyz 503 body returns fixed `"health check failed"` instead of SPIRE internals; tests assert no leakage | `internal/server/handlers.go`, `internal/server/handlers_test.go` |
| **F-14** stale full-git backup directory removed | `.git.bak.20260922074247/` (deleted) |

Verification after fixes: `go test -race ./...` — 66 packages, all pass; `go vet` — clean; `govulncheck ./...` — "No vulnerabilities found."

Remaining open findings, in suggested order: **F-12** (one-line https validation for federation endpoints), **F-2/F-3 remainder** (metrics bind address, `/info`), **F-4** (Dependabot + scheduled govulncheck; go-spiffe v2.9.0 bump), **F-6** (self-sufficient mTLS check), then the LOW/INFO stragglers (F-7–F-11, F-13, F-15).

---

*No code changes were made as part of the review itself; the remediation changes listed above were applied afterward, on request.*
