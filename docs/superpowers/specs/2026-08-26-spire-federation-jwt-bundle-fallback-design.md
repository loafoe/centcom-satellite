# SPIRE-agent-less JWT-SVID validation via federation bundle endpoint

**Status**: Approved for planning
**Date**: 2026-08-26

## Problem

centcom-satellite validates incoming JWT-SVIDs (and, optionally, mTLS
X.509 SVIDs) via the local SPIRE Workload API — a Unix domain socket
provided by a SPIRE Agent running alongside the satellite (as a DaemonSet
sidecar/CSI driver in Kubernetes). This assumes a SPIRE Agent is always
available on the host, which isn't true for every deployment target —
ECS/Fargate tasks have no DaemonSet concept and generally can't run a
SPIRE Agent sidecar, and any similar "no local agent" environment hits
the same wall.

The question this spec answers: does JWT-SVID *validation* actually need
a local agent, or only the trust material (the issuing trust domain's JWT
signing public keys) a local agent happens to be a convenient source of?

## Finding

**JWT-SVID validation does not need a local agent.** `jwtsvid.ParseAndValidate`
(the go-spiffe v2 call centcom-satellite already uses) takes a
`jwtbundle.Source` interface — `workloadapi.JWTSource` (the current,
agent-backed implementation) is just one implementation of it. SPIRE
ships a standard, purpose-built alternative for exactly this case: the
**SPIFFE Federation Bundle Endpoint** — an HTTPS endpoint a SPIRE Server
exposes serving its current trust bundle (X.509 + JWT authorities) as a
signed document, designed for relying parties that can't run a local
agent. The go-spiffe v2 SDK ships a client for it:
`github.com/spiffe/go-spiffe/v2/federation` (`FetchBundle`/`WatchBundle`),
already a transitive dependency of this repo's existing go-spiffe usage.

**Caveat, and why this stays JWT-SVID-only:** mTLS mode requires the
satellite to present *its own* rotating X.509 SVID as the TLS server
certificate — an identity that must be *issued* to this specific
workload (via attestation), not merely *validated* against a trust
bundle. There is no "just fetch a public key" equivalent for issuing your
own identity; that fundamentally requires a SPIRE Agent (or an
equivalent attestation mechanism) running somewhere reachable by this
workload. This design does not attempt to solve that — mTLS mode remains
agent-required. ECS/Fargate deployments would use JWT-SVID auth only,
which is already the more portable of the two documented modes.

**A real, separate bug found during this investigation**: `Client.Start()`
unconditionally calls `workloadapi.NewX509Source(...)` and requires it to
succeed, and `HealthCheck()` unconditionally requires that source to be
non-nil — even when `MTLSEnabled=false`. `GetTLSConfig`/`WrapListener`
(`internal/server/server.go`), the only real consumers of that X.509
source, are already correctly gated behind `IsMTLSEnabled()`. This means
every existing JWT-only deployment has an unneeded X.509 SVID dependency
today. Fixing this is a **prerequisite** for federation mode (there is no
socket to build an X509Source from in that mode) and a worthwhile fix on
its own for existing JWT-only deployments.

## Non-goals

- **mTLS support without a local agent.** No shortcut exists for issuing
  this workload its own identity; out of scope (see Finding above).
- **Auto-detection / runtime fallback** between Workload API and
  federation modes. Mode selection is explicit, deployment-time config —
  matches this codebase's existing fail-fast, no-silent-degradation
  philosophy (the same posture `AssumeRole.Init` already uses). A
  misconfigured socket path should not silently and unpredictably change
  which auth mode a deployment ends up in.
- **SPIFFE-authenticated bootstrap chaining** for the initial federation
  fetch (`federation.WithSPIFFEAuth`). That requires already trusting a
  bundle to bootstrap from — a chicken-and-egg problem not worth solving
  for v1. WebPKI (system trust store, or an optional custom CA bundle)
  covers the common case: a federation endpoint behind a normal
  ALB/ingress with a public or internally-issued-but-CA-distributed cert.

## Design

### Prerequisite: decouple X.509 SVID from Start()/HealthCheck()

In `internal/spire/client.go`:

- `Start()`: only call `workloadapi.NewX509Source(...)` (and the
  subsequent `GetX509SVID()` sanity check) when `c.config.MTLSEnabled` is
  true.
- `HealthCheck()`: only check `c.source`/`GetX509SVID()` when
  `c.config.MTLSEnabled` is true. The JWT bundle health check (already
  present, checking `jwtSource.GetJWTBundleForTrustDomain`) is unchanged
  either way — it just runs against whichever `jwtbundle.Source` `Start()`
  built.
- `GetTLSConfig()`/`WrapListener()` already return an error if `c.source`
  is nil; no change needed there — they're only called when
  `IsMTLSEnabled()` is true (`internal/server/server.go`), so this is
  purely making the precondition explicit at the point it's actually
  established, not a behavior change for any code path that already
  works today.

This is a pure subtraction of an unnecessary dependency: every existing
JWT-only deployment (`MTLSEnabled=false`, `JWT.Enabled=true`) keeps
working identically, just without needing a working X.509 SVID it never
used.

### Config surface (`internal/spire/config.go`)

New `JWTConfig` fields:

```go
type JWTConfig struct {
	Enabled     bool
	Audiences   []string
	// BundleSource selects how the JWT trust bundle is obtained.
	// "workload_api" (default) uses the local SPIRE Workload API, exactly
	// as today. "federation" fetches (and keeps live-updated) the bundle
	// from a SPIFFE Federation Bundle Endpoint instead — no local SPIRE
	// Agent required. Explicit, no auto-detection.
	BundleSource string
	// FederationBundleEndpoints maps trust domain -> federation bundle
	// endpoint URL. Required, one entry per trust domain in TrustDomains,
	// when BundleSource is "federation".
	FederationBundleEndpoints map[string]string
	// FederationCABundlePath is an optional PEM file of root CAs to trust
	// when fetching from FederationBundleEndpoints. Empty (default) uses
	// the system trust store — the common case for an endpoint behind a
	// normal ALB/ingress with a publicly-trusted cert.
	FederationCABundlePath string
}
```

New env vars (`internal/config/config.go`, following the existing
`SPIRE_*` naming convention):

| Env var | Default | Notes |
|---|---|---|
| `SPIRE_JWT_BUNDLE_SOURCE` | `workload_api` | `workload_api` or `federation`. |
| `SPIRE_FEDERATION_BUNDLE_ENDPOINTS` | unset | Comma-separated `trustdomain=https://url` pairs, e.g. `example.org=https://spire-server.example.org/bundle`. Required when bundle source is `federation`. |
| `SPIRE_FEDERATION_CA_BUNDLE_PATH` | unset | Optional PEM path. Falls back to system trust store. |

New validation rules (`Config.Validate()`):

- `SPIRE_JWT_BUNDLE_SOURCE` must be `workload_api` or `federation`.
- When `federation`: `SPIRE_MTLS_ENABLED` must be `false` (fail fast —
  federation mode has no X.509 identity source at all, so mTLS can never
  work alongside it) — and `SPIRE_FEDERATION_BUNDLE_ENDPOINTS` must
  supply exactly one entry per configured trust domain.
- `SPIRE_AGENT_SOCKET`'s existing "required when SPIRE enabled" check
  becomes conditional: only required when `BundleSource == "workload_api"`
  (federation mode never touches the Workload API at all — no MTLS
  source, no JWT source).

### Client architecture (`internal/spire/client.go`)

`Client.Start(ctx)` branches on `config.JWT.BundleSource`:

- **`workload_api`** (default): unchanged — `workloadapi.NewJWTSource(...)`.
- **`federation`**: builds a small internal type, `federationJWTSource`,
  implementing `jwtbundle.Source` (the exact interface
  `jwtsvid.ParseAndValidate` and `workloadapi.JWTSource` both already
  satisfy — swapping the implementation requires no change to
  `ValidateJWTToken`'s call site). It holds one mutex-protected
  `*spiffebundle.Bundle` per configured trust domain. For each configured
  endpoint:
  1. One synchronous `federation.FetchBundle(ctx, trustDomain, url, opts...)`
     call before `Start()` returns — fail fast on an unreachable endpoint
     or a bundle that doesn't cover the expected trust domain, matching
     `AssumeRole.Init`'s posture (misconfiguration surfaces at startup,
     not on the first caller's request).
  2. A background goroutine running `federation.WatchBundle(ctx, trustDomain, url, watcher, opts...)`
     to keep the bundle live-updated — the `watcher`'s `OnUpdate` swaps
     the mutex-protected bundle; `OnError` logs and keeps serving the
     last-known-good bundle (same "an outage never blanks known-good
     state" posture used elsewhere in this codebase, e.g. the
     cross-account AssumeRole persistGeo design).
  `federationJWTSource.GetJWTBundleForTrustDomain(td)` reads the
  mutex-protected bundle for that trust domain and returns
  `bundle.GetJWTBundleForTrustDomain(td)` (delegating to
  `spiffebundle.Bundle`'s own method, since a fetched SPIFFE bundle
  already contains both X.509 and JWT authorities combined).
  `opts` is `federation.WithWebPKIRoots(pool)` when
  `FederationCABundlePath` is set, otherwise no fetch options at all
  (system trust store — go-spiffe's default when no auth-method option is
  given).

`HealthCheck()` in federation mode checks that each trust domain's held
bundle is non-empty (`spiffebundle.Bundle.Empty()`), mirroring today's
`jwtSource.GetJWTBundleForTrustDomain` check but against the new source.

`ValidateJWTToken` is **unchanged** — it already calls
`jwtsvid.ParseAndValidate(token, jwtSource, audiences)` against whatever
`jwtSource` interface value `Start()` built; it has no idea (and needs no
idea) which concrete bundle-source implementation is behind it.

### Helm chart implications (companion change, `philips-software/helm-charts`, chart `centcom-satellite`)

In federation mode, the chart's SPIRE agent-socket plumbing — the CSI
volume/mount or hostPath volume, the `spire.csi.enabled`/
`spire.hostSocketPath` values, and the CSI driver dependency itself —
becomes entirely unnecessary. This is the concrete ECS/Fargate payoff: no
sidecar, no hostPath, no CSI driver.

New values: `spire.jwt.bundleSource` (`workload_api`|`federation`),
`spire.jwt.federationBundleEndpoints` (map of trust domain → URL),
`spire.jwt.federationCABundlePath`. When `bundleSource=federation`, the
chart should skip rendering the agent-socket volume/mount entirely
(matching the existing nil-safe/opt-in pattern the chart already uses for
e.g. `httpRoute`/`aws.assumeRole`). This chart-side work is tracked as a
companion task in the helm-charts repo, not part of this spec's
implementation plan — mirroring how the original AssumeRole spec handled
its own companion Helm chart work.

### Testing

- `internal/spire`: unit tests for the new `federationJWTSource` type
  using a fake `federation.BundleWatcher`-style test double / a local
  `httptest.Server` serving a canned SPIFFE bundle document, covering:
  successful fetch populates the bundle; fetch failure at `Start()` fails
  fast (returns an error, doesn't start); a subsequent `OnUpdate` swaps
  the held bundle; `OnError` preserves the last-known-good bundle.
- `internal/config`: env var parsing/validation tests for the three new
  `SPIRE_*` vars, mirroring the existing `AWSAssumeRole` config test
  style (defaults, explicit values, and the new fail-fast validation
  rules).
- `Start()`/`HealthCheck()`'s decoupling from `MTLSEnabled`: a test
  proving `Start()` succeeds without ever touching the Workload API
  socket when `MTLSEnabled=false` and `BundleSource=federation` (no real
  SPIRE Agent needed to run this test at all — that's the point).
