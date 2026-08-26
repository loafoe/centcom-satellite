# Agent-less JWT-SVID Validation via SPIFFE Federation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let centcom-satellite validate incoming JWT-SVIDs without a local SPIRE Agent, by fetching the trust domain's JWT bundle from a SPIFFE Federation Bundle Endpoint instead of the local Workload API — enabling ECS/Fargate and other agent-less deployment targets for JWT-SVID auth (mTLS stays agent-required; out of scope).

**Architecture:** A prerequisite fix decouples the unused X.509 SVID dependency from JWT-only deployments. A new `SPIRE_JWT_BUNDLE_SOURCE` config selects between the existing `workload_api` behavior (default, unchanged) and a new `federation` mode. In federation mode, a new `federationJWTSource` type — implementing the same `jwtbundle.Source` interface `jwtsvid.ParseAndValidate` already consumes — fetches and keeps live-updated one `*spiffebundle.Bundle` per configured trust domain via `github.com/spiffe/go-spiffe/v2/federation` (`FetchBundle` for a fail-fast initial fetch, `WatchBundle` for background rotation).

**Tech Stack:** Go, `github.com/spiffe/go-spiffe/v2` (`federation`, `bundle/spiffebundle`, `bundle/jwtbundle`, `svid/jwtsvid`), existing SPIRE client/config framework.

**Spec:** `docs/superpowers/specs/2026-08-26-spire-federation-jwt-bundle-fallback-design.md`

## Global Constraints

- mTLS mode stays agent-required — no attempt to issue this workload its own identity without a local agent. `federation` bundle source is incompatible with `SPIRE_MTLS_ENABLED=true` (fail validation, not silently ignore).
- No auto-detection/runtime fallback between bundle sources — explicit config only (`SPIRE_JWT_BUNDLE_SOURCE`), matching this codebase's fail-fast philosophy.
- `ValidateJWTToken` must not change — it already calls `jwtsvid.ParseAndValidate(token, jwtSource, audiences)` against whatever `jwtbundle.Source` `Start()` built. Swapping bundle-source implementations must require zero changes to that call site.
- Federation mode must fail fast at startup (one synchronous fetch before `Start()` returns) on an unreachable endpoint or a bundle missing the expected trust domain — not defer the failure to the first caller's request.
- Backward compatible: `SPIRE_JWT_BUNDLE_SOURCE` unset defaults to `workload_api`, byte-for-byte identical to today's behavior for every existing deployment.

---

### Task 1: Decouple X.509 SVID from MTLSEnabled in Start()/HealthCheck()

**Files:**
- Modify: `internal/spire/client.go`
- Test: `internal/spire/client_test.go`

**Interfaces:**
- Produces: no new exported symbols — this task changes *when* existing internal logic runs, not its shape. `Start(ctx) error` and `HealthCheck(ctx) error` keep their exact signatures.

**Note:** This is a real, standalone bug fix independent of the federation feature — every existing JWT-only deployment (`MTLSEnabled=false`, `JWT.Enabled=true`) currently requires a working X.509 SVID it never uses, since `GetTLSConfig`/`WrapListener` (the only real consumers of `c.source`) are already gated behind `IsMTLSEnabled()` in `internal/server/server.go:105`. It is also a **hard prerequisite** for Task 3 — federation mode has no Workload API socket to build an X509Source from at all.

- [ ] **Step 1: Write the failing test**

Add to `internal/spire/client_test.go`:

```go
func TestClient_HealthCheck_JWTOnly_SkipsX509Check(t *testing.T) {
	// MTLSEnabled=false, JWT.Enabled=true, jwtSource never initialized.
	// Before this fix, HealthCheck failed on the X.509 source check first,
	// masking what should be a JWT-specific error. After this fix, with
	// MTLS disabled, the X.509 check is skipped entirely and the JWT
	// check's own error surfaces instead.
	cfg := &Config{
		Enabled:     true,
		MTLSEnabled: false,
		JWT:         JWTConfig{Enabled: true},
	}
	client := NewClient(cfg)

	err := client.HealthCheck(context.Background())
	if err == nil {
		t.Fatal("expected error when JWT is enabled but jwtSource is uninitialized")
	}
	if strings.Contains(err.Error(), "X509") {
		t.Errorf("X.509 must not be checked when MTLSEnabled=false, got: %v", err)
	}
	if !strings.Contains(err.Error(), "SPIRE JWT source not initialized") {
		t.Errorf("expected JWT-specific error, got: %v", err)
	}
}

func TestClient_HealthCheck_NeitherMTLSNorJWT_NoOp(t *testing.T) {
	// Enabled=true but nothing configured to check — must not error just
	// because the (unused) X.509 source was never initialized.
	cfg := &Config{Enabled: true}
	client := NewClient(cfg)

	if err := client.HealthCheck(context.Background()); err != nil {
		t.Fatalf("expected nil error when neither MTLS nor JWT is enabled, got: %v", err)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/spire/... -run TestClient_HealthCheck_JWTOnly -v`
Expected: FAIL — `TestClient_HealthCheck_JWTOnly_SkipsX509Check` currently gets "SPIRE X509 source not initialized" (the X.509 check runs unconditionally today), not the JWT-specific error the test asserts.

- [ ] **Step 3: Update the existing test that encodes the old behavior**

`TestClient_HealthCheck_Enabled_UninitializedSource` in `internal/spire/client_test.go` currently constructs `Config{Enabled: true}` (MTLSEnabled defaults to false) and asserts the X.509-source error. After this fix, that config no longer triggers the X.509 check at all. Update it to explicitly enable MTLS so it keeps testing what it says it tests:

```go
func TestClient_HealthCheck_Enabled_UninitializedSource(t *testing.T) {
	cfg := &Config{Enabled: true, MTLSEnabled: true}
	client := NewClient(cfg)

	err := client.HealthCheck(context.Background())
	if err == nil {
		t.Fatalf("expected error when MTLS is enabled but source is nil, got nil")
	}
	if !strings.Contains(err.Error(), "SPIRE X509 source not initialized") {
		t.Errorf("unexpected error message: %v", err)
	}
}
```

- [ ] **Step 4: Implement — gate Start()'s X509Source creation behind MTLSEnabled**

In `internal/spire/client.go`, `Start()` currently (lines ~43-100) builds the X509Source unconditionally before checking `c.config.JWT.Enabled` for the JWT source. Change it to:

```go
func (c *Client) Start(ctx context.Context) error {
	if !c.config.Enabled {
		slog.Info("SPIRE disabled, skipping workload API connection")
		return nil
	}

	slog.Info("connecting to SPIRE workload API",
		"socket", c.config.AgentSocket,
		"trust_domains", c.config.TrustDomains,
		"jwt_enabled", c.config.JWT.Enabled,
	)

	if c.config.MTLSEnabled {
		source, err := workloadapi.NewX509Source(ctx,
			workloadapi.WithClientOptions(
				workloadapi.WithAddr(c.config.AgentSocket),
			),
		)
		if err != nil {
			return fmt.Errorf("failed to create X509 source: %w", err)
		}

		c.mu.Lock()
		c.source = source
		c.mu.Unlock()

		// Log our SPIFFE ID
		svid, err := source.GetX509SVID()
		if err != nil {
			return fmt.Errorf("failed to get initial SVID: %w", err)
		}

		slog.Info("acquired SPIFFE identity",
			"spiffe_id", svid.ID.String(),
			"expires", svid.Certificates[0].NotAfter,
		)
	}

	// Initialize JWT source if JWT auth is enabled
	if c.config.JWT.Enabled {
		jwtSource, err := workloadapi.NewJWTSource(ctx,
			workloadapi.WithClientOptions(
				workloadapi.WithAddr(c.config.AgentSocket),
			),
		)
		if err != nil {
			return fmt.Errorf("failed to create JWT source: %w", err)
		}

		c.mu.Lock()
		c.jwtSource = jwtSource
		c.mu.Unlock()

		slog.Info("JWT-SVID validation enabled",
			"audiences", c.config.JWT.Audiences,
		)
	}

	return nil
}
```

(This is the exact same body as today, just with the X.509 block wrapped in `if c.config.MTLSEnabled { ... }`.)

- [ ] **Step 5: Implement — gate HealthCheck()'s X.509 check behind MTLSEnabled**

Replace `HealthCheck` with:

```go
func (c *Client) HealthCheck(ctx context.Context) error {
	if c == nil || c.config == nil || !c.config.Enabled {
		return nil
	}

	c.mu.RLock()
	source := c.source
	jwtSource := c.jwtSource
	c.mu.RUnlock()

	var svidTrustDomain string
	if c.config.MTLSEnabled {
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
		svidTrustDomain = svid.ID.TrustDomain().String()
	}

	if c.config.JWT.Enabled {
		if jwtSource == nil {
			return fmt.Errorf("SPIRE JWT source not initialized")
		}
		trustDomains := c.config.TrustDomains
		if len(trustDomains) == 0 {
			if svidTrustDomain == "" {
				return fmt.Errorf("no trust domain configured to health-check JWT bundle")
			}
			trustDomains = []string{svidTrustDomain}
		}
		for _, tdStr := range trustDomains {
			td, err := spiffeid.TrustDomainFromString(tdStr)
			if err != nil {
				return fmt.Errorf("invalid trust domain %q: %w", tdStr, err)
			}
			if _, err := jwtSource.GetJWTBundleForTrustDomain(td); err != nil {
				return fmt.Errorf("SPIRE JWT bundle error: %w", err)
			}
		}
	}

	return nil
}
```

The only behavioral change from today: the X.509 block (source/SVID checks) only runs when `MTLSEnabled` is true. The JWT block, and its trust-domain fallback logic, are otherwise identical — just renamed the local var (`svid` → `svidTrustDomain` string) since `svid` itself is now scoped inside the `if MTLSEnabled` block.

- [ ] **Step 6: Run tests to verify they pass**

Run: `go test ./internal/spire/... -v`
Expected: PASS for all tests, including the two new ones, the updated `TestClient_HealthCheck_Enabled_UninitializedSource`, and every other pre-existing test in the package.

- [ ] **Step 7: Run the full build and test suite**

Run: `go build ./... && go test ./...`
Expected: no errors; no other package touches `spire.Client` in a way this changes.

- [ ] **Step 8: Commit**

```bash
git add internal/spire/client.go internal/spire/client_test.go
git commit -m "fix(spire): decouple X.509 SVID requirement from JWT-only deployments"
```

---

### Task 2: Config surface for federation bundle source

**Files:**
- Modify: `internal/spire/config.go`
- Test: `internal/spire/config_test.go`
- Modify: `internal/config/config.go`

**Interfaces:**
- Consumes: nothing from Task 1.
- Produces: `JWTConfig.BundleSource string`, `JWTConfig.FederationBundleEndpoints map[string]string`, `JWTConfig.FederationCABundlePath string` — consumed by Task 3's `Client.Start()` branching. `Config.Validate()` gains the new fail-fast rules described below — consumed by nothing else, but must hold before Task 3's client code can assume it's already been checked.

- [ ] **Step 1: Write the failing tests**

Add to `internal/spire/config_test.go`, as new cases in the existing `tests` table inside `TestConfig_Validate` (append these entries to the slice, right before the closing `}` of the table):

```go
		{
			name: "federation bundle source - valid, mtls disabled, endpoint covers trust domain",
			config: Config{
				Enabled:      true,
				TrustDomains: []string{"example.org"},
				MTLSEnabled:  false,
				JWT: JWTConfig{
					Enabled:      true,
					Audiences:    []string{"centcom-satellite"},
					BundleSource: "federation",
					FederationBundleEndpoints: map[string]string{
						"example.org": "https://spire-server.example.org/bundle",
					},
				},
			},
			wantErr: false,
		},
		{
			name: "federation bundle source - does not require AgentSocket",
			config: Config{
				Enabled:      true,
				TrustDomains: []string{"example.org"},
				MTLSEnabled:  false,
				JWT: JWTConfig{
					Enabled:      true,
					Audiences:    []string{"centcom-satellite"},
					BundleSource: "federation",
					FederationBundleEndpoints: map[string]string{
						"example.org": "https://spire-server.example.org/bundle",
					},
				},
			},
			wantErr: false, // AgentSocket is empty here and must NOT trigger a validation error
		},
		{
			name: "federation bundle source - rejected when MTLS also enabled",
			config: Config{
				Enabled:      true,
				AgentSocket:  "unix:///run/spire/agent.sock",
				TrustDomains: []string{"example.org"},
				MTLSEnabled:  true,
				JWT: JWTConfig{
					Enabled:      true,
					Audiences:    []string{"centcom-satellite"},
					BundleSource: "federation",
					FederationBundleEndpoints: map[string]string{
						"example.org": "https://spire-server.example.org/bundle",
					},
				},
			},
			wantErr: true,
		},
		{
			name: "federation bundle source - missing endpoints map entirely",
			config: Config{
				Enabled:      true,
				TrustDomains: []string{"example.org"},
				MTLSEnabled:  false,
				JWT: JWTConfig{
					Enabled:      true,
					Audiences:    []string{"centcom-satellite"},
					BundleSource: "federation",
				},
			},
			wantErr: true,
		},
		{
			name: "federation bundle source - endpoints map missing one trust domain",
			config: Config{
				Enabled:      true,
				TrustDomains: []string{"example.org", "partner.com"},
				MTLSEnabled:  false,
				JWT: JWTConfig{
					Enabled:      true,
					Audiences:    []string{"centcom-satellite"},
					BundleSource: "federation",
					FederationBundleEndpoints: map[string]string{
						"example.org": "https://spire-server.example.org/bundle",
					},
				},
			},
			wantErr: true,
		},
		{
			name: "unrecognized bundle source value",
			config: Config{
				Enabled:      true,
				AgentSocket:  "unix:///run/spire/agent.sock",
				TrustDomains: []string{"example.org"},
				JWT: JWTConfig{
					Enabled:      true,
					Audiences:    []string{"centcom-satellite"},
					BundleSource: "nonsense",
				},
			},
			wantErr: true,
		},
		{
			name: "empty bundle source defaults to workload_api behavior (socket still required)",
			config: Config{
				Enabled:      true,
				TrustDomains: []string{"example.org"},
				JWT: JWTConfig{
					Enabled:   true,
					Audiences: []string{"centcom-satellite"},
					// BundleSource left empty — must behave exactly like "workload_api".
				},
			},
			wantErr: true, // AgentSocket is empty, and workload_api mode requires it
		},
```

Also add a standalone test verifying the pre-existing "missing socket" case is unaffected by this change (defends against accidentally making `AgentSocket` optional in the default mode):

```go
func TestConfig_Validate_WorkloadAPIStillRequiresSocket(t *testing.T) {
	cfg := Config{
		Enabled:      true,
		TrustDomains: []string{"example.org"},
		JWT:          JWTConfig{Enabled: true, Audiences: []string{"x"}},
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error: workload_api (default) bundle source still requires AgentSocket")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/spire/... -run TestConfig_Validate -v`
Expected: FAIL — `JWTConfig` has no `BundleSource`/`FederationBundleEndpoints` fields yet (compile error).

- [ ] **Step 3: Implement — extend JWTConfig and Validate()**

In `internal/spire/config.go`, replace `JWTConfig`:

```go
// JWTConfig holds JWT-SVID specific configuration.
type JWTConfig struct {
	// Enabled controls whether JWT-SVID authentication is active.
	// Can be used alongside or instead of X.509 mTLS.
	Enabled bool

	// Audiences is the list of expected JWT audience values.
	// The JWT must contain at least one of these audiences.
	// Example: ["centcom-satellite", "https://centcom-satellite.example.org"]
	Audiences []string

	// BundleSource selects how the JWT trust bundle is obtained.
	// "workload_api" (default, used when empty) fetches it from the local
	// SPIRE Workload API, exactly as before this field existed. "federation"
	// fetches it from a SPIFFE Federation Bundle Endpoint instead — no
	// local SPIRE Agent required. Explicit, no auto-detection between them.
	BundleSource string

	// FederationBundleEndpoints maps trust domain -> federation bundle
	// endpoint URL (e.g. "example.org" -> "https://spire-server.example.org/bundle").
	// Required, with one entry per trust domain in TrustDomains, when
	// BundleSource is "federation".
	FederationBundleEndpoints map[string]string

	// FederationCABundlePath is an optional PEM file of root CAs to trust
	// when fetching from FederationBundleEndpoints. Empty (default) uses
	// the system trust store — the common case for an endpoint behind a
	// normal ALB/ingress with a publicly-trusted certificate.
	FederationCABundlePath string
}
```

In `internal/spire/config.go`, `Validate()` currently has:

```go
	if c.AgentSocket == "" {
		return fmt.Errorf("SPIRE_AGENT_SOCKET is required when SPIRE is enabled")
	}
```

Replace that block, and add the new bundle-source validation right after the existing JWT audiences check (`if c.JWT.Enabled && len(c.JWT.Audiences) == 0 { ... }`), so the full `Validate()` becomes:

```go
// Validate checks that the configuration is valid when SPIRE is enabled.
func (c *Config) Validate() error {
	if !c.Enabled {
		return nil
	}

	usesFederation := c.JWT.Enabled && c.JWT.BundleSource == "federation"

	if !usesFederation && c.AgentSocket == "" {
		return fmt.Errorf("SPIRE_AGENT_SOCKET is required when SPIRE is enabled (unless SPIRE_JWT_BUNDLE_SOURCE=federation)")
	}

	if len(c.TrustDomains) == 0 {
		return fmt.Errorf("SPIRE_TRUST_DOMAINS is required when SPIRE is enabled")
	}

	// Validate trust domain format (should not contain spiffe:// prefix)
	for _, td := range c.TrustDomains {
		if strings.HasPrefix(td, "spiffe://") {
			return fmt.Errorf("invalid trust domain format: %s (should not include spiffe:// prefix)", td)
		}
		if td == "" {
			return fmt.Errorf("empty trust domain in SPIRE_TRUST_DOMAINS")
		}
	}

	// Validate SPIFFE ID format
	for _, id := range c.AllowedSPIFFEIDs {
		if !strings.HasPrefix(id, "spiffe://") {
			return fmt.Errorf("invalid SPIFFE ID format: %s (must start with spiffe://)", id)
		}
	}

	// Validate JWT config
	if c.JWT.Enabled {
		if len(c.JWT.Audiences) == 0 {
			return fmt.Errorf("SPIRE_JWT_AUDIENCES is required when JWT-SVID auth is enabled")
		}

		switch c.JWT.BundleSource {
		case "", "workload_api":
			// Default; nothing further to validate — AgentSocket already
			// checked above.
		case "federation":
			if c.MTLSEnabled {
				return fmt.Errorf("SPIRE_MTLS_ENABLED must be false when SPIRE_JWT_BUNDLE_SOURCE=federation (federation mode has no X.509 identity source)")
			}
			if len(c.JWT.FederationBundleEndpoints) == 0 {
				return fmt.Errorf("SPIRE_FEDERATION_BUNDLE_ENDPOINTS is required when SPIRE_JWT_BUNDLE_SOURCE=federation")
			}
			for _, td := range c.TrustDomains {
				if _, ok := c.JWT.FederationBundleEndpoints[td]; !ok {
					return fmt.Errorf("SPIRE_FEDERATION_BUNDLE_ENDPOINTS is missing an entry for trust domain %q", td)
				}
			}
		default:
			return fmt.Errorf(`SPIRE_JWT_BUNDLE_SOURCE must be "workload_api" or "federation", got %q`, c.JWT.BundleSource)
		}
	}

	return nil
}
```

Note: the "unrecognized bundle source value" test case above (`BundleSource: "nonsense"`) only triggers this `default` branch because it also sets `JWT.Enabled: true` — the switch is nested inside `if c.JWT.Enabled`. This is deliberate: an unrecognized `BundleSource` is meaningless when JWT auth isn't even active.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/spire/... -v`
Expected: PASS for every test in the package, including all new cases and the untouched pre-existing ones (`TestConfig_IsIDAllowed`, `TestConfig_IsTrustDomainAllowed`, etc.).

- [ ] **Step 5: Wire the new env vars in `internal/config/config.go`**

Add a small map-parsing helper near the existing `getEnvStringSlice`/`loadTrustDomains` helpers:

```go
// getEnvStringMap parses a comma-separated "key=value,key2=value2" env var
// into a map. Returns nil if the env var is unset or empty. Malformed pairs
// (no "=") are skipped — Validate() is responsible for catching a resulting
// missing-entry error, not this parser.
func getEnvStringMap(key string) map[string]string {
	value := os.Getenv(key)
	if value == "" {
		return nil
	}
	result := make(map[string]string)
	for _, pair := range strings.Split(value, ",") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		k, v, ok := strings.Cut(pair, "=")
		if !ok {
			continue
		}
		result[strings.TrimSpace(k)] = strings.TrimSpace(v)
	}
	if len(result) == 0 {
		return nil
	}
	return result
}
```

This needs `"strings"` in `internal/config/config.go`'s imports — check first with `grep -n '"strings"' internal/config/config.go`; it's already imported (used by `strings.ToLower`/`strings.Join` elsewhere in that file), so no import change needed.

In `internal/config/config.go`, the `SPIRE: spire.Config{...}` literal inside `Load()` currently ends with:

```go
			JWT: spire.JWTConfig{
				Enabled:   getEnvBool("SPIRE_JWT_ENABLED", false),
				Audiences: getEnvStringSlice("SPIRE_JWT_AUDIENCES"),
			},
```

Change to:

```go
			JWT: spire.JWTConfig{
				Enabled:                   getEnvBool("SPIRE_JWT_ENABLED", false),
				Audiences:                 getEnvStringSlice("SPIRE_JWT_AUDIENCES"),
				BundleSource:              getEnvString("SPIRE_JWT_BUNDLE_SOURCE", "workload_api"),
				FederationBundleEndpoints: getEnvStringMap("SPIRE_FEDERATION_BUNDLE_ENDPOINTS"),
				FederationCABundlePath:    os.Getenv("SPIRE_FEDERATION_CA_BUNDLE_PATH"),
			},
```

- [ ] **Step 6: Run the full build and test suite**

Run: `go build ./... && go test ./...`
Expected: no errors.

- [ ] **Step 7: Update CLAUDE.md's Configuration section**

In `CLAUDE.md`, in the "SPIRE configuration" bullet list (after `SPIRE_JWT_AUDIENCES`), add:

```markdown
- `SPIRE_JWT_BUNDLE_SOURCE` (default: `workload_api`) - `workload_api` fetches the JWT trust bundle from the local SPIRE Workload API (requires a local SPIRE Agent). `federation` fetches it from a SPIFFE Federation Bundle Endpoint instead — no local SPIRE Agent required, enabling agent-less deployment targets (e.g. ECS/Fargate) for JWT-SVID auth. Incompatible with `SPIRE_MTLS_ENABLED=true` — mTLS always requires a local agent to issue this workload its own identity, which federation mode has no way to do.
- `SPIRE_FEDERATION_BUNDLE_ENDPOINTS` (default: unset) - Comma-separated `trustdomain=https://url` pairs, e.g. `example.org=https://spire-server.example.org/bundle`. Required, with one entry per configured trust domain, when `SPIRE_JWT_BUNDLE_SOURCE=federation`.
- `SPIRE_FEDERATION_CA_BUNDLE_PATH` (default: unset) - Optional PEM file of root CAs to trust when fetching from `SPIRE_FEDERATION_BUNDLE_ENDPOINTS`. Unset uses the system trust store — the common case for an endpoint behind a normal ALB/ingress with a publicly-trusted certificate.
```

- [ ] **Step 8: Commit**

```bash
git add internal/spire/config.go internal/spire/config_test.go internal/config/config.go CLAUDE.md
git commit -m "feat(spire): add SPIRE_JWT_BUNDLE_SOURCE config for agent-less JWT bundle fetching"
```

---

### Task 3: federationJWTSource + Start()/Close() wiring

**Files:**
- Create: `internal/spire/federation_source.go`
- Test: `internal/spire/federation_source_test.go`
- Modify: `internal/spire/client.go`

**Interfaces:**
- Consumes: Task 1's `MTLSEnabled`-gated `Start()` (this task adds the sibling JWT-source branch inside the same function). Task 2's `JWTConfig.BundleSource`/`FederationBundleEndpoints`/`FederationCABundlePath`.
- Produces: `startFederationJWTSource(ctx context.Context, cfg JWTConfig) (*federationJWTSource, error)` and the type `*federationJWTSource` (implements `jwtbundle.Source` — same interface `*workloadapi.JWTSource` already satisfies). `Client.jwtSource`'s field type changes from `*workloadapi.JWTSource` to the `jwtbundle.Source` interface so `Start()` can assign either implementation to it — `ValidateJWTToken`'s call to `jwtsvid.ParseAndValidate(token, jwtSource, ...)` requires no change, since it already only needs that interface.

- [ ] **Step 1: Write the failing tests**

Create `internal/spire/federation_source_test.go`:

```go
package spire

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/spiffe/go-spiffe/v2/bundle/spiffebundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

// testBundleServer serves a real, marshaled SPIFFE bundle (one JWT
// authority) for the given trust domain, so tests exercise the actual
// spiffebundle.Read parse path FetchBundle uses, not a hand-rolled stand-in.
func testBundleServer(t *testing.T, td spiffeid.TrustDomain) *httptest.Server {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	bundle := spiffebundle.FromJWTAuthorities(td, map[string]crypto.PublicKey{"kid1": &key.PublicKey})
	body, err := bundle.Marshal()
	if err != nil {
		t.Fatalf("marshal bundle: %v", err)
	}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(body)
	}))
}

func TestStartFederationJWTSource_FetchesInitialBundle(t *testing.T) {
	td := spiffeid.RequireTrustDomainFromString("example.org")
	srv := testBundleServer(t, td)
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cfg := JWTConfig{
		FederationBundleEndpoints: map[string]string{"example.org": srv.URL},
	}
	source, err := startFederationJWTSource(ctx, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	jb, err := source.GetJWTBundleForTrustDomain(td)
	if err != nil {
		t.Fatalf("unexpected error getting JWT bundle: %v", err)
	}
	if jb == nil {
		t.Fatal("expected non-nil JWT bundle")
	}
}

func TestStartFederationJWTSource_FailsFastOnUnreachableEndpoint(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cfg := JWTConfig{
		// Port 1 is reserved and never listens — connection refused, fast.
		FederationBundleEndpoints: map[string]string{"example.org": "http://127.0.0.1:1/nope"},
	}
	if _, err := startFederationJWTSource(ctx, cfg); err == nil {
		t.Fatal("expected error when the federation endpoint is unreachable")
	}
}

func TestStartFederationJWTSource_InvalidTrustDomain(t *testing.T) {
	cfg := JWTConfig{
		FederationBundleEndpoints: map[string]string{"not a trust domain!!": "http://example.org/bundle"},
	}
	if _, err := startFederationJWTSource(context.Background(), cfg); err == nil {
		t.Fatal("expected error for an invalid trust domain name")
	}
}

func TestFederationJWTSource_GetJWTBundleForTrustDomain_NotYetFetched(t *testing.T) {
	source := newFederationJWTSource()
	_, err := source.GetJWTBundleForTrustDomain(spiffeid.RequireTrustDomainFromString("example.org"))
	if err == nil {
		t.Fatal("expected error when no bundle has been fetched for this trust domain yet")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/spire/... -run "TestStartFederationJWTSource|TestFederationJWTSource" -v`
Expected: FAIL — `startFederationJWTSource`, `federationJWTSource`, `newFederationJWTSource` don't exist yet (compile error).

- [ ] **Step 3: Implement — create `internal/spire/federation_source.go`**

```go
package spire

import (
	"context"
	"crypto/x509"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/jwtbundle"
	"github.com/spiffe/go-spiffe/v2/bundle/spiffebundle"
	"github.com/spiffe/go-spiffe/v2/federation"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

// federationJWTSource implements jwtbundle.Source by fetching and keeping
// live-updated one SPIFFE bundle per trust domain from a SPIFFE Federation
// Bundle Endpoint — no local SPIRE Agent / Workload API required. It is a
// drop-in alternative to workloadapi.JWTSource: jwtsvid.ParseAndValidate
// (via Client.ValidateJWTToken) calls the jwtbundle.Source interface, not
// this concrete type, so swapping between the two requires no change to
// validation logic.
type federationJWTSource struct {
	mu      sync.RWMutex
	bundles map[string]*spiffebundle.Bundle // trust domain name -> latest bundle
}

func newFederationJWTSource() *federationJWTSource {
	return &federationJWTSource{bundles: make(map[string]*spiffebundle.Bundle)}
}

// GetJWTBundleForTrustDomain implements jwtbundle.Source.
func (f *federationJWTSource) GetJWTBundleForTrustDomain(trustDomain spiffeid.TrustDomain) (*jwtbundle.Bundle, error) {
	f.mu.RLock()
	bundle, ok := f.bundles[trustDomain.Name()]
	f.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("no federation bundle fetched yet for trust domain %q", trustDomain.Name())
	}
	return bundle.GetJWTBundleForTrustDomain(trustDomain)
}

func (f *federationJWTSource) set(trustDomainName string, bundle *spiffebundle.Bundle) {
	f.mu.Lock()
	f.bundles[trustDomainName] = bundle
	f.mu.Unlock()
}

// federationBundleWatcher adapts federation.WatchBundle's callbacks for one
// trust domain into federationJWTSource. OnError logs and keeps serving the
// last-known-good bundle rather than tearing anything down — a transient
// endpoint outage must not blank out already-trusted key material, matching
// this codebase's "an outage never blanks known-good state" posture used
// elsewhere (e.g. cross-account AssumeRole's persistGeo).
type federationBundleWatcher struct {
	trustDomain spiffeid.TrustDomain
	source      *federationJWTSource
}

func (w *federationBundleWatcher) NextRefresh(refreshHint time.Duration) time.Duration {
	if refreshHint > 0 {
		return refreshHint
	}
	return 5 * time.Minute
}

func (w *federationBundleWatcher) OnUpdate(bundle *spiffebundle.Bundle) {
	w.source.set(w.trustDomain.Name(), bundle)
	slog.Info("federation bundle updated", "trust_domain", w.trustDomain.Name())
}

func (w *federationBundleWatcher) OnError(err error) {
	slog.Warn("federation bundle fetch failed, keeping last-known-good bundle",
		"trust_domain", w.trustDomain.Name(), "error", err)
}

// startFederationJWTSource performs one synchronous fetch per configured
// trust domain — failing fast on an unreachable endpoint or an invalid
// trust domain name, matching AssumeRole.Init's posture of surfacing
// misconfiguration at startup rather than on the first caller's request —
// then starts one background watcher goroutine per trust domain to keep
// the bundle live-updated for as long as ctx isn't cancelled.
func startFederationJWTSource(ctx context.Context, cfg JWTConfig) (*federationJWTSource, error) {
	source := newFederationJWTSource()

	var fetchOpts []federation.FetchOption
	if cfg.FederationCABundlePath != "" {
		pem, err := os.ReadFile(cfg.FederationCABundlePath)
		if err != nil {
			return nil, fmt.Errorf("read federation CA bundle %s: %w", cfg.FederationCABundlePath, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("no certificates found in federation CA bundle %s", cfg.FederationCABundlePath)
		}
		fetchOpts = append(fetchOpts, federation.WithWebPKIRoots(pool))
	}

	for tdName, url := range cfg.FederationBundleEndpoints {
		td, err := spiffeid.TrustDomainFromString(tdName)
		if err != nil {
			return nil, fmt.Errorf("invalid federation trust domain %q: %w", tdName, err)
		}

		bundle, err := federation.FetchBundle(ctx, td, url, fetchOpts...)
		if err != nil {
			return nil, fmt.Errorf("initial federation bundle fetch for %q from %s: %w", tdName, url, err)
		}
		source.set(tdName, bundle)
		slog.Info("fetched initial federation bundle", "trust_domain", tdName, "url", url)

		go func(td spiffeid.TrustDomain, url string) {
			watcher := &federationBundleWatcher{trustDomain: td, source: source}
			if err := federation.WatchBundle(ctx, td, url, watcher, fetchOpts...); err != nil && ctx.Err() == nil {
				slog.Error("federation bundle watcher stopped unexpectedly", "trust_domain", td.Name(), "error", err)
			}
		}(td, url)
	}

	return source, nil
}
```

- [ ] **Step 4: Run the new tests to verify they pass**

Run: `go test ./internal/spire/... -run "TestStartFederationJWTSource|TestFederationJWTSource" -v`
Expected: PASS for all four new tests.

- [ ] **Step 5: Widen `Client.jwtSource`'s field type to the `jwtbundle.Source` interface**

In `internal/spire/client.go`, the struct currently is:

```go
type Client struct {
	config    *Config
	source    *workloadapi.X509Source
	jwtSource *workloadapi.JWTSource
	mu        sync.RWMutex
}
```

Change the `jwtSource` field's type:

```go
type Client struct {
	config *Config
	source *workloadapi.X509Source
	// jwtSource is a jwtbundle.Source rather than the concrete
	// *workloadapi.JWTSource — either that (BundleSource="workload_api",
	// default) or *federationJWTSource (BundleSource="federation") gets
	// assigned here by Start(). jwtsvid.ParseAndValidate (called from
	// ValidateJWTToken) only needs the interface, so this widening
	// requires no change to validation logic.
	jwtSource jwtbundle.Source
	mu        sync.RWMutex
}
```

Add `"github.com/spiffe/go-spiffe/v2/bundle/jwtbundle"` to the import block.

- [ ] **Step 6: Update `Close()` — the interface has no `Close()` method**

`*workloadapi.JWTSource` has a `Close() error` method that isn't part of `jwtbundle.Source`; `*federationJWTSource` has no `Close()` at all (its background watchers stop via `ctx` cancellation, the same `ctx` `Start()` was called with). Replace `Close()`'s JWT-source block:

```go
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	var errs []error
	if c.source != nil {
		if err := c.source.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if closer, ok := c.jwtSource.(interface{ Close() error }); ok {
		if err := closer.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("errors closing SPIRE client: %v", errs)
	}
	return nil
}
```

A nil `c.jwtSource` (e.g. JWT never enabled) correctly fails the type assertion (`ok == false`) rather than needing a separate nil check — a type assertion on a nil interface value is safe and simply doesn't match.

- [ ] **Step 7: Branch `Start()`'s JWT block on `BundleSource`**

`Start()`'s JWT block (after Task 1's edit) currently is:

```go
	// Initialize JWT source if JWT auth is enabled
	if c.config.JWT.Enabled {
		jwtSource, err := workloadapi.NewJWTSource(ctx,
			workloadapi.WithClientOptions(
				workloadapi.WithAddr(c.config.AgentSocket),
			),
		)
		if err != nil {
			return fmt.Errorf("failed to create JWT source: %w", err)
		}

		c.mu.Lock()
		c.jwtSource = jwtSource
		c.mu.Unlock()

		slog.Info("JWT-SVID validation enabled",
			"audiences", c.config.JWT.Audiences,
		)
	}
```

Replace with:

```go
	// Initialize JWT source if JWT auth is enabled
	if c.config.JWT.Enabled {
		var jwtSource jwtbundle.Source
		switch c.config.JWT.BundleSource {
		case "federation":
			source, err := startFederationJWTSource(ctx, c.config.JWT)
			if err != nil {
				return fmt.Errorf("failed to start federation JWT source: %w", err)
			}
			jwtSource = source
			slog.Info("JWT-SVID validation enabled (federation bundle source, no local SPIRE Agent required)",
				"audiences", c.config.JWT.Audiences,
				"trust_domains", c.config.JWT.FederationBundleEndpoints,
			)
		default: // "" or "workload_api"
			source, err := workloadapi.NewJWTSource(ctx,
				workloadapi.WithClientOptions(
					workloadapi.WithAddr(c.config.AgentSocket),
				),
			)
			if err != nil {
				return fmt.Errorf("failed to create JWT source: %w", err)
			}
			jwtSource = source
			slog.Info("JWT-SVID validation enabled",
				"audiences", c.config.JWT.Audiences,
			)
		}

		c.mu.Lock()
		c.jwtSource = jwtSource
		c.mu.Unlock()
	}
```

Config.Validate() (Task 2) already guarantees `BundleSource` is `""`, `"workload_api"`, or `"federation"` by the time `Start()` runs — the `default` case here correctly covers both the empty-default and the explicit `"workload_api"` value without needing a third switch arm.

- [ ] **Step 8: Run the full build and test suite**

Run: `go build ./... && go test ./...`
Expected: no errors. `go vet ./...` and `golangci-lint run ./...` should also be clean (no new issues beyond whatever pre-existing ones the repo already has).

- [ ] **Step 9: Manual smoke test — federation mode end-to-end, no local agent socket**

This is the actual claim of the feature: prove it runs with `ALLOW_UNAUTHENTICATED=false`, `SPIRE_ENABLED=true`, `SPIRE_JWT_BUNDLE_SOURCE=federation`, and **no SPIRE Agent socket present at all** (don't set `SPIRE_AGENT_SOCKET`, or point it at a path that doesn't exist — federation mode must never touch it).

```bash
# Terminal 1: serve a real SPIFFE bundle document over HTTP for the test.
# (Any SPIRE Server's actual federation bundle endpoint works too, if one is reachable.)
cat > /tmp/serve-bundle.go <<'EOF'
package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"log"
	"net/http"

	"github.com/spiffe/go-spiffe/v2/bundle/spiffebundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

func main() {
	td := spiffeid.RequireTrustDomainFromString("example.org")
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	bundle := spiffebundle.FromJWTAuthorities(td, map[string]crypto.PublicKey{"kid1": &key.PublicKey})
	body, _ := bundle.Marshal()
	http.HandleFunc("/bundle", func(w http.ResponseWriter, r *http.Request) { w.Write(body) })
	log.Fatal(http.ListenAndServe(":9999", nil))
}
EOF
go run /tmp/serve-bundle.go &

# Terminal 2: run the satellite in federation mode, no SPIRE_AGENT_SOCKET at all.
SPIRE_ENABLED=true \
SPIRE_TRUST_DOMAINS=example.org \
SPIRE_JWT_ENABLED=true \
SPIRE_JWT_AUDIENCES=centcom-satellite \
SPIRE_JWT_BUNDLE_SOURCE=federation \
SPIRE_FEDERATION_BUNDLE_ENDPOINTS=example.org=http://localhost:9999/bundle \
go run ./cmd/centcom-satellite
```

Expected: the process starts and logs `"JWT-SVID validation enabled (federation bundle source, no local SPIRE Agent required)"` and `"fetched initial federation bundle"` — no attempt to connect to any Workload API socket, no error about a missing/unreachable socket path. `curl http://localhost:8080/healthz` and `.../readyz` both return 200. (A full "send a real JWT-SVID and confirm it validates" round-trip needs a real SPIRE-issued token and is out of scope for this manual smoke test — the fail-fast startup + healthy `/readyz` already prove the agent-less path works end-to-end for bundle acquisition, which is this task's actual claim.)

- [ ] **Step 10: Commit**

```bash
git add internal/spire/client.go internal/spire/federation_source.go internal/spire/federation_source_test.go
git commit -m "feat(spire): add federation bundle source for agent-less JWT-SVID validation"
```

---

### Task 4: CLAUDE.md narrative section + final verification

**Files:**
- Modify: `CLAUDE.md`

**Interfaces:** None — documentation only. This task's "test" is the final full-repo verification pass.

- [ ] **Step 1: Add a narrative subsection under Authentication**

In `CLAUDE.md`, find the `## Authentication` section (currently a short paragraph plus a numbered list: "1. SPIRE X.509 mTLS ... 2. SPIRE JWT-SVID ...", ending with "For local development, set `ALLOW_UNAUTHENTICATED=true`."). Add a new subsection directly after it:

```markdown
### Agent-less JWT-SVID validation (no local SPIRE Agent)

JWT-SVID validation only needs the issuing trust domain's JWT signing
public keys — it does not need this satellite to have its own issued
identity, unlike mTLS (which requires a local SPIRE Agent to attest this
workload and issue it a rotating X.509 SVID; there's no way around that).
Setting `SPIRE_JWT_BUNDLE_SOURCE=federation` fetches those public keys
directly from a SPIFFE Federation Bundle Endpoint over HTTPS instead of
the local SPIRE Workload API socket, removing the local-agent dependency
entirely for JWT-SVID-only deployments — this is what makes ECS/Fargate
(or any target that can't run a SPIRE Agent sidecar) viable. Requires
`SPIRE_MTLS_ENABLED=false`; mTLS mode is unaffected either way and
continues to require a local agent when used.
```

- [ ] **Step 2: Run the full build, vet, lint, and test suite**

```bash
go build ./...
go vet ./...
golangci-lint run ./...
go test ./...
```

Expected: all clean. `golangci-lint` should report the same pre-existing issue count as `main` before this branch (if any) — no new issues introduced by this plan's changes.

- [ ] **Step 3: Re-run Task 3's manual smoke test once more against the final code**

Repeat Task 3 Step 9 exactly, now that Task 4's doc change is the only thing since. Confirms nothing in the doc-only commit broke the build.

- [ ] **Step 4: Commit**

```bash
git add CLAUDE.md
git commit -m "docs: document agent-less JWT-SVID validation via SPIFFE federation"
```

---

## Self-Review

**Spec coverage:**
- Prerequisite X.509/MTLS decoupling → Task 1.
- New `SPIRE_JWT_BUNDLE_SOURCE`/`SPIRE_FEDERATION_BUNDLE_ENDPOINTS`/`SPIRE_FEDERATION_CA_BUNDLE_PATH` config + fail-fast validation (federation requires `MTLSEnabled=false`, endpoints must cover every trust domain) → Task 2.
- `federationJWTSource` client architecture, fail-fast initial fetch + background `WatchBundle` rotation, `Start()`/`Close()` wiring → Task 3.
- Helm chart implications (skip agent-socket volume/mount in federation mode) → explicitly out of scope for this plan, tracked as a companion task in the `philips-software/helm-charts` repo, exactly as the spec states and as the original AssumeRole plan handled its own companion chart work.
- Testing approach (unit tests with a fake bundle endpoint, no real SPIRE Agent needed) → Tasks 1-3's test steps; Task 3 Step 9 covers the manual end-to-end smoke test the spec calls for.

**Placeholder scan:** No TBD/TODO markers. Fixed one real issue during review: Task 3's manual smoke-test script had an invalid Go type-literal placeholder (`map[string]interface{ /* crypto.PublicKey */ }`) — corrected to `map[string]crypto.PublicKey` with the `"crypto"` import added.

**Type consistency:** `federationJWTSource`/`newFederationJWTSource`/`startFederationJWTSource(ctx, cfg JWTConfig) (*federationJWTSource, error)` are used identically across Task 3's test file and implementation. `Client.jwtSource jwtbundle.Source` (Task 3 Step 5) matches how Task 3 Step 7's `Start()` rewrite assigns to it (`var jwtSource jwtbundle.Source`) and how Task 3 Step 6's `Close()` rewrite handles it via type assertion. `JWTConfig.BundleSource`/`FederationBundleEndpoints`/`FederationCABundlePath` (Task 2) are the exact field names Task 3's `startFederationJWTSource` and `Start()` read.
