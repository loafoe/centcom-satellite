# Cross-account AWS AssumeRole Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let a centcom-satellite deployment assume an IAM role in a different AWS account, so its AWS-facing tasks (`cw_*`, `cost_explorer`, `guardduty_*`, `securityhub_*`) operate against that remote account while Kubernetes tasks keep using the local in-cluster identity.

**Architecture:** A new `internal/aws.Init` builds a process-wide cached `AssumeRoleProvider` once at startup (only when `AWS_ASSUME_ROLE_ARN` is set) and stores it in a package-level variable. The existing `internal/aws.LoadConfig` — already called, unmodified in signature, by all 17 AWS task files — transparently applies that shared provider when present. Startup fails fast via one `sts:GetCallerIdentity` call through the assumed credentials before the HTTP server starts serving.

**Tech Stack:** Go, `aws-sdk-go-v2` (`config`, `credentials/stscreds`, `service/sts`), existing task/registry framework.

**Spec:** `docs/superpowers/specs/2026-08-25-aws-cross-account-assumerole-design.md`

## Global Constraints

- Zero changes to any of the 17 existing AWS task files (`cw_*`, `cost_explorer`, `guardduty_*`, `securityhub_*`) — the switch happens entirely inside `internal/aws`.
- Backward compatible: when `AWS_ASSUME_ROLE_ARN` is unset (default `""`), every code path behaves byte-for-byte as it does today.
- `cluster_info/aws.go`'s account detection must keep using `config.LoadDefaultConfig` directly (not `awshelper.LoadConfig`) so it continues reporting the satellite's own local account, never the assumed-role target.
- Fail fast at startup: if `AWS_ASSUME_ROLE_ARN` is set and the assumed-role credentials don't verify via `GetCallerIdentity`, the process must exit non-zero before serving traffic.
- No per-request/per-payload account selection, no per-caller authz — this is a fixed, deployment-level, single-target-account feature (see spec's Non-goals).

---

### Task 1: Config surface for AssumeRole settings

**Files:**
- Modify: `internal/config/config.go`
- Test: `internal/config/config_test.go`
- Modify: `CLAUDE.md:152-167` (Configuration section — add new env vars to the bullet list)

**Interfaces:**
- Produces: `config.AWSAssumeRole` struct with fields `ARN string`, `ExternalID string`, `SessionName string`, embedded as `Config.AWSAssumeRole` — consumed by Task 3 (`main.go`) to build `awshelper.AssumeRoleOptions`.

- [ ] **Step 1: Write the failing tests**

Add to `internal/config/config_test.go`:

```go
func TestLoad_AWSAssumeRoleDefaultsEmpty(t *testing.T) {
	t.Setenv("ALLOW_UNAUTHENTICATED", "true")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.AWSAssumeRole.ARN != "" {
		t.Fatalf("AWSAssumeRole.ARN = %q, want empty by default", cfg.AWSAssumeRole.ARN)
	}
	if cfg.AWSAssumeRole.SessionName != "centcom-satellite" {
		t.Fatalf("AWSAssumeRole.SessionName = %q, want default centcom-satellite", cfg.AWSAssumeRole.SessionName)
	}
}

func TestLoad_AWSAssumeRoleFromEnv(t *testing.T) {
	t.Setenv("ALLOW_UNAUTHENTICATED", "true")
	t.Setenv("AWS_ASSUME_ROLE_ARN", "arn:aws:iam::123456789012:role/centcom-satellite-remote")
	t.Setenv("AWS_ASSUME_ROLE_EXTERNAL_ID", "shared-secret-id")
	t.Setenv("AWS_ASSUME_ROLE_SESSION_NAME", "custom-session")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.AWSAssumeRole.ARN != "arn:aws:iam::123456789012:role/centcom-satellite-remote" {
		t.Fatalf("AWSAssumeRole.ARN = %q, want the configured ARN", cfg.AWSAssumeRole.ARN)
	}
	if cfg.AWSAssumeRole.ExternalID != "shared-secret-id" {
		t.Fatalf("AWSAssumeRole.ExternalID = %q, want shared-secret-id", cfg.AWSAssumeRole.ExternalID)
	}
	if cfg.AWSAssumeRole.SessionName != "custom-session" {
		t.Fatalf("AWSAssumeRole.SessionName = %q, want custom-session", cfg.AWSAssumeRole.SessionName)
	}
}

func TestLoad_AWSAssumeRoleARNMustLookLikeIAMRoleARN(t *testing.T) {
	t.Setenv("ALLOW_UNAUTHENTICATED", "true")
	t.Setenv("AWS_ASSUME_ROLE_ARN", "not-an-arn")
	if _, err := Load(); err == nil {
		t.Fatal("expected error for malformed AWS_ASSUME_ROLE_ARN, got nil")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/config/... -run TestLoad_AWSAssumeRole -v`
Expected: FAIL — `cfg.AWSAssumeRole` doesn't exist yet (compile error).

- [ ] **Step 3: Implement the config struct, loading, and validation**

In `internal/config/config.go`, add the struct (near `FeaturesConfig`):

```go
// AWSAssumeRoleConfig configures cross-account AWS access via STS AssumeRole.
// When ARN is empty (the default), AWS tasks use the pod's own IRSA identity
// exactly as before — this feature is entirely additive and opt-in.
type AWSAssumeRoleConfig struct {
	// ARN is the target IAM role in the remote AWS account.
	ARN string
	// ExternalID is passed to AssumeRole for confused-deputy protection.
	// Optional — only required if the target role's trust policy demands it.
	ExternalID string
	// SessionName is the STS RoleSessionName, visible in the target
	// account's CloudTrail.
	SessionName string
}
```

Add `AWSAssumeRole AWSAssumeRoleConfig` as a field on `Config`, alongside `Features`.

In `Load()`, add to the `cfg := &Config{...}` literal:

```go
		AWSAssumeRole: AWSAssumeRoleConfig{
			ARN:         os.Getenv("AWS_ASSUME_ROLE_ARN"),
			ExternalID:  os.Getenv("AWS_ASSUME_ROLE_EXTERNAL_ID"),
			SessionName: getEnvString("AWS_ASSUME_ROLE_SESSION_NAME", "centcom-satellite"),
		},
```

In `Validate()`, add after the SPIRE validation block:

```go
	if c.AWSAssumeRole.ARN != "" && !strings.HasPrefix(c.AWSAssumeRole.ARN, "arn:aws:iam::") {
		errs = append(errs, "AWS_ASSUME_ROLE_ARN must be a valid IAM role ARN (arn:aws:iam::<account>:role/<name>)")
	}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/config/... -v`
Expected: PASS for all tests, including the three new ones and every pre-existing test in the file.

- [ ] **Step 5: Update CLAUDE.md's Configuration section**

In `CLAUDE.md`, after the `SECURITYHUB_WRITE_ENABLED` bullet (around line 167), add:

```markdown
- `AWS_ASSUME_ROLE_ARN` (default: unset) - Target IAM role ARN in a different AWS account. When set, all AWS data-retrieval/write tasks (`cw_*`, `cost_explorer`, `guardduty_*`, `securityhub_*`) operate against that remote account via STS AssumeRole, while Kubernetes tasks continue using the local in-cluster identity. Unset (default) preserves the original single-account behavior exactly. See `deploy/iam-policy-assumerole.json` for the source-account permission the satellite's own IRSA role needs.
- `AWS_ASSUME_ROLE_EXTERNAL_ID` (default: unset) - Optional STS ExternalId, passed to AssumeRole. Only needed if the target role's trust policy requires one.
- `AWS_ASSUME_ROLE_SESSION_NAME` (default: `centcom-satellite`) - STS RoleSessionName, visible in the target account's CloudTrail.
```

- [ ] **Step 6: Commit**

```bash
git add internal/config/config.go internal/config/config_test.go CLAUDE.md
git commit -m "feat(config): add AWS_ASSUME_ROLE_ARN/EXTERNAL_ID/SESSION_NAME settings"
```

---

### Task 2: `internal/aws` — shared cached AssumeRole credentials

**Files:**
- Modify: `internal/aws/client.go`
- Test: `internal/aws/client_test.go`

**Interfaces:**
- Consumes: nothing from Task 1 directly (this package doesn't import `internal/config` — it takes plain strings via `AssumeRoleOptions`, keeping `internal/aws` free of a config dependency).
- Produces: `AssumeRoleOptions{ARN, ExternalID, SessionName string}` and `Init(ctx context.Context, opts AssumeRoleOptions) error` — consumed by Task 3 (`main.go`), which builds `AssumeRoleOptions` from `cfg.AWSAssumeRole`. `LoadConfig(ctx, Options{Region string})` keeps its existing signature but now applies the shared credentials transparently — consumed unchanged by all 17 existing AWS task files.

**Note on existing dead field:** `Options` currently has an unused `AssumeRoleARN string` field (nothing in the codebase sets it — confirmed via `grep -rn AssumeRoleARN`). This task removes it; its purpose is fully replaced by the process-wide `Init`/package-var approach, which is what the design spec calls for (one fixed target account per deployment, not per-call).

- [ ] **Step 1: Write the failing tests**

Replace the contents of `internal/aws/client_test.go` with:

```go
package aws

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

func TestLoadConfig_AppliesRegion(t *testing.T) {
	cfg, err := LoadConfig(context.Background(), Options{Region: "eu-west-1"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Region != "eu-west-1" {
		t.Fatalf("region = %q, want eu-west-1", cfg.Region)
	}
}

func TestLoadConfig_EmptyOptionsOK(t *testing.T) {
	if _, err := LoadConfig(context.Background(), Options{}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestHasCredentials_EnvIndicator(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIAEXAMPLE")
	if !HasCredentials() {
		t.Fatal("HasCredentials() = false, want true when AWS_ACCESS_KEY_ID set")
	}
}

// fakeCredentialsProvider lets tests assert LoadConfig wired in a specific
// shared provider instance, without making any real AWS/network call.
type fakeCredentialsProvider struct{}

func (f *fakeCredentialsProvider) Retrieve(_ context.Context) (aws.Credentials, error) {
	return aws.Credentials{AccessKeyID: "fake"}, nil
}

func TestLoadConfig_UsesSharedAssumeRoleCredentialsWhenConfigured(t *testing.T) {
	fake := &fakeCredentialsProvider{}
	prev := assumeRoleCredentials
	assumeRoleCredentials = fake
	defer func() { assumeRoleCredentials = prev }()

	cfg, err := LoadConfig(context.Background(), Options{Region: "eu-west-1"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Credentials != fake {
		t.Fatalf("cfg.Credentials = %v, want the shared fake provider", cfg.Credentials)
	}
}

func TestLoadConfig_RepeatedCallsReuseSameCredentialsInstance(t *testing.T) {
	fake := &fakeCredentialsProvider{}
	prev := assumeRoleCredentials
	assumeRoleCredentials = fake
	defer func() { assumeRoleCredentials = prev }()

	cfg1, _ := LoadConfig(context.Background(), Options{Region: "eu-west-1"})
	cfg2, _ := LoadConfig(context.Background(), Options{Region: "us-east-1"})
	if cfg1.Credentials != cfg2.Credentials {
		t.Fatal("expected both LoadConfig calls to reuse the identical cached credentials instance, not build a new one per call")
	}
}

func TestInit_NoopWhenARNEmpty(t *testing.T) {
	prev := assumeRoleCredentials
	defer func() { assumeRoleCredentials = prev }()
	assumeRoleCredentials = nil

	if err := Init(context.Background(), AssumeRoleOptions{}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if assumeRoleCredentials != nil {
		t.Fatal("expected assumeRoleCredentials to remain nil when ARN is empty (no-op, no network call)")
	}
}

type fakeSTSAPI struct {
	out *sts.GetCallerIdentityOutput
	err error
}

func (f *fakeSTSAPI) GetCallerIdentity(_ context.Context, _ *sts.GetCallerIdentityInput, _ ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
	return f.out, f.err
}

func TestVerifyCallerIdentity_ReturnsAccountID(t *testing.T) {
	api := &fakeSTSAPI{out: &sts.GetCallerIdentityOutput{Account: aws.String("999999999999")}}
	accountID, err := verifyCallerIdentity(context.Background(), api)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if accountID != "999999999999" {
		t.Fatalf("accountID = %q, want 999999999999", accountID)
	}
}

func TestVerifyCallerIdentity_PropagatesError(t *testing.T) {
	api := &fakeSTSAPI{err: errors.New("access denied")}
	if _, err := verifyCallerIdentity(context.Background(), api); err == nil {
		t.Fatal("expected error to propagate, got nil")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/aws/... -v`
Expected: FAIL — `assumeRoleCredentials`, `Init`, `AssumeRoleOptions`, and `verifyCallerIdentity` don't exist yet (compile errors).

- [ ] **Step 3: Implement**

Replace the contents of `internal/aws/client.go` with:

```go
// Package aws provides shared AWS SDK v2 client configuration for tasks that
// retrieve data from AWS services (CloudWatch, CloudWatch Logs, Cost
// Explorer, GuardDuty, Security Hub), including optional cross-account
// access via STS AssumeRole.
package aws

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// Options controls how the AWS config is built for a request.
type Options struct {
	// Region overrides the default region when non-empty.
	Region string
}

// AssumeRoleOptions configures process-wide cross-account credentials.
type AssumeRoleOptions struct {
	// ARN is the target IAM role in the remote AWS account. Empty disables
	// the feature entirely (Init becomes a no-op).
	ARN string
	// ExternalID is passed to AssumeRole when non-empty.
	ExternalID string
	// SessionName is the STS RoleSessionName. Defaults to
	// "centcom-satellite" when empty.
	SessionName string
}

// assumeRoleCredentials holds the process-wide cached cross-account
// credentials provider, set once by Init before the HTTP server starts
// accepting requests. Left nil (the default) when AssumeRole isn't
// configured, in which case LoadConfig behaves exactly as it did before this
// feature existed.
var assumeRoleCredentials aws.CredentialsProvider

type stsAPI interface {
	GetCallerIdentity(ctx context.Context, in *sts.GetCallerIdentityInput, optFns ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error)
}

// Init sets up process-wide cross-account AssumeRole credentials when
// opts.ARN is set. It must be called once at startup, before any LoadConfig
// call and before the HTTP server starts accepting requests. It verifies the
// credentials with a single STS GetCallerIdentity call so misconfiguration
// (bad trust policy, wrong ExternalId) fails startup instead of surfacing
// later on the first task request.
func Init(ctx context.Context, opts AssumeRoleOptions) error {
	if opts.ARN == "" {
		return nil
	}

	baseCfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return fmt.Errorf("load base AWS config: %w", err)
	}

	sessionName := opts.SessionName
	if sessionName == "" {
		sessionName = "centcom-satellite"
	}

	provider := stscreds.NewAssumeRoleProvider(sts.NewFromConfig(baseCfg), opts.ARN, func(o *stscreds.AssumeRoleOptions) {
		o.RoleSessionName = sessionName
		if opts.ExternalID != "" {
			o.ExternalID = aws.String(opts.ExternalID)
		}
	})
	cached := aws.NewCredentialsCache(provider)

	verifyCfg := baseCfg.Copy()
	verifyCfg.Credentials = cached
	accountID, err := verifyCallerIdentity(ctx, sts.NewFromConfig(verifyCfg))
	if err != nil {
		return fmt.Errorf("verify assumed-role credentials for %s: %w", opts.ARN, err)
	}

	assumeRoleCredentials = cached
	slog.Info("cross-account AssumeRole configured", "role_arn", opts.ARN, "account_id", accountID)
	return nil
}

// verifyCallerIdentity calls STS GetCallerIdentity and returns the resolved
// account ID, extracted so Init's fail-fast check is unit-testable without a
// real STS call.
func verifyCallerIdentity(ctx context.Context, api stsAPI) (string, error) {
	out, err := api.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return "", err
	}
	return aws.ToString(out.Account), nil
}

// LoadConfig builds an aws.Config from the SDK default credential chain
// (IRSA / Pod Identity in EKS), applying the per-request Region from opts.
// When Init has configured process-wide cross-account credentials, those
// override the default chain's credentials — every AWS task calling
// LoadConfig then transparently operates against the remote account.
func LoadConfig(ctx context.Context, opts Options) (aws.Config, error) {
	loadOpts := []func(*config.LoadOptions) error{}
	if opts.Region != "" {
		loadOpts = append(loadOpts, config.WithRegion(opts.Region))
	}

	cfg, err := config.LoadDefaultConfig(ctx, loadOpts...)
	if err != nil {
		return aws.Config{}, err
	}

	if assumeRoleCredentials != nil {
		cfg.Credentials = assumeRoleCredentials
	}

	return cfg, nil
}

// HasCredentials reports whether AWS credentials appear to be available,
// matching the detection used elsewhere in centcom-satellite.
func HasCredentials() bool {
	indicators := []string{
		"AWS_ACCESS_KEY_ID",
		"AWS_ROLE_ARN",
		"AWS_WEB_IDENTITY_TOKEN_FILE",
		"AWS_CONTAINER_CREDENTIALS_FULL_URI",
		"AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
	}
	for _, env := range indicators {
		if os.Getenv(env) != "" {
			return true
		}
	}
	if _, err := os.Stat("/var/run/secrets/eks.amazonaws.com/serviceaccount/token"); err == nil {
		return true
	}
	return false
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/aws/... -v`
Expected: PASS for every test.

- [ ] **Step 5: Confirm no other package referenced the removed field**

Run: `grep -rn "AssumeRoleARN" --include="*.go" .`
Expected: no matches (the only prior reference was the now-removed `Options.AssumeRoleARN` field itself).

- [ ] **Step 6: Commit**

```bash
git add internal/aws/client.go internal/aws/client_test.go
git commit -m "feat(aws): add process-wide cached cross-account AssumeRole credentials"
```

---

### Task 3: Wire `awshelper.Init` into startup with fail-fast

**Files:**
- Modify: `cmd/centcom-satellite/main.go:113-120`
- Modify: `CLAUDE.md` (Configuration section, right after the bullets added in Task 1)

**Interfaces:**
- Consumes: `config.AWSAssumeRoleConfig` (Task 1) and `awshelper.AssumeRoleOptions` / `awshelper.Init` (Task 2).
- Produces: nothing new for later tasks — this is the integration point that makes the feature live end-to-end.

`main.go` has no existing test file (it's the entrypoint, wired up by hand like the adjacent SPIRE/k8s-client setup) — this task is verified by a manual smoke test instead of `go test`, matching how the rest of `main.go`'s startup sequencing is validated in this codebase.

- [ ] **Step 1: Add the import**

In `cmd/centcom-satellite/main.go`, add to the import block (alongside the existing `"github.com/loafoe/centcom-satellite/internal/k8s"` line):

```go
	awshelper "github.com/loafoe/centcom-satellite/internal/aws"
```

- [ ] **Step 2: Insert the Init call between k8s client setup and task registry setup**

Currently (`cmd/centcom-satellite/main.go:113-120`):

```go
	// Setup Kubernetes client (instrumented with Prometheus metrics)
	k8sClient, err := k8s.NewClient(metrics)
	if err != nil {
		slog.Error("failed to create kubernetes client", "error", err)
		os.Exit(1)
	}

	// Setup task registry
```

Change to:

```go
	// Setup Kubernetes client (instrumented with Prometheus metrics)
	k8sClient, err := k8s.NewClient(metrics)
	if err != nil {
		slog.Error("failed to create kubernetes client", "error", err)
		os.Exit(1)
	}

	// Setup cross-account AWS AssumeRole credentials, if configured. This is
	// independent of the Kubernetes client above: AWS tasks below will use
	// the assumed-role identity for the remote account, while Kubernetes
	// tasks keep using k8sClient for the local cluster. A no-op when
	// AWS_ASSUME_ROLE_ARN is unset. Fails fast — misconfigured trust
	// policies/ExternalId must not surface only on the first task call.
	if err := awshelper.Init(ctx, awshelper.AssumeRoleOptions{
		ARN:         cfg.AWSAssumeRole.ARN,
		ExternalID:  cfg.AWSAssumeRole.ExternalID,
		SessionName: cfg.AWSAssumeRole.SessionName,
	}); err != nil {
		slog.Error("failed to configure cross-account AWS AssumeRole", "error", err)
		os.Exit(1)
	}

	// Setup task registry
```

- [ ] **Step 3: Build to verify it compiles**

Run: `go build ./...`
Expected: no errors.

- [ ] **Step 4: Manual smoke test — no-op path (backward compatibility)**

Run:
```bash
ALLOW_UNAUTHENTICATED=true go run ./cmd/centcom-satellite &
sleep 1
curl -s http://localhost:8080/healthz
kill %1
```
Expected: the server starts and `/healthz` responds normally — no log line about "cross-account AssumeRole configured" appears, since `AWS_ASSUME_ROLE_ARN` is unset. This confirms the default path is unchanged.

- [ ] **Step 5: Manual smoke test — fail-fast path**

Run (using a role ARN you do not have permission to assume, or one that doesn't exist, so `AssumeRole`/`GetCallerIdentity` fails):
```bash
ALLOW_UNAUTHENTICATED=true AWS_ASSUME_ROLE_ARN="arn:aws:iam::123456789012:role/does-not-exist" go run ./cmd/centcom-satellite
```
Expected: the process logs `failed to configure cross-account AWS AssumeRole` and exits non-zero — it must NOT start the HTTP server. Confirm with `echo $?` after the process exits (non-zero).

- [ ] **Step 6: Update CLAUDE.md**

Add one sentence to the `AWS_ASSUME_ROLE_ARN` bullet added in Task 1, clarifying startup behavior, if not already covered. Skip if Task 1's wording already states the fail-fast behavior; otherwise append: "Misconfiguration (bad trust policy, wrong ExternalId) is caught at startup — the process exits before serving traffic rather than failing on the first task call."

- [ ] **Step 7: Commit**

```bash
git add cmd/centcom-satellite/main.go CLAUDE.md
git commit -m "feat: wire cross-account AssumeRole into startup with fail-fast validation"
```

---

### Task 4: IAM reference artifacts (source-account policy + target-account trust example)

**Files:**
- Create: `deploy/iam-policy-assumerole.json`
- Create: `deploy/iam-trust-policy-assumerole-target-example.json`
- Modify: `CLAUDE.md` (Configuration section — cross-reference these files from the `AWS_ASSUME_ROLE_ARN` bullet, if not already done in Task 1/3)

**Interfaces:** None — these are static reference documents, not consumed by any Go code. No dependency on Tasks 1-3's code, so this task can run any time, but it's sequenced last because the placeholder ARN documented here reads more clearly once the reader has seen the env vars it maps to.

- [ ] **Step 1: Create the source-account policy**

Create `deploy/iam-policy-assumerole.json`, following the exact convention of `deploy/iam-policy-guardduty.json` (flat AWS-managed-policy-document JSON, no comments — JSON doesn't support them):

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "CentcomAssumeRoleCrossAccount",
      "Effect": "Allow",
      "Action": "sts:AssumeRole",
      "Resource": "arn:aws:iam::TARGET_ACCOUNT_ID:role/TARGET_ROLE_NAME"
    }
  ]
}
```

This attaches to the satellite's *own* IRSA role (source account). Replace `TARGET_ACCOUNT_ID`/`TARGET_ROLE_NAME` with the actual remote role — unlike the read-only policies (`guardduty`/`securityhub`), this one can't use `"Resource": "*"`: granting `sts:AssumeRole` on `*` would let this satellite assume *any* role in *any* account that trusts it, defeating the point of scoping to one fixed target account.

- [ ] **Step 2: Create the target-account trust policy example**

Create `deploy/iam-trust-policy-assumerole-target-example.json`:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "TrustCentcomSatelliteSourceRole",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::SOURCE_ACCOUNT_ID:role/SOURCE_IRSA_ROLE_NAME"
      },
      "Action": "sts:AssumeRole",
      "Condition": {
        "StringEquals": {
          "sts:ExternalId": "OPTIONAL_EXTERNAL_ID_IF_USED"
        }
      }
    }
  ]
}
```

This is a *reference example* for the trust policy on the role in the **target** (remote) AWS account — outside this repo's own deploy scope, since this repo only controls the source account's IRSA role. Document, in a comment directly above this step's code block in this plan file's execution notes (or as a follow-up commit message), that:
- `SOURCE_ACCOUNT_ID`/`SOURCE_IRSA_ROLE_NAME` is the satellite's own IRSA role ARN (visible via `aws.irsa.roleArnOverride` or the Crossplane-managed role name in the Helm chart).
- Omit the entire `Condition` block if no `AWS_ASSUME_ROLE_EXTERNAL_ID` is configured.

- [ ] **Step 3: Validate JSON syntax**

Run:
```bash
python3 -m json.tool deploy/iam-policy-assumerole.json > /dev/null && echo OK
python3 -m json.tool deploy/iam-trust-policy-assumerole-target-example.json > /dev/null && echo OK
```
Expected: `OK` printed twice, confirming both files parse as valid JSON.

- [ ] **Step 4: Cross-reference from CLAUDE.md**

Confirm the `AWS_ASSUME_ROLE_ARN` bullet in `CLAUDE.md` (added in Task 1) already references `deploy/iam-policy-assumerole.json`. If it references a different filename, fix it to match what was actually created in Step 1. Add one clause mentioning the target-side example:

```markdown
See `deploy/iam-trust-policy-assumerole-target-example.json` for the trust policy the *target* account's role needs (outside this repo's deploy scope, but documented here to save a round trip).
```

- [ ] **Step 5: Commit**

```bash
git add deploy/iam-policy-assumerole.json deploy/iam-trust-policy-assumerole-target-example.json CLAUDE.md
git commit -m "docs(deploy): add IAM reference policies for cross-account AssumeRole"
```

---

## Self-Review

**Spec coverage:**
- Config surface (`AWS_ASSUME_ROLE_ARN`/`EXTERNAL_ID`/`SESSION_NAME`) → Task 1.
- `internal/aws.Init` + shared cached credentials + unchanged `LoadConfig` signature (zero changes to the 17 task files) → Task 2.
- Fail-fast startup validation via `GetCallerIdentity` → Task 2 (`Init` itself) + Task 3 (wiring/manual verification).
- `cluster_info/aws.go` isolation (keeps reporting local account) → explicitly called out as a Global Constraint; no code change needed there, confirmed by design (it already calls `config.LoadDefaultConfig` directly, not `awshelper.LoadConfig`) — no task modifies that file, which is correct.
- Deploy IAM artifacts (source policy + target trust example) → Task 4.
- Helm chart changes (`httpRoute.hostname`, `aws.assumeRole.*` values, Crossplane policy/attachment) → explicitly out of scope for this plan; tracked as a companion task in the `philips-software/helm-charts` repo per the spec.
- Observability (no new metrics, startup log line) → covered by the `slog.Info` call inside `Init` (Task 2, Step 3).

**Placeholder scan:** No TBD/TODO markers; every step has literal code or exact shell commands.

**Type consistency:** `AssumeRoleOptions{ARN, ExternalID, SessionName}` (Task 2) matches the field names used when constructing it in Task 3 (`cfg.AWSAssumeRole.ARN` etc. from Task 1's `AWSAssumeRoleConfig{ARN, ExternalID, SessionName}`). `Init(ctx, AssumeRoleOptions) error` signature is identical between Task 2's implementation and Task 3's call site. `verifyCallerIdentity(ctx, stsAPI) (string, error)` is used identically in Task 2's tests and implementation.
