# AWS Security Hub Support Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add opt-in AWS Security Hub support to centcom-satellite: read tasks for findings/standards retrieval and one write task for updating a finding's Workflow.Status/Note, mirroring the existing `guardduty_*` task family.

**Architecture:** Each Security Hub operation is its own `task.Task` implementation in `internal/task/securityhub_*`, dispatched via the existing `/task` endpoint. A shared `internal/task/securityhub_common` package holds filter-building and finding-normalization helpers. Two new feature flags (`SECURITYHUB_ENABLED` for reads, `SECURITYHUB_WRITE_ENABLED` for the update task) gate registration in `main.go`, following the `GuardDutyEnabled` pattern exactly.

**Tech Stack:** Go 1.25, `github.com/aws/aws-sdk-go-v2/service/securityhub` (new dependency), existing `internal/aws` credential helper, standard library `encoding/json`.

## Global Constraints

- Follow the approved spec exactly: `docs/specs/2026-07-27-securityhub-support-design.md`.
- Read tasks are gated by `SECURITYHUB_ENABLED`; the write task is gated separately by `SECURITYHUB_WRITE_ENABLED`. Both default to `false`.
- `GetFindings` supports `MaxResults` 1–100 (AWS hard limit); default to 100 when unset/out of range, mirroring how `guardduty_list_findings` caps at 50.
- `BatchUpdateFindings` supports at most 100 `FindingIdentifiers` per call (AWS hard limit) — enforce with a task-level error, not a raw AWS error passthrough.
- No same-`ProductArn` constraint exists for `BatchUpdateFindings` — do not add cross-validation beyond the 100-item cap.
- `securityhub_update_findings` payload requires at least one of `workflow_status` or `note` to be set.
- Every new task package gets its own `task_test.go` using an injected fake client via `NewWithClientFactory`, mirroring `internal/task/guardduty_list_findings/task_test.go`.
- Preserve the full raw SDK finding in a `detail json.RawMessage` field on the normalized `Finding` model, same as `guardduty_common.Finding.Detail`.
- Default `record_state` filter to `ACTIVE` only when unset, matching the Security Hub console default (same spirit as GuardDuty's `archived` default).
- `securityhub_get_findings_statistics` paginates `GetFindings` client-side, capped at 10 pages; report `truncated: true` + `next_token` if the cap is hit — never silently present partial counts as complete.
- Commit after each task once its tests pass. Use `git add <specific files>`, never `git add -A`/`.`.

## File Structure

- `go.mod` / `go.sum` — add `github.com/aws/aws-sdk-go-v2/service/securityhub`
- `internal/task/securityhub_common/models.go` — `Finding`, `Standard`, `HubStatus`, `StatCount` normalized structs + `NormalizeFinding`
- `internal/task/securityhub_common/models_test.go`
- `internal/task/securityhub_common/filter.go` — `Filter` struct + `BuildFilters()` + `SortCriteria()` helper
- `internal/task/securityhub_common/filter_test.go`
- `internal/task/securityhub_list_standards/task.go` + `task_test.go`
- `internal/task/securityhub_get_findings/task.go` + `task_test.go`
- `internal/task/securityhub_get_findings_statistics/task.go` + `task_test.go`
- `internal/task/securityhub_update_findings/task.go` + `task_test.go`
- `internal/config/config.go` — add `SecurityHubEnabled` / `SecurityHubWriteEnabled` fields + env wiring
- `internal/config/config_test.go` — test coverage for both new flags
- `internal/task/cluster_info/task.go` — add `SecurityHub` / `SecurityHubWrite` capability fields
- `cmd/centcom-satellite/main.go` — import + register the four new tasks, wire capabilities
- `deploy/iam-policy-securityhub.json` — new (read)
- `deploy/iam-policy-securityhub-write.json` — new (write)
- `deploy/deployment.yaml` — commented env var examples
- `README.md` — task table rows + feature-flag rows
- `CLAUDE.md` — Current Tasks subsection + Configuration env var rows

---

### Task 1: Add securityhub SDK dependency and `securityhub_common` normalized models

**Files:**
- Modify: `go.mod`, `go.sum`
- Create: `internal/task/securityhub_common/models.go`
- Test: `internal/task/securityhub_common/models_test.go`

**Interfaces:**
- Produces:
  - `type Finding struct { ID, ProductArn, ProductName, Title, Description, SeverityLabel, WorkflowStatus, RecordState, ComplianceStatus, ResourceType, ResourceID, AWSAccountID, Region, CreatedAt, UpdatedAt string; SeverityNormalized int32; Types []string; Detail json.RawMessage }`
  - `type Standard struct { StandardsArn, Name, Description, Status string; EnabledByDefault bool }`
  - `type HubStatus struct { HubArn, SubscribedAt string; AutoEnableControls bool; ControlFindingGenerator string }`
  - `type StatCount struct { Key string; Count int32 }`
  - `func NormalizeFinding(f types.AwsSecurityFinding) Finding`

- [ ] **Step 1: Add the SDK dependency**

Run:
```bash
go get github.com/aws/aws-sdk-go-v2/service/securityhub@latest
go mod tidy
```

- [ ] **Step 2: Verify it builds**

Run: `go build ./...`
Expected: succeeds with no errors (the dependency is unused so far, which is fine at this stage — `go mod tidy` only removes truly unreferenced *indirect* deps, and this one will be referenced by Task 2 immediately after).

- [ ] **Step 3: Write the failing test for `NormalizeFinding`**

Create `internal/task/securityhub_common/models_test.go`:

```go
package securityhub_common

import (
	"encoding/json"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/securityhub/types"
)

func TestNormalizeFinding_MapsCoreFields(t *testing.T) {
	sdk := types.AwsSecurityFinding{
		Id:          aws.String("finding-1"),
		ProductArn:  aws.String("arn:aws:securityhub:us-east-1::product/aws/guardduty"),
		ProductName: aws.String("GuardDuty"),
		Title:       aws.String("Some threat"),
		Description: aws.String("A description"),
		Types:       []string{"TTPs/Command and Control"},
		Severity: &types.Severity{
			Label:      types.SeverityLabelHigh,
			Normalized: aws.Int32(70),
		},
		Workflow:      &types.Workflow{Status: types.WorkflowStatusNew},
		RecordState:   types.RecordStateActive,
		AwsAccountId:  aws.String("123456789012"),
		Region:        aws.String("us-east-1"),
		CreatedAt:     aws.String("2026-07-01T00:00:00Z"),
		UpdatedAt:     aws.String("2026-07-02T00:00:00Z"),
		Resources: []types.Resource{
			{Id: aws.String("arn:aws:ec2:us-east-1:123456789012:instance/i-1"), Type: aws.String("AwsEc2Instance")},
		},
	}

	got := NormalizeFinding(sdk)

	if got.ID != "finding-1" {
		t.Errorf("ID = %q, want finding-1", got.ID)
	}
	if got.ProductArn != "arn:aws:securityhub:us-east-1::product/aws/guardduty" {
		t.Errorf("ProductArn = %q", got.ProductArn)
	}
	if got.ProductName != "GuardDuty" {
		t.Errorf("ProductName = %q", got.ProductName)
	}
	if got.SeverityLabel != "HIGH" {
		t.Errorf("SeverityLabel = %q, want HIGH", got.SeverityLabel)
	}
	if got.SeverityNormalized != 70 {
		t.Errorf("SeverityNormalized = %d, want 70", got.SeverityNormalized)
	}
	if got.WorkflowStatus != "NEW" {
		t.Errorf("WorkflowStatus = %q, want NEW", got.WorkflowStatus)
	}
	if got.RecordState != "ACTIVE" {
		t.Errorf("RecordState = %q, want ACTIVE", got.RecordState)
	}
	if got.ResourceType != "AwsEc2Instance" {
		t.Errorf("ResourceType = %q, want AwsEc2Instance", got.ResourceType)
	}
	if got.ResourceID != "arn:aws:ec2:us-east-1:123456789012:instance/i-1" {
		t.Errorf("ResourceID = %q", got.ResourceID)
	}
	if got.AWSAccountID != "123456789012" {
		t.Errorf("AWSAccountID = %q", got.AWSAccountID)
	}
	if len(got.Types) != 1 || got.Types[0] != "TTPs/Command and Control" {
		t.Errorf("Types = %v", got.Types)
	}
	if got.Detail == nil {
		t.Fatal("expected Detail to be populated")
	}
	var roundTrip types.AwsSecurityFinding
	// Detail is a marshaled types.AwsSecurityFinding-shaped JSON; just confirm it decodes to valid JSON.
	if err := json.Unmarshal(got.Detail, &roundTrip); err != nil {
		t.Errorf("Detail did not round-trip as JSON: %v", err)
	}
}

func TestNormalizeFinding_NoResourcesLeavesResourceFieldsEmpty(t *testing.T) {
	sdk := types.AwsSecurityFinding{
		Id:         aws.String("finding-2"),
		ProductArn: aws.String("arn:x"),
		Severity:   &types.Severity{Label: types.SeverityLabelLow},
	}
	got := NormalizeFinding(sdk)
	if got.ResourceType != "" || got.ResourceID != "" {
		t.Errorf("expected empty resource fields, got type=%q id=%q", got.ResourceType, got.ResourceID)
	}
}
```

- [ ] **Step 4: Run the test to verify it fails**

Run: `go test ./internal/task/securityhub_common/... -run TestNormalizeFinding -v`
Expected: FAIL — package `securityhub_common` / function `NormalizeFinding` does not exist yet.

- [ ] **Step 5: Implement `models.go`**

Create `internal/task/securityhub_common/models.go`:

```go
// Package securityhub_common holds shared payload fields, filter construction,
// and normalized output models for the Security Hub tasks.
package securityhub_common

import (
	"encoding/json"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/securityhub/types"
)

// Finding is the normalized finding model. The full SDK finding is preserved in
// Detail so a dashboard can render everything without the satellite having to
// model every nested Security Hub structure.
type Finding struct {
	ID                  string          `json:"id"`
	ProductArn          string          `json:"product_arn"`
	ProductName         string          `json:"product_name,omitempty"`
	Title               string          `json:"title,omitempty"`
	Description         string          `json:"description,omitempty"`
	Types               []string        `json:"types,omitempty"`
	SeverityLabel       string          `json:"severity_label,omitempty"`
	SeverityNormalized  int32           `json:"severity_normalized,omitempty"`
	WorkflowStatus      string          `json:"workflow_status,omitempty"`
	RecordState         string          `json:"record_state,omitempty"`
	ComplianceStatus    string          `json:"compliance_status,omitempty"`
	ResourceType        string          `json:"resource_type,omitempty"`
	ResourceID          string          `json:"resource_id,omitempty"`
	AWSAccountID        string          `json:"aws_account_id,omitempty"`
	Region              string          `json:"region,omitempty"`
	CreatedAt           string          `json:"created_at,omitempty"`
	UpdatedAt           string          `json:"updated_at,omitempty"`
	Detail              json.RawMessage `json:"detail,omitempty"`
}

// NormalizeFinding maps an SDK finding to the normalized model. The full finding
// is marshaled into Detail; marshal failures leave Detail nil rather than erroring.
func NormalizeFinding(f types.AwsSecurityFinding) Finding {
	out := Finding{
		ID:           aws.ToString(f.Id),
		ProductArn:   aws.ToString(f.ProductArn),
		ProductName:  aws.ToString(f.ProductName),
		Title:        aws.ToString(f.Title),
		Description:  aws.ToString(f.Description),
		Types:        f.Types,
		RecordState:  string(f.RecordState),
		AWSAccountID: aws.ToString(f.AwsAccountId),
		Region:       aws.ToString(f.Region),
		CreatedAt:    aws.ToString(f.CreatedAt),
		UpdatedAt:    aws.ToString(f.UpdatedAt),
	}
	if f.Severity != nil {
		out.SeverityLabel = string(f.Severity.Label)
		out.SeverityNormalized = aws.ToInt32(f.Severity.Normalized)
	}
	if f.Workflow != nil {
		out.WorkflowStatus = string(f.Workflow.Status)
	}
	if f.Compliance != nil {
		out.ComplianceStatus = string(f.Compliance.Status)
	}
	if len(f.Resources) > 0 {
		out.ResourceType = aws.ToString(f.Resources[0].Type)
		out.ResourceID = aws.ToString(f.Resources[0].Id)
	}
	if raw, err := json.Marshal(f); err == nil {
		out.Detail = raw
	}
	return out
}

// Standard is the normalized compliance standard model, combining
// DescribeStandards metadata with the account's subscription status.
type Standard struct {
	StandardsArn     string `json:"standards_arn"`
	Name             string `json:"name,omitempty"`
	Description      string `json:"description,omitempty"`
	EnabledByDefault bool   `json:"enabled_by_default"`
	Status           string `json:"status,omitempty"`
}

// HubStatus is the normalized DescribeHub result.
type HubStatus struct {
	HubArn                   string `json:"hub_arn"`
	SubscribedAt             string `json:"subscribed_at,omitempty"`
	AutoEnableControls       bool   `json:"auto_enable_controls"`
	ControlFindingGenerator  string `json:"control_finding_generator,omitempty"`
}

// StatCount is one bucket in a findings-statistics breakdown.
type StatCount struct {
	Key   string `json:"key"`
	Count int32  `json:"count"`
}
```

- [ ] **Step 6: Run gofmt and the test again**

Run:
```bash
gofmt -w internal/task/securityhub_common/models.go
go test ./internal/task/securityhub_common/... -v
```
Expected: PASS for both `TestNormalizeFinding_MapsCoreFields` and `TestNormalizeFinding_NoResourcesLeavesResourceFieldsEmpty`.

- [ ] **Step 7: Commit**

```bash
git add go.mod go.sum internal/task/securityhub_common/models.go internal/task/securityhub_common/models_test.go
git commit -m "feat(securityhub): add SDK dependency and normalized Finding/Standard models"
```

---

### Task 2: `securityhub_common.Filter` — build `AwsSecurityFindingFilters` + sort criteria

**Files:**
- Create: `internal/task/securityhub_common/filter.go`
- Test: `internal/task/securityhub_common/filter_test.go`

**Interfaces:**
- Consumes: nothing new (independent of Task 1's models, but lives in the same package).
- Produces:
  - `type Filter struct { SeverityLabels []string; Types []string; ProductName string; WorkflowStatus []string; RecordState string; ResourceType string; AWSAccountID string; UpdatedAfter, UpdatedBefore string }` (all JSON tags `omitempty`, snake_case)
  - `func (f Filter) BuildFilters() *types.AwsSecurityFindingFilters`
  - `func SortCriteria(field string, desc bool) []types.SortCriterion`

- [ ] **Step 1: Write the failing tests**

Create `internal/task/securityhub_common/filter_test.go`:

```go
package securityhub_common

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/securityhub/types"
)

func TestBuildFilters_DefaultsToActiveRecordState(t *testing.T) {
	f := Filter{}.BuildFilters()
	if len(f.RecordState) != 1 || f.RecordState[0].Value == nil || *f.RecordState[0].Value != "ACTIVE" {
		t.Fatalf("RecordState = %+v, want [ACTIVE]", f.RecordState)
	}
	if f.RecordState[0].Comparison != types.StringFilterComparisonEquals {
		t.Errorf("comparison = %v, want EQUALS", f.RecordState[0].Comparison)
	}
}

func TestBuildFilters_ExplicitRecordStateOverridesDefault(t *testing.T) {
	f := Filter{RecordState: "ARCHIVED"}.BuildFilters()
	if len(f.RecordState) != 1 || *f.RecordState[0].Value != "ARCHIVED" {
		t.Fatalf("RecordState = %+v, want [ARCHIVED]", f.RecordState)
	}
}

func TestBuildFilters_FullFilter(t *testing.T) {
	filter := Filter{
		SeverityLabels: []string{"HIGH", "CRITICAL"},
		Types:          []string{"TTPs/Command and Control"},
		ProductName:    "GuardDuty",
		WorkflowStatus: []string{"NEW", "NOTIFIED"},
		RecordState:    "ACTIVE",
		ResourceType:   "AwsEc2Instance",
		AWSAccountID:   "123456789012",
		UpdatedAfter:   "2026-07-01T00:00:00Z",
		UpdatedBefore:  "2026-07-27T00:00:00Z",
	}
	f := filter.BuildFilters()

	if len(f.SeverityLabel) != 2 {
		t.Errorf("SeverityLabel len = %d, want 2", len(f.SeverityLabel))
	}
	if len(f.Types) != 1 || *f.Types[0].Value != "TTPs/Command and Control" {
		t.Errorf("Types = %+v", f.Types)
	}
	if len(f.ProductName) != 1 || *f.ProductName[0].Value != "GuardDuty" {
		t.Errorf("ProductName = %+v", f.ProductName)
	}
	if len(f.WorkflowStatus) != 2 {
		t.Errorf("WorkflowStatus len = %d, want 2", len(f.WorkflowStatus))
	}
	if len(f.ResourceType) != 1 || *f.ResourceType[0].Value != "AwsEc2Instance" {
		t.Errorf("ResourceType = %+v", f.ResourceType)
	}
	if len(f.AwsAccountId) != 1 || *f.AwsAccountId[0].Value != "123456789012" {
		t.Errorf("AwsAccountId = %+v", f.AwsAccountId)
	}
	if len(f.UpdatedAt) != 1 || f.UpdatedAt[0].DateRange != nil {
		t.Fatalf("UpdatedAt = %+v, want a single DateFilter with Start/End set", f.UpdatedAt)
	}
	if *f.UpdatedAt[0].Start != "2026-07-01T00:00:00Z" || *f.UpdatedAt[0].End != "2026-07-27T00:00:00Z" {
		t.Errorf("UpdatedAt range = [%s,%s]", *f.UpdatedAt[0].Start, *f.UpdatedAt[0].End)
	}
}

func TestBuildFilters_EmptyFiltersOmitted(t *testing.T) {
	f := Filter{}.BuildFilters()
	if len(f.Types) != 0 || len(f.ProductName) != 0 || len(f.WorkflowStatus) != 0 || len(f.ResourceType) != 0 || len(f.AwsAccountId) != 0 || len(f.UpdatedAt) != 0 {
		t.Errorf("expected all unset filters to be empty, got %+v", f)
	}
}

func TestSortCriteria_Defaults(t *testing.T) {
	sc := SortCriteria("", true)
	if len(sc) != 1 || *sc[0].Field != "SeverityNormalized" {
		t.Fatalf("default field = %+v, want SeverityNormalized", sc)
	}
	if sc[0].SortOrder != types.SortOrderDescending {
		t.Errorf("order = %q, want desc", sc[0].SortOrder)
	}
}

func TestSortCriteria_AscendingCustomField(t *testing.T) {
	sc := SortCriteria("UpdatedAt", false)
	if *sc[0].Field != "UpdatedAt" {
		t.Errorf("field = %q, want UpdatedAt", *sc[0].Field)
	}
	if sc[0].SortOrder != types.SortOrderAscending {
		t.Errorf("order = %q, want asc", sc[0].SortOrder)
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/task/securityhub_common/... -run 'TestBuildFilters|TestSortCriteria' -v`
Expected: FAIL — `Filter`, `BuildFilters`, `SortCriteria` undefined.

- [ ] **Step 3: Implement `filter.go`**

Create `internal/task/securityhub_common/filter.go`:

```go
package securityhub_common

import (
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/securityhub/types"
)

// Filter is the pragmatic subset of AwsSecurityFindingFilters we expose.
// Every field is optional except RecordState, which defaults to "ACTIVE"
// when empty (matching the Security Hub console default).
type Filter struct {
	// SeverityLabels keeps findings whose SeverityLabel is in this list
	// (INFORMATIONAL, LOW, MEDIUM, HIGH, CRITICAL).
	SeverityLabels []string `json:"severity_labels,omitempty"`
	// Types keeps findings whose Type is in this list (exact match).
	Types []string `json:"types,omitempty"`
	// ProductName keeps findings from this product (e.g. "GuardDuty", "Macie").
	ProductName string `json:"product_name,omitempty"`
	// WorkflowStatus keeps findings whose workflow status is in this list
	// (NEW, NOTIFIED, RESOLVED, SUPPRESSED).
	WorkflowStatus []string `json:"workflow_status,omitempty"`
	// RecordState selects ACTIVE vs. ARCHIVED findings. Defaults to ACTIVE
	// when empty, matching the Security Hub console default.
	RecordState string `json:"record_state,omitempty"`
	// ResourceType keeps findings for this resource type (e.g. "AwsEc2Instance").
	ResourceType string `json:"resource_type,omitempty"`
	// AWSAccountID keeps findings for this account ID.
	AWSAccountID string `json:"aws_account_id,omitempty"`
	// UpdatedAfter / UpdatedBefore bound UpdatedAt as RFC3339 timestamps.
	UpdatedAfter  string `json:"updated_after,omitempty"`
	UpdatedBefore string `json:"updated_before,omitempty"`
}

// BuildFilters translates the Filter into Security Hub's AwsSecurityFindingFilters.
func (f Filter) BuildFilters() *types.AwsSecurityFindingFilters {
	out := &types.AwsSecurityFindingFilters{}

	recordState := f.RecordState
	if recordState == "" {
		recordState = "ACTIVE"
	}
	out.RecordState = []types.StringFilter{equalsFilter(recordState)}

	for _, s := range f.SeverityLabels {
		out.SeverityLabel = append(out.SeverityLabel, equalsFilter(s))
	}
	for _, t := range f.Types {
		out.Type = append(out.Type, equalsFilter(t))
	}
	if f.ProductName != "" {
		out.ProductName = []types.StringFilter{equalsFilter(f.ProductName)}
	}
	for _, w := range f.WorkflowStatus {
		out.WorkflowStatus = append(out.WorkflowStatus, equalsFilter(w))
	}
	if f.ResourceType != "" {
		out.ResourceType = []types.StringFilter{equalsFilter(f.ResourceType)}
	}
	if f.AWSAccountID != "" {
		out.AwsAccountId = []types.StringFilter{equalsFilter(f.AWSAccountID)}
	}
	if f.UpdatedAfter != "" || f.UpdatedBefore != "" {
		df := types.DateFilter{}
		if f.UpdatedAfter != "" {
			df.Start = aws.String(f.UpdatedAfter)
		}
		if f.UpdatedBefore != "" {
			df.End = aws.String(f.UpdatedBefore)
		}
		out.UpdatedAt = []types.DateFilter{df}
	}

	return out
}

func equalsFilter(value string) types.StringFilter {
	return types.StringFilter{
		Value:      aws.String(value),
		Comparison: types.StringFilterComparisonEquals,
	}
}

// SortCriteria builds Security Hub SortCriterion list from a field + order,
// defaulting to SeverityNormalized descending (the most-severe-first ordering
// a dashboard wants).
func SortCriteria(field string, desc bool) []types.SortCriterion {
	if field == "" {
		field = "SeverityNormalized"
	}
	order := types.SortOrderDescending
	if !desc {
		order = types.SortOrderAscending
	}
	return []types.SortCriterion{{Field: aws.String(field), SortOrder: order}}
}
```

- [ ] **Step 4: Run gofmt and the tests again**

Run:
```bash
gofmt -w internal/task/securityhub_common/filter.go
go test ./internal/task/securityhub_common/... -v
```
Expected: all tests in the package PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/task/securityhub_common/filter.go internal/task/securityhub_common/filter_test.go
git commit -m "feat(securityhub): add Filter/BuildFilters/SortCriteria helpers"
```

---

### Task 3: `securityhub_list_standards` task

**Files:**
- Create: `internal/task/securityhub_list_standards/task.go`
- Test: `internal/task/securityhub_list_standards/task_test.go`

**Interfaces:**
- Consumes: `securityhub_common.Standard`, `securityhub_common.HubStatus` (Task 1).
- Produces:
  - `const TaskName = "securityhub_list_standards"`
  - `type Payload struct { Region string }`
  - `type StandardsList struct { Hub securityhub_common.HubStatus; Total int; Standards []securityhub_common.Standard }`
  - `func New() *Task`
  - `func NewWithClientFactory(f func(ctx context.Context, region string) (api, error)) *Task`
  - `func (t *Task) Name() string`
  - `func (t *Task) Execute(ctx context.Context, rawPayload json.RawMessage) (*task.Result, error)`

**Behavior:** calls `DescribeHub`, then `DescribeStandards` (paginated) to get the catalog of available standards, then `GetEnabledStandards` (paginated) to get subscription status per standard. Joins on `StandardsArn`; standards with no matching subscription get `Status: ""` (not subscribed) rather than being dropped — the catalog is the definitive list, subscriptions overlay status onto it.

- [ ] **Step 1: Write the failing test**

Create `internal/task/securityhub_list_standards/task_test.go`:

```go
package securityhub_list_standards

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/securityhub"
	"github.com/aws/aws-sdk-go-v2/service/securityhub/types"
)

type fakeAPI struct {
	describeHubOut       *securityhub.DescribeHubOutput
	describeStandardsOut *securityhub.DescribeStandardsOutput
	enabledStandardsOut  *securityhub.GetEnabledStandardsOutput
}

func (f *fakeAPI) DescribeHub(_ context.Context, _ *securityhub.DescribeHubInput, _ ...func(*securityhub.Options)) (*securityhub.DescribeHubOutput, error) {
	return f.describeHubOut, nil
}

func (f *fakeAPI) DescribeStandards(_ context.Context, _ *securityhub.DescribeStandardsInput, _ ...func(*securityhub.Options)) (*securityhub.DescribeStandardsOutput, error) {
	return f.describeStandardsOut, nil
}

func (f *fakeAPI) GetEnabledStandards(_ context.Context, _ *securityhub.GetEnabledStandardsInput, _ ...func(*securityhub.Options)) (*securityhub.GetEnabledStandardsOutput, error) {
	return f.enabledStandardsOut, nil
}

func newTestTask(a api) *Task {
	return NewWithClientFactory(func(_ context.Context, _ string) (api, error) { return a, nil })
}

func TestExecute_JoinsCatalogWithSubscriptions(t *testing.T) {
	api := &fakeAPI{
		describeHubOut: &securityhub.DescribeHubOutput{
			HubArn:                   aws.String("arn:aws:securityhub:us-east-1:123456789012:hub/default"),
			SubscribedAt:             aws.String("2026-01-01T00:00:00Z"),
			AutoEnableControls:       aws.Bool(true),
			ControlFindingGenerator:  types.ControlFindingGeneratorSecurityControl,
		},
		describeStandardsOut: &securityhub.DescribeStandardsOutput{
			Standards: []types.Standard{
				{StandardsArn: aws.String("arn:std/cis"), Name: aws.String("CIS"), EnabledByDefault: aws.Bool(false)},
				{StandardsArn: aws.String("arn:std/fsbp"), Name: aws.String("FSBP"), EnabledByDefault: aws.Bool(true)},
			},
		},
		enabledStandardsOut: &securityhub.GetEnabledStandardsOutput{
			StandardsSubscriptions: []types.StandardsSubscription{
				{StandardsArn: aws.String("arn:std/fsbp"), StandardsStatus: types.StandardsStatusReady},
			},
		},
	}

	res, err := newTestTask(api).Execute(context.Background(), json.RawMessage(`{}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.Success {
		t.Fatalf("expected success, got error: %s", res.Error)
	}
	list := res.Details.(StandardsList)
	if list.Hub.HubArn != "arn:aws:securityhub:us-east-1:123456789012:hub/default" {
		t.Errorf("Hub.HubArn = %q", list.Hub.HubArn)
	}
	if list.Total != 2 {
		t.Fatalf("Total = %d, want 2", list.Total)
	}
	byArn := map[string]string{}
	for _, s := range list.Standards {
		byArn[s.StandardsArn] = s.Status
	}
	if byArn["arn:std/fsbp"] != "READY" {
		t.Errorf("fsbp status = %q, want READY", byArn["arn:std/fsbp"])
	}
	if byArn["arn:std/cis"] != "" {
		t.Errorf("cis status = %q, want empty (not subscribed)", byArn["arn:std/cis"])
	}
}

func TestExecute_InvalidPayload(t *testing.T) {
	res, err := newTestTask(&fakeAPI{}).Execute(context.Background(), json.RawMessage(`{`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Success {
		t.Fatal("expected success=false for invalid payload")
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./internal/task/securityhub_list_standards/... -v`
Expected: FAIL — package does not exist yet.

- [ ] **Step 3: Implement the task**

Create `internal/task/securityhub_list_standards/task.go`:

```go
// Package securityhub_list_standards lists the Security Hub subscription
// status plus the catalog of available compliance standards (CIS/PCI-DSS/FSBP)
// and each one's enablement status, powering the dashboard's hub header.
package securityhub_list_standards

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/securityhub"

	awshelper "github.com/loafoe/centcom-satellite/internal/aws"
	"github.com/loafoe/centcom-satellite/internal/task"
	shc "github.com/loafoe/centcom-satellite/internal/task/securityhub_common"
)

const TaskName = "securityhub_list_standards"

type api interface {
	DescribeHub(context.Context, *securityhub.DescribeHubInput, ...func(*securityhub.Options)) (*securityhub.DescribeHubOutput, error)
	DescribeStandards(context.Context, *securityhub.DescribeStandardsInput, ...func(*securityhub.Options)) (*securityhub.DescribeStandardsOutput, error)
	GetEnabledStandards(context.Context, *securityhub.GetEnabledStandardsInput, ...func(*securityhub.Options)) (*securityhub.GetEnabledStandardsOutput, error)
}

// Payload for securityhub_list_standards.
type Payload struct {
	Region string `json:"region,omitempty"`
}

// StandardsList is the task result payload.
type StandardsList struct {
	Hub       shc.HubStatus  `json:"hub"`
	Total     int            `json:"total"`
	Standards []shc.Standard `json:"standards"`
}

type Task struct {
	clientFactory func(ctx context.Context, region string) (api, error)
}

func New() *Task {
	return &Task{clientFactory: func(ctx context.Context, region string) (api, error) {
		cfg, err := awshelper.LoadConfig(ctx, awshelper.Options{Region: region})
		if err != nil {
			return nil, err
		}
		return securityhub.NewFromConfig(cfg), nil
	}}
}

func NewWithClientFactory(f func(ctx context.Context, region string) (api, error)) *Task {
	return &Task{clientFactory: f}
}

func (t *Task) Name() string { return TaskName }

func (t *Task) Execute(ctx context.Context, rawPayload json.RawMessage) (*task.Result, error) {
	var payload Payload
	if len(rawPayload) > 0 {
		if err := json.Unmarshal(rawPayload, &payload); err != nil {
			return task.NewErrorResult(fmt.Sprintf("invalid payload: %v", err)), nil
		}
	}

	client, err := t.clientFactory(ctx, payload.Region)
	if err != nil {
		return nil, fmt.Errorf("failed to build securityhub client: %w", err)
	}

	hubOut, err := client.DescribeHub(ctx, &securityhub.DescribeHubInput{})
	if err != nil {
		return nil, fmt.Errorf("describe hub: %w", err)
	}

	statusByArn := map[string]string{}
	subPaginator := securityhub.NewGetEnabledStandardsPaginator(client, &securityhub.GetEnabledStandardsInput{})
	for subPaginator.HasMorePages() {
		page, err := subPaginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("get enabled standards: %w", err)
		}
		for _, sub := range page.StandardsSubscriptions {
			statusByArn[aws.ToString(sub.StandardsArn)] = string(sub.StandardsStatus)
		}
	}

	result := StandardsList{
		Hub: shc.HubStatus{
			HubArn:                  aws.ToString(hubOut.HubArn),
			SubscribedAt:            aws.ToString(hubOut.SubscribedAt),
			AutoEnableControls:      aws.ToBool(hubOut.AutoEnableControls),
			ControlFindingGenerator: string(hubOut.ControlFindingGenerator),
		},
		Standards: []shc.Standard{},
	}

	stdPaginator := securityhub.NewDescribeStandardsPaginator(client, &securityhub.DescribeStandardsInput{})
	for stdPaginator.HasMorePages() {
		page, err := stdPaginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("describe standards: %w", err)
		}
		for _, s := range page.Standards {
			arn := aws.ToString(s.StandardsArn)
			result.Standards = append(result.Standards, shc.Standard{
				StandardsArn:     arn,
				Name:             aws.ToString(s.Name),
				Description:      aws.ToString(s.Description),
				EnabledByDefault: aws.ToBool(s.EnabledByDefault),
				Status:           statusByArn[arn],
			})
		}
	}
	result.Total = len(result.Standards)

	return task.NewSuccessResultWithDetails(fmt.Sprintf("found %d standards", result.Total), result), nil
}
```

- [ ] **Step 4: Run gofmt, build, and the tests**

Run:
```bash
gofmt -w internal/task/securityhub_list_standards/task.go
go build ./...
go test ./internal/task/securityhub_list_standards/... -v
```
Expected: build succeeds; both tests PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/task/securityhub_list_standards/
git commit -m "feat(securityhub): add securityhub_list_standards task"
```

---

### Task 4: `securityhub_get_findings` task

**Files:**
- Create: `internal/task/securityhub_get_findings/task.go`
- Test: `internal/task/securityhub_get_findings/task_test.go`

**Interfaces:**
- Consumes: `securityhub_common.Filter.BuildFilters()`, `securityhub_common.SortCriteria()`, `securityhub_common.Finding`, `securityhub_common.NormalizeFinding()` (Tasks 1–2).
- Produces:
  - `const TaskName = "securityhub_get_findings"`
  - `type Payload struct { Region string; Filter securityhub_common.Filter; SortField string; SortAsc bool; MaxResults int32; NextToken string }`
  - `type FindingList struct { Total int; Findings []securityhub_common.Finding; NextToken string }`
  - `func New() *Task`
  - `func NewWithClientFactory(f func(ctx context.Context, region string) (api, error)) *Task`
  - `func (t *Task) Name() string`
  - `func (t *Task) Execute(ctx context.Context, rawPayload json.RawMessage) (*task.Result, error)`

**Behavior:** single `GetFindings` call (no detector resolution needed — Security Hub has no detector concept). `MaxResults` clamps to [1,100], defaulting to 100 when unset/out of range. Filter and sort criteria are always applied (defaults come from `BuildFilters`/`SortCriteria` when the payload's `Filter`/`SortField` are zero-valued).

- [ ] **Step 1: Write the failing test**

Create `internal/task/securityhub_get_findings/task_test.go`:

```go
package securityhub_get_findings

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/securityhub"
	"github.com/aws/aws-sdk-go-v2/service/securityhub/types"
)

type fakeAPI struct {
	lastInput      *securityhub.GetFindingsInput
	getFindingsOut *securityhub.GetFindingsOutput
}

func (f *fakeAPI) GetFindings(_ context.Context, in *securityhub.GetFindingsInput, _ ...func(*securityhub.Options)) (*securityhub.GetFindingsOutput, error) {
	f.lastInput = in
	return f.getFindingsOut, nil
}

func newTestTask(a api) *Task {
	return NewWithClientFactory(func(_ context.Context, _ string) (api, error) { return a, nil })
}

func TestExecute_ReturnsNormalizedFindings(t *testing.T) {
	api := &fakeAPI{
		getFindingsOut: &securityhub.GetFindingsOutput{
			Findings: []types.AwsSecurityFinding{
				{Id: aws.String("f1"), ProductArn: aws.String("arn:p1"), Severity: &types.Severity{Label: types.SeverityLabelHigh}},
				{Id: aws.String("f2"), ProductArn: aws.String("arn:p1"), Severity: &types.Severity{Label: types.SeverityLabelLow}},
			},
			NextToken: aws.String("nt"),
		},
	}
	res, err := newTestTask(api).Execute(context.Background(), json.RawMessage(`{"filter":{"severity_labels":["HIGH"]}}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.Success {
		t.Fatalf("expected success, got error: %s", res.Error)
	}
	list := res.Details.(FindingList)
	if list.Total != 2 || list.NextToken != "nt" {
		t.Fatalf("unexpected result: %+v", list)
	}
	if len(api.lastInput.Filters.SeverityLabel) != 1 {
		t.Errorf("expected severity_labels to be translated into Filters, got %+v", api.lastInput.Filters)
	}
	if aws.ToInt32(api.lastInput.MaxResults) != 100 {
		t.Errorf("MaxResults = %d, want default 100", aws.ToInt32(api.lastInput.MaxResults))
	}
}

func TestExecute_MaxResultsClampedToUpperBound(t *testing.T) {
	api := &fakeAPI{getFindingsOut: &securityhub.GetFindingsOutput{}}
	_, _ = newTestTask(api).Execute(context.Background(), json.RawMessage(`{"max_results":500}`))
	if aws.ToInt32(api.lastInput.MaxResults) != 100 {
		t.Errorf("MaxResults = %d, want clamped to 100", aws.ToInt32(api.lastInput.MaxResults))
	}
}

func TestExecute_NextTokenPassedThrough(t *testing.T) {
	api := &fakeAPI{getFindingsOut: &securityhub.GetFindingsOutput{}}
	_, _ = newTestTask(api).Execute(context.Background(), json.RawMessage(`{"next_token":"page2"}`))
	if aws.ToString(api.lastInput.NextToken) != "page2" {
		t.Errorf("NextToken = %q, want page2", aws.ToString(api.lastInput.NextToken))
	}
}

func TestExecute_EmptyResultsAreNonNil(t *testing.T) {
	api := &fakeAPI{getFindingsOut: &securityhub.GetFindingsOutput{Findings: nil}}
	res, _ := newTestTask(api).Execute(context.Background(), json.RawMessage(`{}`))
	list := res.Details.(FindingList)
	if list.Findings == nil {
		t.Fatal("expected non-nil findings slice")
	}
}

func TestExecute_InvalidPayload(t *testing.T) {
	res, err := newTestTask(&fakeAPI{}).Execute(context.Background(), json.RawMessage(`{`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Success {
		t.Fatal("expected success=false for invalid payload")
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./internal/task/securityhub_get_findings/... -v`
Expected: FAIL — package does not exist yet.

- [ ] **Step 3: Implement the task**

Create `internal/task/securityhub_get_findings/task.go`:

```go
// Package securityhub_get_findings retrieves Security Hub findings matching a
// filter, fully hydrated and normalized in one call — unlike GuardDuty,
// Security Hub's GetFindings returns full records directly, no separate
// list-then-hydrate step is needed.
package securityhub_get_findings

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/securityhub"

	awshelper "github.com/loafoe/centcom-satellite/internal/aws"
	"github.com/loafoe/centcom-satellite/internal/task"
	shc "github.com/loafoe/centcom-satellite/internal/task/securityhub_common"
)

const TaskName = "securityhub_get_findings"

// defaultMaxResults / maxAllowedResults reflect Security Hub's GetFindings
// MaxResults valid range (1-100).
const (
	defaultMaxResults int32 = 100
	maxAllowedResults int32 = 100
)

type api interface {
	GetFindings(context.Context, *securityhub.GetFindingsInput, ...func(*securityhub.Options)) (*securityhub.GetFindingsOutput, error)
}

// Payload for securityhub_get_findings.
type Payload struct {
	Region     string      `json:"region,omitempty"`
	Filter     shc.Filter  `json:"filter,omitempty"`
	SortField  string      `json:"sort_field,omitempty"` // default "SeverityNormalized"
	SortAsc    bool        `json:"sort_asc,omitempty"`   // default false (descending)
	MaxResults int32       `json:"max_results,omitempty"`
	NextToken  string      `json:"next_token,omitempty"`
}

// FindingList is the task result payload.
type FindingList struct {
	Total     int          `json:"total"`
	Findings  []shc.Finding `json:"findings"`
	NextToken string       `json:"next_token,omitempty"`
}

type Task struct {
	clientFactory func(ctx context.Context, region string) (api, error)
}

func New() *Task {
	return &Task{clientFactory: func(ctx context.Context, region string) (api, error) {
		cfg, err := awshelper.LoadConfig(ctx, awshelper.Options{Region: region})
		if err != nil {
			return nil, err
		}
		return securityhub.NewFromConfig(cfg), nil
	}}
}

func NewWithClientFactory(f func(ctx context.Context, region string) (api, error)) *Task {
	return &Task{clientFactory: f}
}

func (t *Task) Name() string { return TaskName }

func (t *Task) Execute(ctx context.Context, rawPayload json.RawMessage) (*task.Result, error) {
	var payload Payload
	if len(rawPayload) > 0 {
		if err := json.Unmarshal(rawPayload, &payload); err != nil {
			return task.NewErrorResult(fmt.Sprintf("invalid payload: %v", err)), nil
		}
	}

	client, err := t.clientFactory(ctx, payload.Region)
	if err != nil {
		return nil, fmt.Errorf("failed to build securityhub client: %w", err)
	}

	maxResults := payload.MaxResults
	if maxResults <= 0 || maxResults > maxAllowedResults {
		maxResults = defaultMaxResults
	}

	input := &securityhub.GetFindingsInput{
		Filters:      payload.Filter.BuildFilters(),
		SortCriteria: shc.SortCriteria(payload.SortField, !payload.SortAsc),
		MaxResults:   aws.Int32(maxResults),
	}
	if payload.NextToken != "" {
		input.NextToken = aws.String(payload.NextToken)
	}

	out, err := client.GetFindings(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("get findings: %w", err)
	}

	result := FindingList{Findings: []shc.Finding{}, NextToken: aws.ToString(out.NextToken)}
	for _, f := range out.Findings {
		result.Findings = append(result.Findings, shc.NormalizeFinding(f))
	}
	result.Total = len(result.Findings)

	return task.NewSuccessResultWithDetails(fmt.Sprintf("retrieved %d findings", result.Total), result), nil
}
```

- [ ] **Step 4: Run gofmt, build, and the tests**

Run:
```bash
gofmt -w internal/task/securityhub_get_findings/task.go
go build ./...
go test ./internal/task/securityhub_get_findings/... -v
```
Expected: build succeeds; all five tests PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/task/securityhub_get_findings/
git commit -m "feat(securityhub): add securityhub_get_findings task"
```

---

### Task 5: `securityhub_get_findings_statistics` task

**Files:**
- Create: `internal/task/securityhub_get_findings_statistics/task.go`
- Test: `internal/task/securityhub_get_findings_statistics/task_test.go`

**Interfaces:**
- Consumes: `securityhub_common.Filter.BuildFilters()`, `securityhub_common.StatCount` (Tasks 1–2).
- Produces:
  - `const TaskName = "securityhub_get_findings_statistics"`
  - `type Payload struct { Region string; Filter securityhub_common.Filter; GroupBy string }`
  - `type Statistics struct { GroupBy string; Total int32; Counts []securityhub_common.StatCount; Truncated bool; NextToken string }`
  - `func New() *Task`
  - `func NewWithClientFactory(f func(ctx context.Context, region string) (api, error)) *Task`
  - `func (t *Task) Name() string`
  - `func (t *Task) Execute(ctx context.Context, rawPayload json.RawMessage) (*task.Result, error)`

**Behavior:** Security Hub has no server-side groupBy/statistics API (unlike GuardDuty), so this task pages through `GetFindings` (100 per page, capped at 10 pages / ~1000 findings total per the spec) and aggregates counts client-side by the requested `group_by` field (SEVERITY → `SeverityLabel`, TYPE → first entry of `Types`, WORKFLOW_STATUS → `Workflow.Status`, PRODUCT → `ProductName`; default SEVERITY). If the page cap is hit while more pages remain, the result sets `truncated: true` and `next_token` to the last page's token, making the lower-bound nature of the counts explicit rather than presenting them as complete.

- [ ] **Step 1: Write the failing test**

Create `internal/task/securityhub_get_findings_statistics/task_test.go`:

```go
package securityhub_get_findings_statistics

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/securityhub"
	"github.com/aws/aws-sdk-go-v2/service/securityhub/types"
)

type fakeAPI struct {
	pages    [][]types.AwsSecurityFinding
	tokens   []string // NextToken to return after each page; "" means no more pages
	callIdx  int
}

func (f *fakeAPI) GetFindings(_ context.Context, in *securityhub.GetFindingsInput, _ ...func(*securityhub.Options)) (*securityhub.GetFindingsOutput, error) {
	idx := f.callIdx
	f.callIdx++
	out := &securityhub.GetFindingsOutput{Findings: f.pages[idx]}
	if idx < len(f.tokens) && f.tokens[idx] != "" {
		out.NextToken = aws.String(f.tokens[idx])
	}
	return out, nil
}

func newTestTask(a api) *Task {
	return NewWithClientFactory(func(_ context.Context, _ string) (api, error) { return a, nil })
}

func sevFinding(label types.SeverityLabel) types.AwsSecurityFinding {
	return types.AwsSecurityFinding{Id: aws.String("f"), ProductArn: aws.String("arn"), Severity: &types.Severity{Label: label}}
}

func TestExecute_AggregatesBySeverityDefault(t *testing.T) {
	api := &fakeAPI{
		pages: [][]types.AwsSecurityFinding{
			{sevFinding(types.SeverityLabelHigh), sevFinding(types.SeverityLabelHigh), sevFinding(types.SeverityLabelLow)},
		},
	}
	res, err := newTestTask(api).Execute(context.Background(), json.RawMessage(`{}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.Success {
		t.Fatalf("expected success, got error: %s", res.Error)
	}
	stats := res.Details.(Statistics)
	if stats.GroupBy != "SEVERITY" {
		t.Errorf("GroupBy = %q, want SEVERITY", stats.GroupBy)
	}
	counts := map[string]int32{}
	for _, c := range stats.Counts {
		counts[c.Key] = c.Count
	}
	if counts["HIGH"] != 2 || counts["LOW"] != 1 {
		t.Errorf("counts = %+v, want HIGH:2 LOW:1", counts)
	}
	if stats.Total != 3 {
		t.Errorf("Total = %d, want 3", stats.Total)
	}
	if stats.Truncated {
		t.Error("expected Truncated=false when all pages consumed")
	}
}

func TestExecute_TruncatesAtPageCap(t *testing.T) {
	pages := make([][]types.AwsSecurityFinding, 11)
	tokens := make([]string, 11)
	for i := range pages {
		pages[i] = []types.AwsSecurityFinding{sevFinding(types.SeverityLabelMedium)}
		tokens[i] = "more" // every page claims there's more
	}
	api := &fakeAPI{pages: pages, tokens: tokens}
	res, _ := newTestTask(api).Execute(context.Background(), json.RawMessage(`{}`))
	stats := res.Details.(Statistics)
	if !stats.Truncated {
		t.Error("expected Truncated=true when page cap is hit with more pages remaining")
	}
	if stats.NextToken == "" {
		t.Error("expected NextToken to be set when truncated")
	}
	if stats.Total != 10 {
		t.Errorf("Total = %d, want 10 (10 pages x 1 finding, capped)", stats.Total)
	}
}

func TestExecute_UnsupportedGroupBy(t *testing.T) {
	res, err := newTestTask(&fakeAPI{}).Execute(context.Background(), json.RawMessage(`{"group_by":"BOGUS"}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Success {
		t.Fatal("expected failure for unsupported group_by")
	}
}

func TestExecute_InvalidPayload(t *testing.T) {
	res, err := newTestTask(&fakeAPI{}).Execute(context.Background(), json.RawMessage(`{`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Success {
		t.Fatal("expected success=false for invalid payload")
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./internal/task/securityhub_get_findings_statistics/... -v`
Expected: FAIL — package does not exist yet.

- [ ] **Step 3: Implement the task**

Create `internal/task/securityhub_get_findings_statistics/task.go`:

```go
// Package securityhub_get_findings_statistics aggregates Security Hub finding
// counts (by severity/type/workflow-status/product) for dashboard summary
// widgets. Security Hub has no server-side groupBy/statistics API (unlike
// GuardDuty's GetFindingsStatistics), so this task pages through GetFindings
// and aggregates client-side, capped to bound cost and latency.
package securityhub_get_findings_statistics

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/securityhub"
	"github.com/aws/aws-sdk-go-v2/service/securityhub/types"

	awshelper "github.com/loafoe/centcom-satellite/internal/aws"
	"github.com/loafoe/centcom-satellite/internal/task"
	shc "github.com/loafoe/centcom-satellite/internal/task/securityhub_common"
)

const TaskName = "securityhub_get_findings_statistics"

// maxPages caps how many GetFindings pages are aggregated per call (10 pages
// x 100 findings/page = up to 1,000 findings), bounding latency/cost. Hitting
// the cap sets Statistics.Truncated so callers know the counts are a lower
// bound, not silently partial data presented as complete.
const maxPages = 10

const pageSize int32 = 100

var groupByExtractors = map[string]func(types.AwsSecurityFinding) string{
	"SEVERITY": func(f types.AwsSecurityFinding) string {
		if f.Severity == nil {
			return ""
		}
		return string(f.Severity.Label)
	},
	"TYPE": func(f types.AwsSecurityFinding) string {
		if len(f.Types) == 0 {
			return ""
		}
		return f.Types[0]
	},
	"WORKFLOW_STATUS": func(f types.AwsSecurityFinding) string {
		if f.Workflow == nil {
			return ""
		}
		return string(f.Workflow.Status)
	},
	"PRODUCT": func(f types.AwsSecurityFinding) string {
		return aws.ToString(f.ProductName)
	},
}

type api interface {
	GetFindings(context.Context, *securityhub.GetFindingsInput, ...func(*securityhub.Options)) (*securityhub.GetFindingsOutput, error)
}

// Payload for securityhub_get_findings_statistics.
type Payload struct {
	Region  string     `json:"region,omitempty"`
	Filter  shc.Filter `json:"filter,omitempty"`
	GroupBy string     `json:"group_by,omitempty"` // default SEVERITY
}

// Statistics is the task result payload.
type Statistics struct {
	GroupBy   string          `json:"group_by"`
	Total     int32           `json:"total"`
	Counts    []shc.StatCount `json:"counts"`
	Truncated bool            `json:"truncated,omitempty"`
	NextToken string          `json:"next_token,omitempty"`
}

type Task struct {
	clientFactory func(ctx context.Context, region string) (api, error)
}

func New() *Task {
	return &Task{clientFactory: func(ctx context.Context, region string) (api, error) {
		cfg, err := awshelper.LoadConfig(ctx, awshelper.Options{Region: region})
		if err != nil {
			return nil, err
		}
		return securityhub.NewFromConfig(cfg), nil
	}}
}

func NewWithClientFactory(f func(ctx context.Context, region string) (api, error)) *Task {
	return &Task{clientFactory: f}
}

func (t *Task) Name() string { return TaskName }

func (t *Task) Execute(ctx context.Context, rawPayload json.RawMessage) (*task.Result, error) {
	var payload Payload
	if len(rawPayload) > 0 {
		if err := json.Unmarshal(rawPayload, &payload); err != nil {
			return task.NewErrorResult(fmt.Sprintf("invalid payload: %v", err)), nil
		}
	}

	groupByStr := payload.GroupBy
	if groupByStr == "" {
		groupByStr = "SEVERITY"
	}
	extract, ok := groupByExtractors[groupByStr]
	if !ok {
		return task.NewErrorResult(fmt.Sprintf("unsupported group_by %q (allowed: SEVERITY, TYPE, WORKFLOW_STATUS, PRODUCT)", groupByStr)), nil
	}

	client, err := t.clientFactory(ctx, payload.Region)
	if err != nil {
		return nil, fmt.Errorf("failed to build securityhub client: %w", err)
	}

	counts := map[string]int32{}
	result := Statistics{GroupBy: groupByStr, Counts: []shc.StatCount{}}

	var nextToken *string
	for page := 0; page < maxPages; page++ {
		input := &securityhub.GetFindingsInput{
			Filters:    payload.Filter.BuildFilters(),
			MaxResults: aws.Int32(pageSize),
		}
		if nextToken != nil {
			input.NextToken = nextToken
		}

		out, err := client.GetFindings(ctx, input)
		if err != nil {
			return nil, fmt.Errorf("get findings: %w", err)
		}
		for _, f := range out.Findings {
			key := extract(f)
			counts[key]++
			result.Total++
		}

		if out.NextToken == nil || aws.ToString(out.NextToken) == "" {
			nextToken = nil
			break
		}
		nextToken = out.NextToken

		if page == maxPages-1 {
			result.Truncated = true
			result.NextToken = aws.ToString(nextToken)
		}
	}

	for key, count := range counts {
		result.Counts = append(result.Counts, shc.StatCount{Key: key, Count: count})
	}

	return task.NewSuccessResultWithDetails(fmt.Sprintf("statistics grouped by %s: %d buckets", groupByStr, len(result.Counts)), result), nil
}
```

- [ ] **Step 4: Run gofmt, build, and the tests**

Run:
```bash
gofmt -w internal/task/securityhub_get_findings_statistics/task.go
go build ./...
go test ./internal/task/securityhub_get_findings_statistics/... -v
```
Expected: build succeeds; all four tests PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/task/securityhub_get_findings_statistics/
git commit -m "feat(securityhub): add securityhub_get_findings_statistics task"
```

---

### Task 6: `securityhub_update_findings` task (write)

**Files:**
- Create: `internal/task/securityhub_update_findings/task.go`
- Test: `internal/task/securityhub_update_findings/task_test.go`

**Interfaces:**
- Consumes: nothing from earlier tasks (independent of `securityhub_common`).
- Produces:
  - `const TaskName = "securityhub_update_findings"`
  - `type FindingRef struct { ID string; ProductArn string }`
  - `type Payload struct { Region string; Findings []FindingRef; WorkflowStatus string; Note string; NoteUpdatedBy string }`
  - `type UnprocessedFinding struct { ID, ProductArn, ErrorCode, ErrorMessage string }`
  - `type UpdateResult struct { Processed []FindingRef; Unprocessed []UnprocessedFinding }`
  - `func New() *Task`
  - `func NewWithClientFactory(f func(ctx context.Context, region string) (api, error)) *Task`
  - `func (t *Task) Name() string`
  - `func (t *Task) Execute(ctx context.Context, rawPayload json.RawMessage) (*task.Result, error)`

**Behavior:** validates `findings` is non-empty and ≤100 entries (AWS hard limit — rejected with a clear task error, not a raw AWS error), and that at least one of `workflow_status`/`note` is set. No same-`ProductArn` validation (AWS has no such constraint). Calls `BatchUpdateFindings` once and returns `ProcessedFindings`/`UnprocessedFindings` separately so partial failures are visible.

- [ ] **Step 1: Write the failing test**

Create `internal/task/securityhub_update_findings/task_test.go`:

```go
package securityhub_update_findings

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/securityhub"
	"github.com/aws/aws-sdk-go-v2/service/securityhub/types"
)

type fakeAPI struct {
	lastInput *securityhub.BatchUpdateFindingsInput
	out       *securityhub.BatchUpdateFindingsOutput
}

func (f *fakeAPI) BatchUpdateFindings(_ context.Context, in *securityhub.BatchUpdateFindingsInput, _ ...func(*securityhub.Options)) (*securityhub.BatchUpdateFindingsOutput, error) {
	f.lastInput = in
	return f.out, nil
}

func newTestTask(a api) *Task {
	return NewWithClientFactory(func(_ context.Context, _ string) (api, error) { return a, nil })
}

func TestExecute_SetsWorkflowStatusAndNote(t *testing.T) {
	api := &fakeAPI{
		out: &securityhub.BatchUpdateFindingsOutput{
			ProcessedFindings: []types.AwsSecurityFindingIdentifier{
				{Id: aws.String("f1"), ProductArn: aws.String("arn:p1")},
			},
		},
	}
	payload := `{
		"findings": [{"id":"f1","product_arn":"arn:p1"}],
		"workflow_status": "RESOLVED",
		"note": "fixed via automation",
		"note_updated_by": "centcom-satellite"
	}`
	res, err := newTestTask(api).Execute(context.Background(), json.RawMessage(payload))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.Success {
		t.Fatalf("expected success, got error: %s", res.Error)
	}
	if api.lastInput.Workflow == nil || api.lastInput.Workflow.Status != types.WorkflowStatusResolved {
		t.Errorf("Workflow = %+v, want status RESOLVED", api.lastInput.Workflow)
	}
	if api.lastInput.Note == nil || aws.ToString(api.lastInput.Note.Text) != "fixed via automation" {
		t.Errorf("Note = %+v", api.lastInput.Note)
	}
	if aws.ToString(api.lastInput.Note.UpdatedBy) != "centcom-satellite" {
		t.Errorf("Note.UpdatedBy = %q", aws.ToString(api.lastInput.Note.UpdatedBy))
	}
	if len(api.lastInput.FindingIdentifiers) != 1 || aws.ToString(api.lastInput.FindingIdentifiers[0].Id) != "f1" {
		t.Errorf("FindingIdentifiers = %+v", api.lastInput.FindingIdentifiers)
	}

	result := res.Details.(UpdateResult)
	if len(result.Processed) != 1 || result.Processed[0].ID != "f1" {
		t.Errorf("Processed = %+v", result.Processed)
	}
}

func TestExecute_SurfacesUnprocessedFindings(t *testing.T) {
	api := &fakeAPI{
		out: &securityhub.BatchUpdateFindingsOutput{
			UnprocessedFindings: []types.BatchUpdateFindingsUnprocessedFinding{
				{
					FindingIdentifier: &types.AwsSecurityFindingIdentifier{Id: aws.String("f2"), ProductArn: aws.String("arn:p2")},
					ErrorCode:         aws.String("INVALID_INPUT"),
					ErrorMessage:      aws.String("bad finding"),
				},
			},
		},
	}
	payload := `{"findings":[{"id":"f2","product_arn":"arn:p2"}],"workflow_status":"NOTIFIED"}`
	res, err := newTestTask(api).Execute(context.Background(), json.RawMessage(payload))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	result := res.Details.(UpdateResult)
	if len(result.Unprocessed) != 1 || result.Unprocessed[0].ErrorCode != "INVALID_INPUT" {
		t.Errorf("Unprocessed = %+v", result.Unprocessed)
	}
}

func TestExecute_RejectsMoreThan100Findings(t *testing.T) {
	refs := make([]map[string]string, 101)
	for i := range refs {
		refs[i] = map[string]string{"id": "f", "product_arn": "arn:p"}
	}
	body, _ := json.Marshal(map[string]any{"findings": refs, "workflow_status": "NEW"})
	res, err := newTestTask(&fakeAPI{}).Execute(context.Background(), body)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Success {
		t.Fatal("expected failure for >100 findings")
	}
	if !strings.Contains(res.Error, "100") {
		t.Errorf("error = %q, want it to mention the 100-item limit", res.Error)
	}
}

func TestExecute_RejectsEmptyFindings(t *testing.T) {
	res, err := newTestTask(&fakeAPI{}).Execute(context.Background(), json.RawMessage(`{"workflow_status":"NEW"}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Success {
		t.Fatal("expected failure for empty findings list")
	}
}

func TestExecute_RejectsNeitherWorkflowStatusNorNote(t *testing.T) {
	payload := `{"findings":[{"id":"f1","product_arn":"arn:p1"}]}`
	res, err := newTestTask(&fakeAPI{}).Execute(context.Background(), json.RawMessage(payload))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Success {
		t.Fatal("expected failure when neither workflow_status nor note is set")
	}
}

func TestExecute_InvalidPayload(t *testing.T) {
	res, err := newTestTask(&fakeAPI{}).Execute(context.Background(), json.RawMessage(`{`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Success {
		t.Fatal("expected success=false for invalid payload")
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./internal/task/securityhub_update_findings/... -v`
Expected: FAIL — package does not exist yet.

- [ ] **Step 3: Implement the task**

Create `internal/task/securityhub_update_findings/task.go`:

```go
// Package securityhub_update_findings sets a Security Hub finding's
// investigation Workflow.Status and/or attaches a Note via BatchUpdateFindings
// — the triage/remediation capability GuardDuty's API does not offer.
package securityhub_update_findings

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/securityhub"
	"github.com/aws/aws-sdk-go-v2/service/securityhub/types"

	awshelper "github.com/loafoe/centcom-satellite/internal/aws"
	"github.com/loafoe/centcom-satellite/internal/task"
)

const TaskName = "securityhub_update_findings"

// maxFindings is BatchUpdateFindings' per-call limit.
const maxFindings = 100

// defaultUpdatedBy is used when the caller omits note_updated_by.
const defaultUpdatedBy = "centcom-satellite"

type api interface {
	BatchUpdateFindings(context.Context, *securityhub.BatchUpdateFindingsInput, ...func(*securityhub.Options)) (*securityhub.BatchUpdateFindingsOutput, error)
}

// FindingRef identifies one finding to update.
type FindingRef struct {
	ID         string `json:"id"`
	ProductArn string `json:"product_arn"`
}

// Payload for securityhub_update_findings.
type Payload struct {
	Region         string       `json:"region,omitempty"`
	Findings       []FindingRef `json:"findings"`
	WorkflowStatus string       `json:"workflow_status,omitempty"`
	Note           string       `json:"note,omitempty"`
	NoteUpdatedBy  string       `json:"note_updated_by,omitempty"`
}

// UnprocessedFinding is one finding AWS could not update.
type UnprocessedFinding struct {
	ID           string `json:"id"`
	ProductArn   string `json:"product_arn"`
	ErrorCode    string `json:"error_code,omitempty"`
	ErrorMessage string `json:"error_message,omitempty"`
}

// UpdateResult is the task result payload.
type UpdateResult struct {
	Processed   []FindingRef         `json:"processed"`
	Unprocessed []UnprocessedFinding `json:"unprocessed"`
}

type Task struct {
	clientFactory func(ctx context.Context, region string) (api, error)
}

func New() *Task {
	return &Task{clientFactory: func(ctx context.Context, region string) (api, error) {
		cfg, err := awshelper.LoadConfig(ctx, awshelper.Options{Region: region})
		if err != nil {
			return nil, err
		}
		return securityhub.NewFromConfig(cfg), nil
	}}
}

func NewWithClientFactory(f func(ctx context.Context, region string) (api, error)) *Task {
	return &Task{clientFactory: f}
}

func (t *Task) Name() string { return TaskName }

func (t *Task) Execute(ctx context.Context, rawPayload json.RawMessage) (*task.Result, error) {
	var payload Payload
	if len(rawPayload) > 0 {
		if err := json.Unmarshal(rawPayload, &payload); err != nil {
			return task.NewErrorResult(fmt.Sprintf("invalid payload: %v", err)), nil
		}
	}

	if len(payload.Findings) == 0 {
		return task.NewErrorResult("findings is required and must be non-empty"), nil
	}
	if len(payload.Findings) > maxFindings {
		return task.NewErrorResult(fmt.Sprintf("findings supports at most %d entries per call, got %d", maxFindings, len(payload.Findings))), nil
	}
	if payload.WorkflowStatus == "" && payload.Note == "" {
		return task.NewErrorResult("at least one of workflow_status or note is required"), nil
	}

	client, err := t.clientFactory(ctx, payload.Region)
	if err != nil {
		return nil, fmt.Errorf("failed to build securityhub client: %w", err)
	}

	input := &securityhub.BatchUpdateFindingsInput{}
	for _, f := range payload.Findings {
		input.FindingIdentifiers = append(input.FindingIdentifiers, types.AwsSecurityFindingIdentifier{
			Id:         aws.String(f.ID),
			ProductArn: aws.String(f.ProductArn),
		})
	}
	if payload.WorkflowStatus != "" {
		input.Workflow = &types.WorkflowUpdate{Status: types.WorkflowStatus(payload.WorkflowStatus)}
	}
	if payload.Note != "" {
		updatedBy := payload.NoteUpdatedBy
		if updatedBy == "" {
			updatedBy = defaultUpdatedBy
		}
		input.Note = &types.NoteUpdate{Text: aws.String(payload.Note), UpdatedBy: aws.String(updatedBy)}
	}

	out, err := client.BatchUpdateFindings(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("batch update findings: %w", err)
	}

	result := UpdateResult{Processed: []FindingRef{}, Unprocessed: []UnprocessedFinding{}}
	for _, p := range out.ProcessedFindings {
		result.Processed = append(result.Processed, FindingRef{ID: aws.ToString(p.Id), ProductArn: aws.ToString(p.ProductArn)})
	}
	for _, u := range out.UnprocessedFindings {
		uf := UnprocessedFinding{ErrorCode: aws.ToString(u.ErrorCode), ErrorMessage: aws.ToString(u.ErrorMessage)}
		if u.FindingIdentifier != nil {
			uf.ID = aws.ToString(u.FindingIdentifier.Id)
			uf.ProductArn = aws.ToString(u.FindingIdentifier.ProductArn)
		}
		result.Unprocessed = append(result.Unprocessed, uf)
	}

	return task.NewSuccessResultWithDetails(
		fmt.Sprintf("updated %d findings (%d unprocessed)", len(result.Processed), len(result.Unprocessed)),
		result,
	), nil
}
```

- [ ] **Step 4: Run gofmt, build, and the tests**

Run:
```bash
gofmt -w internal/task/securityhub_update_findings/task.go
go build ./...
go test ./internal/task/securityhub_update_findings/... -v
```
Expected: build succeeds; all six tests PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/task/securityhub_update_findings/
git commit -m "feat(securityhub): add securityhub_update_findings write task"
```

---

### Task 7: Config flags `SecurityHubEnabled` / `SecurityHubWriteEnabled`

**Files:**
- Modify: `internal/config/config.go`
- Modify: `internal/config/config_test.go`

**Interfaces:**
- Produces: `FeaturesConfig.SecurityHubEnabled bool`, `FeaturesConfig.SecurityHubWriteEnabled bool`, both read from `SECURITYHUB_ENABLED` / `SECURITYHUB_WRITE_ENABLED` env vars, default `false`.

- [ ] **Step 1: Write the failing tests**

Add to `internal/config/config_test.go` (near `TestLoad_CloudWatchRCAFlag`):

```go
func TestLoad_SecurityHubFlags(t *testing.T) {
	t.Setenv("ALLOW_UNAUTHENTICATED", "true")
	t.Setenv("SECURITYHUB_ENABLED", "true")
	t.Setenv("SECURITYHUB_WRITE_ENABLED", "true")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !cfg.Features.SecurityHubEnabled {
		t.Fatal("SecurityHubEnabled = false, want true")
	}
	if !cfg.Features.SecurityHubWriteEnabled {
		t.Fatal("SecurityHubWriteEnabled = false, want true")
	}
}

func TestLoad_SecurityHubFlagsDefaultFalse(t *testing.T) {
	t.Setenv("ALLOW_UNAUTHENTICATED", "true")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Features.SecurityHubEnabled {
		t.Fatal("SecurityHubEnabled = true, want false by default")
	}
	if cfg.Features.SecurityHubWriteEnabled {
		t.Fatal("SecurityHubWriteEnabled = true, want false by default")
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/config/... -run TestLoad_SecurityHub -v`
Expected: FAIL — `SecurityHubEnabled`/`SecurityHubWriteEnabled` fields undefined.

- [ ] **Step 3: Add the fields and wiring**

In `internal/config/config.go`, add to `FeaturesConfig` right after the `GuardDutyEnabled` field (around line 107):

```go
	// SecurityHubEnabled enables the Security Hub data-retrieval tasks
	// (securityhub_list_standards, securityhub_get_findings,
	// securityhub_get_findings_statistics). Disabled by default as it requires
	// AWS credentials (IRSA) and read-only Security Hub IAM permissions (see
	// deploy/iam-policy-securityhub.json).
	SecurityHubEnabled bool

	// SecurityHubWriteEnabled enables the securityhub_update_findings task,
	// which calls BatchUpdateFindings to set a finding's Workflow.Status and/or
	// Note. Independently toggleable from SecurityHubEnabled. Disabled by
	// default; requires the write IAM policy in
	// deploy/iam-policy-securityhub-write.json.
	SecurityHubWriteEnabled bool
```

Then in `Load()`, add right after the `GuardDutyEnabled` line (around line 159):

```go
			SecurityHubEnabled:      getEnvBool("SECURITYHUB_ENABLED", false),
			SecurityHubWriteEnabled: getEnvBool("SECURITYHUB_WRITE_ENABLED", false),
```

- [ ] **Step 4: Run the tests**

Run: `go test ./internal/config/... -v`
Expected: all tests PASS, including the two new ones.

- [ ] **Step 5: Commit**

```bash
git add internal/config/config.go internal/config/config_test.go
git commit -m "feat(securityhub): add SECURITYHUB_ENABLED and SECURITYHUB_WRITE_ENABLED config flags"
```

---

### Task 8: Advertise `SecurityHub`/`SecurityHubWrite` capabilities in `cluster_info`

**Files:**
- Modify: `internal/task/cluster_info/task.go`

**Interfaces:**
- Consumes: nothing new.
- Produces: `Capabilities.SecurityHub bool` (`json:"securityhub"`), `Capabilities.SecurityHubWrite bool` (`json:"securityhub_write"`).

There is no existing `task_test.go` for `cluster_info` (confirmed absent during investigation), so this task has no test step of its own — it's a two-field struct addition consumed and exercised by Task 9's build/test pass.

- [ ] **Step 1: Add the fields**

In `internal/task/cluster_info/task.go`, add to the `Capabilities` struct right after `GuardDuty bool` (around line 45):

```go
	SecurityHub      bool `json:"securityhub"`
	SecurityHubWrite bool `json:"securityhub_write"`
```

- [ ] **Step 2: Build to confirm no breakage**

Run: `go build ./...`
Expected: succeeds (struct field addition is additive, nothing consumes `Capabilities` yet outside `main.go`, which Task 9 updates next).

- [ ] **Step 3: Commit**

```bash
git add internal/task/cluster_info/task.go
git commit -m "feat(securityhub): advertise securityhub/securityhub_write capabilities"
```

---

### Task 9: Register the four Security Hub tasks in `main.go`

**Files:**
- Modify: `cmd/centcom-satellite/main.go`

**Interfaces:**
- Consumes: `securityhub_list_standards.New()`, `securityhub_get_findings.New()`, `securityhub_get_findings_statistics.New()`, `securityhub_update_findings.New()` (Tasks 3–6); `cfg.Features.SecurityHubEnabled`, `cfg.Features.SecurityHubWriteEnabled` (Task 7); `cluster_info.Capabilities{SecurityHub, SecurityHubWrite}` (Task 8).

- [ ] **Step 1: Add the imports**

In `cmd/centcom-satellite/main.go`, add these import lines alphabetically among the existing `internal/task/...` imports (they sort right after `internal/task/resource_pressure` and before `internal/task/storage_status` — actually alphabetically `securityhub_*` sorts between `resource_pressure` and `storage_status`; place them there):

```go
	"github.com/loafoe/centcom-satellite/internal/task/securityhub_get_findings"
	"github.com/loafoe/centcom-satellite/internal/task/securityhub_get_findings_statistics"
	"github.com/loafoe/centcom-satellite/internal/task/securityhub_list_standards"
	"github.com/loafoe/centcom-satellite/internal/task/securityhub_update_findings"
```

- [ ] **Step 2: Wire capabilities into the `cluster_info.New(...).WithCapabilities(...)` call**

In the `cluster_info.Capabilities{...}` literal (around line 117-131), add right after `GuardDuty: cfg.Features.GuardDutyEnabled,`:

```go
		SecurityHub:      cfg.Features.SecurityHubEnabled,
		SecurityHubWrite: cfg.Features.SecurityHubWriteEnabled,
```

- [ ] **Step 3: Add the registration block**

Immediately after the existing GuardDuty registration block (the one ending `"tasks", "guardduty_list_detectors,...")` and its closing `}`, add:

```go
	// Optional: Security Hub data-retrieval tasks (require AWS credentials +
	// read-only Security Hub IAM; see deploy/iam-policy-securityhub.json).
	// Independently toggleable from GuardDuty/CloudWatch RCA — Security Hub
	// aggregates findings from more products and, unlike GuardDuty, supports
	// updating a finding's Workflow.Status via the separate write flag below.
	if cfg.Features.SecurityHubEnabled {
		registry.Register(securityhub_list_standards.New())
		registry.Register(securityhub_get_findings.New())
		registry.Register(securityhub_get_findings_statistics.New())
		slog.Info("securityhub tasks enabled",
			"tasks", "securityhub_list_standards,securityhub_get_findings,securityhub_get_findings_statistics")
	}

	// Optional: Security Hub write task (BatchUpdateFindings). Gated
	// separately from SecurityHubEnabled so a cluster can grant read-only
	// triage visibility without write access; see
	// deploy/iam-policy-securityhub-write.json.
	if cfg.Features.SecurityHubWriteEnabled {
		registry.Register(securityhub_update_findings.New())
		slog.Info("securityhub_update_findings task enabled")
	}
```

- [ ] **Step 4: Build and run the full test suite**

Run:
```bash
go build ./...
go test ./... 2>&1 | grep -v "no test files"
```
Expected: build succeeds; all packages report `ok` (no failures).

- [ ] **Step 5: Manual smoke test with `ALLOW_UNAUTHENTICATED`**

Run in one terminal:
```bash
ALLOW_UNAUTHENTICATED=true SECURITYHUB_ENABLED=true SECURITYHUB_WRITE_ENABLED=true go run ./cmd/centcom-satellite &
sleep 1
curl -s -X POST http://localhost:8080/task -H "Content-Type: application/json" \
  -d '{"type":"securityhub_get_findings","payload":{}}'
kill %1
```
Expected: a JSON response. If no AWS credentials/region are configured locally, expect a `success: false` result with an AWS credential/region error message (not a Go panic or HTTP 500) — that confirms the task is registered and dispatching correctly; it does not require live AWS access to prove wiring.

- [ ] **Step 6: Commit**

```bash
git add cmd/centcom-satellite/main.go
git commit -m "feat(securityhub): register securityhub tasks in main.go"
```

---

### Task 10: IAM policy files

**Files:**
- Create: `deploy/iam-policy-securityhub.json`
- Create: `deploy/iam-policy-securityhub-write.json`

No tests apply to static JSON policy files; validation is a JSON-parse check.

- [ ] **Step 1: Create the read policy**

Create `deploy/iam-policy-securityhub.json`:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "CentcomSecurityHubRead",
      "Effect": "Allow",
      "Action": [
        "securityhub:DescribeHub",
        "securityhub:GetEnabledStandards",
        "securityhub:DescribeStandards",
        "securityhub:GetFindings"
      ],
      "Resource": "*"
    }
  ]
}
```

- [ ] **Step 2: Create the write policy**

Create `deploy/iam-policy-securityhub-write.json`:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "CentcomSecurityHubWrite",
      "Effect": "Allow",
      "Action": [
        "securityhub:BatchUpdateFindings"
      ],
      "Resource": "*"
    }
  ]
}
```

- [ ] **Step 3: Validate both are well-formed JSON**

Run:
```bash
python3 -m json.tool deploy/iam-policy-securityhub.json > /dev/null && echo OK
python3 -m json.tool deploy/iam-policy-securityhub-write.json > /dev/null && echo OK
```
Expected: `OK` printed twice.

- [ ] **Step 4: Commit**

```bash
git add deploy/iam-policy-securityhub.json deploy/iam-policy-securityhub-write.json
git commit -m "feat(securityhub): add read and write IAM policy files"
```

---

### Task 11: Documentation — README, CLAUDE.md, deployment.yaml

**Files:**
- Modify: `README.md`
- Modify: `CLAUDE.md`
- Modify: `deploy/deployment.yaml`

No automated tests; this task is a documentation-accuracy review.

- [ ] **Step 1: Add task table rows to README.md**

In `README.md`, in the `## Available Tasks` table, add rows immediately after the existing `guardduty_list_findings` row (keep alphabetical grouping consistent with the existing GuardDuty block):

```markdown
| `securityhub_get_findings` | Retrieve Security Hub findings matching a filter (product-agnostic) |
| `securityhub_get_findings_statistics` | Aggregate Security Hub finding counts (by severity/type/workflow-status/product) |
| `securityhub_list_standards` | List Security Hub subscription status and enabled compliance standards |
| `securityhub_update_findings` | Update a finding's Workflow.Status and/or Note via BatchUpdateFindings |
```

- [ ] **Step 2: Add feature-flag rows to README.md**

In `README.md`, in the configuration/env-var table, add rows immediately after the existing `GUARDDUTY_ENABLED` row:

```markdown
| `SECURITYHUB_ENABLED` | false | Enable Security Hub data-retrieval tasks (needs AWS IRSA + read-only Security Hub IAM; see `deploy/iam-policy-securityhub.json`) |
| `SECURITYHUB_WRITE_ENABLED` | false | Enable `securityhub_update_findings` (needs AWS IRSA + write IAM; see `deploy/iam-policy-securityhub-write.json`) |
```

- [ ] **Step 3: Add a Security Hub subsection to CLAUDE.md**

In `CLAUDE.md`, in the `## Current Tasks` section, add a new subsection after `### Implemented: nodeclaim_delete` (following the same request/response example format used there):

```markdown
### Implemented: Security Hub tasks

Read tasks (`securityhub_list_standards`, `securityhub_get_findings`,
`securityhub_get_findings_statistics`) retrieve Security Hub findings and
compliance-standard status. Unlike GuardDuty, Security Hub aggregates findings
from many products (GuardDuty, Inspector, Macie, IAM Access Analyzer, Config
compliance checks, custom integrations) and supports a write task,
`securityhub_update_findings`, for setting a finding's triage state.

**Request** (`securityhub_update_findings`):
```json
{
  "type": "securityhub_update_findings",
  "payload": {
    "findings": [
      {"id": "finding-id-1", "product_arn": "arn:aws:securityhub:us-east-1:123456789012:product/aws/guardduty"}
    ],
    "workflow_status": "RESOLVED",
    "note": "Remediated via automation",
    "note_updated_by": "centcom-satellite"
  }
}
```

**Response**:
```json
{
  "success": true,
  "message": "updated 1 findings (0 unprocessed)",
  "details": {
    "processed": [
      {"id": "finding-id-1", "product_arn": "arn:aws:securityhub:us-east-1:123456789012:product/aws/guardduty"}
    ],
    "unprocessed": []
  }
}
```
```

- [ ] **Step 4: Add env var rows to CLAUDE.md**

In `CLAUDE.md`, in the `## Configuration` section, add right after the existing `GUARDDUTY_ENABLED` line:

```markdown
- `SECURITYHUB_ENABLED` (default: false) - Enable Security Hub data-retrieval tasks (securityhub_list_standards, securityhub_get_findings, securityhub_get_findings_statistics). Requires AWS credentials via IRSA and the read-only IAM policy in `deploy/iam-policy-securityhub.json`.
- `SECURITYHUB_WRITE_ENABLED` (default: false) - Enable securityhub_update_findings (BatchUpdateFindings — sets Workflow.Status/Note). Independently toggleable from SECURITYHUB_ENABLED. Requires the write IAM policy in `deploy/iam-policy-securityhub-write.json`.
```

- [ ] **Step 5: Add commented env var examples to deployment.yaml**

In `deploy/deployment.yaml`, add commented lines near the existing `# Optional: OTEL endpoint` comment block (in the `env:` list):

```yaml
            # Optional: Security Hub read tasks
            # - name: SECURITYHUB_ENABLED
            #   value: "true"
            # Optional: Security Hub write task (BatchUpdateFindings)
            # - name: SECURITYHUB_WRITE_ENABLED
            #   value: "true"
```

- [ ] **Step 6: Review for accuracy**

Read back the four edited sections and confirm: task names match exactly what Tasks 3–6 implemented (`securityhub_list_standards`, `securityhub_get_findings`, `securityhub_get_findings_statistics`, `securityhub_update_findings`); env var names match Task 7 (`SECURITYHUB_ENABLED`, `SECURITYHUB_WRITE_ENABLED`); the example request/response in CLAUDE.md matches the `Payload`/`UpdateResult` shapes from Task 6 exactly (field names `findings`, `id`, `product_arn`, `workflow_status`, `note`, `note_updated_by`, and response `processed`/`unprocessed`).

- [ ] **Step 7: Commit**

```bash
git add README.md CLAUDE.md deploy/deployment.yaml
git commit -m "docs(securityhub): document tasks, feature flags, and IAM policies"
```

---

### Task 12: Final verification pass

**Files:** none (verification only).

- [ ] **Step 1: Full build**

Run: `go build ./...`
Expected: no errors.

- [ ] **Step 2: Full test suite**

Run: `go test ./... 2>&1 | tee /tmp/securityhub-test-output.txt; grep -c FAIL /tmp/securityhub-test-output.txt`
Expected: the `grep -c FAIL` count is `0`.

- [ ] **Step 3: go vet**

Run: `go vet ./...`
Expected: no output (no issues).

- [ ] **Step 4: gofmt check across all new files**

Run: `gofmt -l internal/task/securityhub_common internal/task/securityhub_list_standards internal/task/securityhub_get_findings internal/task/securityhub_get_findings_statistics internal/task/securityhub_update_findings internal/config cmd/centcom-satellite`
Expected: no output (empty = all files already formatted).

- [ ] **Step 5: Confirm go.mod/go.sum are tidy**

Run: `go mod tidy && git diff --stat go.mod go.sum`
Expected: no diff (already tidy from Task 1's `go mod tidy` run) — if there is a diff, stage and commit it (`git add go.mod go.sum && git commit -m "chore: tidy go.mod/go.sum"`).

- [ ] **Step 6: Review the diff against the spec**

Run: `git log --oneline main..HEAD` (or the equivalent base-branch comparison) and skim each commit's diff against `docs/specs/2026-07-27-securityhub-support-design.md` section by section — confirm every task in the spec's "Task surface" table has a corresponding implementation, every non-goal was in fact skipped, and the IAM policies match the "RBAC / IAM" section verbatim.

- [ ] **Step 7: Push and open the pull request**

```bash
git push -u origin worktree-securityhub-support
gh pr create --title "feat: add AWS Security Hub support" --body "$(cat <<'EOF'
## Summary
- Adds opt-in AWS Security Hub support alongside the existing GuardDuty tasks: `securityhub_list_standards`, `securityhub_get_findings`, `securityhub_get_findings_statistics` (read, gated by `SECURITYHUB_ENABLED`) and `securityhub_update_findings` (write via BatchUpdateFindings, gated separately by `SECURITYHUB_WRITE_ENABLED`).
- Security Hub aggregates findings from more products than GuardDuty alone and supports updating a finding's Workflow.Status/Note — the write capability GuardDuty's API lacks.
- New IAM policies (`deploy/iam-policy-securityhub.json`, `deploy/iam-policy-securityhub-write.json`) split read/write least-privilege, matching the GuardDuty/CloudWatch RCA pattern.

## Test plan
- [x] `go build ./...` succeeds
- [x] `go test ./...` passes with no failures
- [x] `go vet ./...` clean
- [x] Manual smoke test: `ALLOW_UNAUTHENTICATED=true SECURITYHUB_ENABLED=true SECURITYHUB_WRITE_ENABLED=true go run ./cmd/centcom-satellite` + `curl /task` dispatches to the new tasks
- [ ] Reviewer: confirm IAM policy actions match your Security Hub deployment's needs before applying in a live account

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

Report the resulting PR URL to the user.

---

## Self-Review Notes

- **Spec coverage:** All four tasks from the spec's task table (§ Task surface) are implemented in Tasks 3–6. Config flags (Task 7), capability advertisement (Task 8), registration (Task 9), IAM policies (Task 10), and docs (Task 11) all trace directly to spec sections of the same name. Non-goals (multi-account, Insights API, extra `BatchUpdateFindings` fields, GuardDuty removal, Automation Rules/Connectors) are correctly absent from every task.
- **Type consistency:** `securityhub_common.Filter` (Task 2) is consumed identically by `securityhub_get_findings` (Task 4) and `securityhub_get_findings_statistics` (Task 5) via `.BuildFilters()`. `securityhub_common.Finding`/`NormalizeFinding` (Task 1) is consumed only by Task 4 (Task 5 aggregates raw SDK types directly for its own counting, not the normalized model — intentional, since statistics never surface individual findings). `FindingRef`/`UpdateResult` in Task 6 are self-contained and don't depend on `securityhub_common`, matching the "Consumes: nothing" note in that task.
- **No placeholders:** every step has literal code, not descriptions of code.
