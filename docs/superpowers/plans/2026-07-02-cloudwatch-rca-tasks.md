# CloudWatch RCA Data-Retrieval Tasks Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add seven read-only AWS CloudWatch/Cost-Explorer data-retrieval tasks to centcom-satellite, ported from the `ai-powered-cw-alarms-rca` prototype and reaching feature parity with the awslabs `cloudwatch-mcp-server` so the upstream MCP server (centcom) no longer needs it.

**Architecture:** Each capability is a standard task package under `internal/task/`, implementing the existing `task.Task` interface, registered in `main.go` behind one feature flag, using a shared `internal/aws/` helper that builds AWS SDK Go v2 clients from the default credential chain (IRSA). AWS APIs are injected via narrow interfaces for testability.

**Tech Stack:** Go 1.25, AWS SDK for Go v2 (`service/cloudwatch`, `service/cloudwatchlogs`, `service/costexplorer`, `config`), `testify`.

## Global Constraints

- Module: `github.com/loafoe/centcom-satellite`; Go `1.25.0`.
- Every task implements `task.Task`: `Name() string` and `Execute(ctx context.Context, payload json.RawMessage) (*task.Result, error)`.
- Validation / user errors → `task.NewErrorResult(msg)` with **nil** Go error (HTTP 200, `success:false`). Only infrastructure/AWS-call failures return a non-nil error (HTTP 500).
- Success → `task.NewSuccessResultWithDetails(message, details)`.
- One package per task: `internal/task/<name>/task.go` + `task_test.go`, with `const TaskName = "<name>"`, a `Payload` struct, and a `New(...)` constructor.
- AWS API access is injected via a narrow per-task interface (matching `http_request`'s injected `httpClient`/`resolver`); tests use fakes, never live AWS.
- All seven tasks gated behind `CLOUDWATCH_RCA_ENABLED` (default false).
- Tests must pass with `make test`; format with `gofmt`.

---

## File Structure

- Create `internal/aws/client.go` — shared AWS config loader (default chain + optional region/AssumeRole).
- Create `internal/aws/client_test.go` — helper tests.
- Create `internal/task/cw_list_alarms/{task.go,task_test.go}`.
- Create `internal/task/cw_alarm_history/{task.go,task_test.go}`.
- Create `internal/task/cw_get_metrics/{task.go,task_test.go}`.
- Create `internal/task/cw_list_metrics/{task.go,task_test.go}`.
- Create `internal/task/cw_describe_log_groups/{task.go,task_test.go}`.
- Create `internal/task/cw_logs_query/{task.go,task_test.go}`.
- Create `internal/task/cost_explorer/{task.go,task_test.go}`.
- Modify `internal/config/config.go` — add `CloudWatchRCAEnabled` flag.
- Modify `internal/task/cluster_info/task.go` — add `CloudWatchRCA` capability field.
- Modify `cmd/centcom-satellite/main.go` — flag-gated registration + capability wiring.
- Modify `README.md`, `CLAUDE.md` — docs + IAM policy.

Tasks are ordered so each ends with an independently testable, committable deliverable:
- **Task 1** — shared `internal/aws` helper.
- **Phase 1 (Tasks 2–4)** — `cw_list_alarms`, `cw_alarm_history`, `cost_explorer`.
- **Phase 2 (Tasks 5–8)** — `cw_get_metrics`, `cw_list_metrics`, `cw_describe_log_groups`, `cw_logs_query`.
- **Task 9** — config flag + capability + `main.go` registration wiring.
- **Task 10** — docs (README, CLAUDE.md, IAM policy).

---

### Task 1: Shared AWS client helper (`internal/aws`)

**Files:**
- Create: `internal/aws/client.go`
- Test: `internal/aws/client_test.go`

**Interfaces:**
- Consumes: nothing (leaf package).
- Produces:
  - `type Options struct { Region string; AssumeRoleARN string }`
  - `func LoadConfig(ctx context.Context, opts Options) (aws.Config, error)` — loads the SDK default chain; applies `Region` when non-empty; wraps with `stscreds.NewAssumeRoleProvider` when `AssumeRoleARN` non-empty.
  - `func HasCredentials() bool` — mirrors `cluster_info.hasAWSCredentials` (env indicators + EKS token file).

- [ ] **Step 1: Add SDK service dependencies**

Run:
```bash
cd /Users/andy/DEV/Go/centcom-satellite
go get github.com/aws/aws-sdk-go-v2/service/cloudwatch@latest \
       github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs@latest \
       github.com/aws/aws-sdk-go-v2/service/costexplorer@latest \
       github.com/aws/aws-sdk-go-v2/credentials@latest
```
Expected: `go.mod`/`go.sum` updated with the four modules; no errors.

- [ ] **Step 2: Write the failing test**

Create `internal/aws/client_test.go`:
```go
package aws

import (
	"context"
	"testing"
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
```

- [ ] **Step 3: Run test to verify it fails**

Run: `go test ./internal/aws/`
Expected: FAIL — `undefined: LoadConfig` / `undefined: Options` / `undefined: HasCredentials`.

- [ ] **Step 4: Write minimal implementation**

Create `internal/aws/client.go`:
```go
// Package aws provides shared AWS SDK v2 client configuration for tasks that
// retrieve data from AWS services (CloudWatch, CloudWatch Logs, Cost Explorer).
package aws

import (
	"context"
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
	// AssumeRoleARN, when non-empty, wraps the base credentials in an
	// STS AssumeRole provider for cross-account access.
	AssumeRoleARN string
}

// LoadConfig builds an aws.Config from the SDK default credential chain
// (IRSA / Pod Identity in EKS), applying the per-request Region and optional
// AssumeRole from opts.
func LoadConfig(ctx context.Context, opts Options) (aws.Config, error) {
	loadOpts := []func(*config.LoadOptions) error{}
	if opts.Region != "" {
		loadOpts = append(loadOpts, config.WithRegion(opts.Region))
	}

	cfg, err := config.LoadDefaultConfig(ctx, loadOpts...)
	if err != nil {
		return aws.Config{}, err
	}

	if opts.AssumeRoleARN != "" {
		stsClient := sts.NewFromConfig(cfg)
		provider := stscreds.NewAssumeRoleProvider(stsClient, opts.AssumeRoleARN)
		cfg.Credentials = aws.NewCredentialsCache(provider)
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

- [ ] **Step 5: Run test to verify it passes**

Run: `go test ./internal/aws/`
Expected: PASS (3 tests).

- [ ] **Step 6: Commit**

```bash
git add internal/aws/ go.mod go.sum
git commit -m "feat(aws): add shared AWS SDK v2 client helper for data-retrieval tasks"
```

---

### Task 2: `cw_list_alarms` task

**Files:**
- Create: `internal/task/cw_list_alarms/task.go`
- Test: `internal/task/cw_list_alarms/task_test.go`

**Interfaces:**
- Consumes: `awshelper.LoadConfig` / `awshelper.Options` (Task 1); `task.Task`, `task.NewErrorResult`, `task.NewSuccessResultWithDetails`.
- Produces:
  - `const TaskName = "cw_list_alarms"`
  - `type describeAlarmsAPI interface { DescribeAlarms(ctx, *cloudwatch.DescribeAlarmsInput, ...func(*cloudwatch.Options)) (*cloudwatch.DescribeAlarmsOutput, error) }`
  - `func New() *Task` (production; builds client per-request from region) and `func NewWithClientFactory(f func(ctx context.Context, region string) (describeAlarmsAPI, error)) *Task` (tests).
  - `type Alarm struct` with JSON fields `name,arn,metric,namespace,state,reason,dimensions,updated`.

- [ ] **Step 1: Write the failing test**

Create `internal/task/cw_list_alarms/task_test.go`:
```go
package cw_list_alarms

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cwtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
)

type fakeDescribeAlarms struct {
	out *cloudwatch.DescribeAlarmsOutput
	err error
}

func (f *fakeDescribeAlarms) DescribeAlarms(_ context.Context, _ *cloudwatch.DescribeAlarmsInput, _ ...func(*cloudwatch.Options)) (*cloudwatch.DescribeAlarmsOutput, error) {
	return f.out, f.err
}

func newTestTask(api describeAlarmsAPI) *Task {
	return NewWithClientFactory(func(_ context.Context, _ string) (describeAlarmsAPI, error) {
		return api, nil
	})
}

func TestExecute_NormalizesMetricAlarm(t *testing.T) {
	updated := time.Date(2026, 6, 30, 12, 0, 0, 0, time.UTC)
	api := &fakeDescribeAlarms{out: &cloudwatch.DescribeAlarmsOutput{
		MetricAlarms: []cwtypes.MetricAlarm{{
			AlarmName:               aws.String("cpu-high"),
			AlarmArn:                aws.String("arn:aws:cloudwatch:eu-west-1:1:alarm:cpu-high"),
			MetricName:              aws.String("CPUUtilization"),
			Namespace:               aws.String("AWS/EC2"),
			StateValue:              cwtypes.StateValueAlarm,
			StateReason:             aws.String("threshold breached"),
			StateUpdatedTimestamp:   &updated,
			Dimensions:              []cwtypes.Dimension{{Name: aws.String("InstanceId"), Value: aws.String("i-123")}},
		}},
	}}

	res, err := newTestTask(api).Execute(context.Background(), json.RawMessage(`{}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.Success {
		t.Fatalf("expected success, got error: %s", res.Error)
	}
	list, ok := res.Details.(AlarmList)
	if !ok {
		t.Fatalf("details type = %T, want AlarmList", res.Details)
	}
	if list.Total != 1 || list.Alarms[0].Name != "cpu-high" {
		t.Fatalf("unexpected alarm list: %+v", list)
	}
	if list.Alarms[0].Dimensions["InstanceId"] != "i-123" {
		t.Fatalf("dimension not mapped: %+v", list.Alarms[0].Dimensions)
	}
}

func TestExecute_InvalidPayload(t *testing.T) {
	res, err := newTestTask(&fakeDescribeAlarms{}).Execute(context.Background(), json.RawMessage(`{`))
	if err != nil {
		t.Fatalf("expected nil error for bad payload, got %v", err)
	}
	if res.Success {
		t.Fatal("expected success=false for invalid payload")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/task/cw_list_alarms/`
Expected: FAIL — undefined `Task`, `NewWithClientFactory`, `describeAlarmsAPI`, `AlarmList`.

- [ ] **Step 3: Write minimal implementation**

Create `internal/task/cw_list_alarms/task.go`:
```go
// Package cw_list_alarms lists CloudWatch alarms in the requested state(s).
package cw_list_alarms

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cwtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"

	awshelper "github.com/loafoe/centcom-satellite/internal/aws"
	"github.com/loafoe/centcom-satellite/internal/task"
)

const TaskName = "cw_list_alarms"

// describeAlarmsAPI is the narrow slice of the CloudWatch client used here.
type describeAlarmsAPI interface {
	DescribeAlarms(context.Context, *cloudwatch.DescribeAlarmsInput, ...func(*cloudwatch.Options)) (*cloudwatch.DescribeAlarmsOutput, error)
}

// Payload for cw_list_alarms.
type Payload struct {
	StateFilter     []string `json:"state_filter,omitempty"`
	AlarmNamePrefix string   `json:"alarm_name_prefix,omitempty"`
	Region          string   `json:"region,omitempty"`
}

// Alarm is the normalized alarm model (matches the RCA prototype).
type Alarm struct {
	Name       string            `json:"name"`
	ARN        string            `json:"arn"`
	Metric     string            `json:"metric"`
	Namespace  string            `json:"namespace"`
	State      string            `json:"state"`
	Reason     string            `json:"reason"`
	Dimensions map[string]string `json:"dimensions,omitempty"`
	Updated    string            `json:"updated,omitempty"`
}

// AlarmList is the task result payload.
type AlarmList struct {
	Total  int     `json:"total"`
	Alarms []Alarm `json:"alarms"`
}

// Task lists CloudWatch alarms.
type Task struct {
	clientFactory func(ctx context.Context, region string) (describeAlarmsAPI, error)
}

// New builds a production task using the shared AWS config helper.
func New() *Task {
	return &Task{clientFactory: func(ctx context.Context, region string) (describeAlarmsAPI, error) {
		cfg, err := awshelper.LoadConfig(ctx, awshelper.Options{Region: region})
		if err != nil {
			return nil, err
		}
		return cloudwatch.NewFromConfig(cfg), nil
	}}
}

// NewWithClientFactory builds a task with an injected client factory (tests).
func NewWithClientFactory(f func(ctx context.Context, region string) (describeAlarmsAPI, error)) *Task {
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

	states := payload.StateFilter
	if len(states) == 0 {
		states = []string{"ALARM", "INSUFFICIENT_DATA"}
	}

	client, err := t.clientFactory(ctx, payload.Region)
	if err != nil {
		return nil, fmt.Errorf("failed to build cloudwatch client: %w", err)
	}

	input := &cloudwatch.DescribeAlarmsInput{
		AlarmTypes: []cwtypes.AlarmType{cwtypes.AlarmTypeMetricAlarm, cwtypes.AlarmTypeCompositeAlarm},
	}
	if payload.AlarmNamePrefix != "" {
		input.AlarmNamePrefix = aws.String(payload.AlarmNamePrefix)
	}

	wanted := make(map[string]bool, len(states))
	for _, s := range states {
		wanted[s] = true
	}

	result := AlarmList{Alarms: []Alarm{}}
	paginator := cloudwatch.NewDescribeAlarmsPaginator(client, input)
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("describe alarms: %w", err)
		}
		for _, a := range page.MetricAlarms {
			if !wanted[string(a.StateValue)] {
				continue
			}
			result.Alarms = append(result.Alarms, normalizeMetricAlarm(a))
		}
		for _, a := range page.CompositeAlarms {
			if !wanted[string(a.StateValue)] {
				continue
			}
			result.Alarms = append(result.Alarms, normalizeCompositeAlarm(a))
		}
	}
	result.Total = len(result.Alarms)

	return task.NewSuccessResultWithDetails(fmt.Sprintf("found %d alarms", result.Total), result), nil
}

func normalizeMetricAlarm(a cwtypes.MetricAlarm) Alarm {
	dims := map[string]string{}
	for _, d := range a.Dimensions {
		dims[aws.ToString(d.Name)] = aws.ToString(d.Value)
	}
	updated := ""
	if a.StateUpdatedTimestamp != nil {
		updated = a.StateUpdatedTimestamp.UTC().Format("2006-01-02T15:04:05Z")
	}
	return Alarm{
		Name:       aws.ToString(a.AlarmName),
		ARN:        aws.ToString(a.AlarmArn),
		Metric:     aws.ToString(a.MetricName),
		Namespace:  aws.ToString(a.Namespace),
		State:      string(a.StateValue),
		Reason:     aws.ToString(a.StateReason),
		Dimensions: dims,
		Updated:    updated,
	}
}

func normalizeCompositeAlarm(a cwtypes.CompositeAlarm) Alarm {
	updated := ""
	if a.StateUpdatedTimestamp != nil {
		updated = a.StateUpdatedTimestamp.UTC().Format("2006-01-02T15:04:05Z")
	}
	return Alarm{
		Name:    aws.ToString(a.AlarmName),
		ARN:     aws.ToString(a.AlarmArn),
		State:   string(a.StateValue),
		Reason:  aws.ToString(a.StateReason),
		Updated: updated,
	}
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/task/cw_list_alarms/`
Expected: PASS (2 tests).

- [ ] **Step 5: Commit**

```bash
git add internal/task/cw_list_alarms/
git commit -m "feat(cw_list_alarms): add CloudWatch alarm listing task"
```

---

### Task 3: `cw_alarm_history` task

**Files:**
- Create: `internal/task/cw_alarm_history/task.go`
- Test: `internal/task/cw_alarm_history/task_test.go`

**Interfaces:**
- Consumes: `awshelper.LoadConfig`/`Options`; `task.*`.
- Produces:
  - `const TaskName = "cw_alarm_history"`
  - `type describeAlarmHistoryAPI interface { DescribeAlarmHistory(ctx, *cloudwatch.DescribeAlarmHistoryInput, ...func(*cloudwatch.Options)) (*cloudwatch.DescribeAlarmHistoryOutput, error) }`
  - `func New() *Task`, `func NewWithClientFactory(func(ctx, region string) (describeAlarmHistoryAPI, error)) *Task`
  - `type HistoryItem struct { Timestamp, OldState, NewState, Reason string }`

- [ ] **Step 1: Write the failing test**

Create `internal/task/cw_alarm_history/task_test.go`:
```go
package cw_alarm_history

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cwtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
)

type fakeAPI struct {
	out *cloudwatch.DescribeAlarmHistoryOutput
	err error
}

func (f *fakeAPI) DescribeAlarmHistory(_ context.Context, _ *cloudwatch.DescribeAlarmHistoryInput, _ ...func(*cloudwatch.Options)) (*cloudwatch.DescribeAlarmHistoryOutput, error) {
	return f.out, f.err
}

func newTestTask(api describeAlarmHistoryAPI) *Task {
	return NewWithClientFactory(func(_ context.Context, _ string) (describeAlarmHistoryAPI, error) { return api, nil })
}

func TestExecute_ParsesHistoryData(t *testing.T) {
	ts := time.Date(2026, 6, 30, 10, 0, 0, 0, time.UTC)
	hist := `{"oldState":{"stateValue":"OK"},"newState":{"stateValue":"ALARM","stateReason":"breached"}}`
	api := &fakeAPI{out: &cloudwatch.DescribeAlarmHistoryOutput{
		AlarmHistoryItems: []cwtypes.AlarmHistoryItem{{
			Timestamp:   &ts,
			HistoryData: aws.String(hist),
		}},
	}}
	res, err := newTestTask(api).Execute(context.Background(), json.RawMessage(`{"alarm_name":"a"}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	items := res.Details.(HistoryList).Items
	if len(items) != 1 || items[0].NewState != "ALARM" || items[0].Reason != "breached" {
		t.Fatalf("unexpected parse: %+v", items)
	}
}

func TestExecute_MissingAlarmName(t *testing.T) {
	res, err := newTestTask(&fakeAPI{}).Execute(context.Background(), json.RawMessage(`{}`))
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if res.Success {
		t.Fatal("expected success=false when alarm_name missing")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/task/cw_alarm_history/`
Expected: FAIL — undefined symbols.

- [ ] **Step 3: Write minimal implementation**

Create `internal/task/cw_alarm_history/task.go`:
```go
// Package cw_alarm_history retrieves CloudWatch alarm state-change history.
package cw_alarm_history

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cwtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"

	awshelper "github.com/loafoe/centcom-satellite/internal/aws"
	"github.com/loafoe/centcom-satellite/internal/task"
)

const TaskName = "cw_alarm_history"

const defaultLookbackDays = 14
const defaultMaxRecords = 50

type describeAlarmHistoryAPI interface {
	DescribeAlarmHistory(context.Context, *cloudwatch.DescribeAlarmHistoryInput, ...func(*cloudwatch.Options)) (*cloudwatch.DescribeAlarmHistoryOutput, error)
}

// Payload for cw_alarm_history.
type Payload struct {
	AlarmName  string `json:"alarm_name"`
	Start      string `json:"start,omitempty"` // RFC3339; default now-14d
	MaxRecords int32  `json:"max_records,omitempty"`
	Region     string `json:"region,omitempty"`
}

// HistoryItem is one parsed state transition.
type HistoryItem struct {
	Timestamp string `json:"timestamp"`
	OldState  string `json:"old_state,omitempty"`
	NewState  string `json:"new_state,omitempty"`
	Reason    string `json:"reason,omitempty"`
}

// HistoryList is the result payload.
type HistoryList struct {
	AlarmName string        `json:"alarm_name"`
	Total     int           `json:"total"`
	Items     []HistoryItem `json:"items"`
}

type Task struct {
	clientFactory func(ctx context.Context, region string) (describeAlarmHistoryAPI, error)
	now           func() time.Time
}

func New() *Task {
	return &Task{
		clientFactory: func(ctx context.Context, region string) (describeAlarmHistoryAPI, error) {
			cfg, err := awshelper.LoadConfig(ctx, awshelper.Options{Region: region})
			if err != nil {
				return nil, err
			}
			return cloudwatch.NewFromConfig(cfg), nil
		},
		now: time.Now,
	}
}

func NewWithClientFactory(f func(ctx context.Context, region string) (describeAlarmHistoryAPI, error)) *Task {
	return &Task{clientFactory: f, now: time.Now}
}

func (t *Task) Name() string { return TaskName }

func (t *Task) Execute(ctx context.Context, rawPayload json.RawMessage) (*task.Result, error) {
	var payload Payload
	if err := json.Unmarshal(rawPayload, &payload); err != nil {
		return task.NewErrorResult(fmt.Sprintf("invalid payload: %v", err)), nil
	}
	if payload.AlarmName == "" {
		return task.NewErrorResult("alarm_name is required"), nil
	}

	start := t.now().UTC().AddDate(0, 0, -defaultLookbackDays)
	if payload.Start != "" {
		parsed, err := time.Parse(time.RFC3339, payload.Start)
		if err != nil {
			return task.NewErrorResult(fmt.Sprintf("invalid start (want RFC3339): %v", err)), nil
		}
		start = parsed
	}
	maxRecords := payload.MaxRecords
	if maxRecords <= 0 {
		maxRecords = defaultMaxRecords
	}

	client, err := t.clientFactory(ctx, payload.Region)
	if err != nil {
		return nil, fmt.Errorf("failed to build cloudwatch client: %w", err)
	}

	out, err := client.DescribeAlarmHistory(ctx, &cloudwatch.DescribeAlarmHistoryInput{
		AlarmName:       aws.String(payload.AlarmName),
		HistoryItemType: cwtypes.HistoryItemTypeStateUpdate,
		StartDate:       aws.Time(start),
		EndDate:         aws.Time(t.now().UTC()),
		MaxRecords:      aws.Int32(maxRecords),
	})
	if err != nil {
		return nil, fmt.Errorf("describe alarm history: %w", err)
	}

	result := HistoryList{AlarmName: payload.AlarmName, Items: []HistoryItem{}}
	for _, h := range out.AlarmHistoryItems {
		item := HistoryItem{}
		if h.Timestamp != nil {
			item.Timestamp = h.Timestamp.UTC().Format(time.RFC3339)
		}
		var hd struct {
			OldState struct {
				StateValue string `json:"stateValue"`
			} `json:"oldState"`
			NewState struct {
				StateValue  string `json:"stateValue"`
				StateReason string `json:"stateReason"`
			} `json:"newState"`
		}
		if h.HistoryData != nil {
			_ = json.Unmarshal([]byte(*h.HistoryData), &hd)
		}
		item.OldState = hd.OldState.StateValue
		item.NewState = hd.NewState.StateValue
		item.Reason = hd.NewState.StateReason
		result.Items = append(result.Items, item)
	}
	sort.Slice(result.Items, func(i, j int) bool {
		return result.Items[i].Timestamp < result.Items[j].Timestamp
	})
	result.Total = len(result.Items)

	return task.NewSuccessResultWithDetails(fmt.Sprintf("%d history items for %s", result.Total, payload.AlarmName), result), nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/task/cw_alarm_history/`
Expected: PASS (2 tests).

- [ ] **Step 5: Commit**

```bash
git add internal/task/cw_alarm_history/
git commit -m "feat(cw_alarm_history): add CloudWatch alarm history task"
```

---

### Task 4: `cost_explorer` task

**Files:**
- Create: `internal/task/cost_explorer/task.go`
- Test: `internal/task/cost_explorer/task_test.go`

**Interfaces:**
- Consumes: `awshelper.LoadConfig`/`Options`; `task.*`.
- Produces:
  - `const TaskName = "cost_explorer"`
  - `type getCostAndUsageAPI interface { GetCostAndUsage(ctx, *costexplorer.GetCostAndUsageInput, ...func(*costexplorer.Options)) (*costexplorer.GetCostAndUsageOutput, error) }`
  - `func New() *Task`, `func NewWithClientFactory(func(ctx) (getCostAndUsageAPI, error)) *Task`
  - `namespace→service` map matching the prototype (AWS/EC2→Amazon Elastic Compute Cloud - Compute, AWS/RDS→Amazon Relational Database Service, AWS/Lambda→AWS Lambda, AWS/StorageGateway→AWS Storage Gateway, AWS/ECS→Amazon Elastic Container Service).

- [ ] **Step 1: Write the failing test**

Create `internal/task/cost_explorer/task_test.go`:
```go
package cost_explorer

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/costexplorer"
	cetypes "github.com/aws/aws-sdk-go-v2/service/costexplorer/types"
)

type fakeCE struct {
	in  *costexplorer.GetCostAndUsageInput
	out *costexplorer.GetCostAndUsageOutput
	err error
}

func (f *fakeCE) GetCostAndUsage(_ context.Context, in *costexplorer.GetCostAndUsageInput, _ ...func(*costexplorer.Options)) (*costexplorer.GetCostAndUsageOutput, error) {
	f.in = in
	return f.out, f.err
}

func newTestTask(api *fakeCE) *Task {
	return NewWithClientFactory(func(_ context.Context) (getCostAndUsageAPI, error) { return api, nil })
}

func TestExecute_MapsNamespaceToServiceFilter(t *testing.T) {
	api := &fakeCE{out: &costexplorer.GetCostAndUsageOutput{
		ResultsByTime: []cetypes.ResultByTime{{
			TimePeriod: &cetypes.DateInterval{Start: aws.String("2026-06-01"), End: aws.String("2026-07-01")},
			Total: map[string]cetypes.MetricValue{
				"UnblendedCost": {Amount: aws.String("12.34"), Unit: aws.String("USD")},
			},
		}},
	}}
	res, err := newTestTask(api).Execute(context.Background(), json.RawMessage(`{"namespace":"AWS/EC2"}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.Success {
		t.Fatalf("expected success, got %s", res.Error)
	}
	if api.in.Filter == nil {
		t.Fatal("expected a SERVICE filter to be set for AWS/EC2 namespace")
	}
	report := res.Details.(CostReport)
	if len(report.Periods) != 1 || report.Periods[0].Amount != "12.34" {
		t.Fatalf("unexpected report: %+v", report)
	}
}

func TestExecute_NoNamespaceNoFilter(t *testing.T) {
	api := &fakeCE{out: &costexplorer.GetCostAndUsageOutput{}}
	if _, err := newTestTask(api).Execute(context.Background(), json.RawMessage(`{}`)); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if api.in.Filter != nil {
		t.Fatal("expected no filter when namespace omitted")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/task/cost_explorer/`
Expected: FAIL — undefined symbols.

- [ ] **Step 3: Write minimal implementation**

Create `internal/task/cost_explorer/task.go`:
```go
// Package cost_explorer retrieves AWS cost and usage data, optionally filtered
// to the service backing a CloudWatch namespace.
package cost_explorer

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/costexplorer"
	cetypes "github.com/aws/aws-sdk-go-v2/service/costexplorer/types"

	awshelper "github.com/loafoe/centcom-satellite/internal/aws"
	"github.com/loafoe/centcom-satellite/internal/task"
)

const TaskName = "cost_explorer"

// ceRegion is fixed: Cost Explorer is a global service reachable via us-east-1.
const ceRegion = "us-east-1"

// namespaceToService maps CloudWatch namespaces to Cost Explorer SERVICE values.
var namespaceToService = map[string]string{
	"AWS/EC2":            "Amazon Elastic Compute Cloud - Compute",
	"AWS/RDS":            "Amazon Relational Database Service",
	"AWS/Lambda":         "AWS Lambda",
	"AWS/StorageGateway": "AWS Storage Gateway",
	"AWS/ECS":            "Amazon Elastic Container Service",
}

type getCostAndUsageAPI interface {
	GetCostAndUsage(context.Context, *costexplorer.GetCostAndUsageInput, ...func(*costexplorer.Options)) (*costexplorer.GetCostAndUsageOutput, error)
}

// Payload for cost_explorer.
type Payload struct {
	Namespace   string `json:"namespace,omitempty"`
	Start       string `json:"start,omitempty"`       // YYYY-MM-DD; default now-30d
	End         string `json:"end,omitempty"`         // YYYY-MM-DD; default today
	Granularity string `json:"granularity,omitempty"` // default MONTHLY
}

// PeriodCost is cost for one time period.
type PeriodCost struct {
	Start  string `json:"start"`
	End    string `json:"end"`
	Amount string `json:"amount"`
	Unit   string `json:"unit"`
}

// CostReport is the result payload.
type CostReport struct {
	Service string       `json:"service,omitempty"`
	Periods []PeriodCost `json:"periods"`
}

type Task struct {
	clientFactory func(ctx context.Context) (getCostAndUsageAPI, error)
	now           func() time.Time
}

func New() *Task {
	return &Task{
		clientFactory: func(ctx context.Context) (getCostAndUsageAPI, error) {
			cfg, err := awshelper.LoadConfig(ctx, awshelper.Options{Region: ceRegion})
			if err != nil {
				return nil, err
			}
			return costexplorer.NewFromConfig(cfg), nil
		},
		now: time.Now,
	}
}

func NewWithClientFactory(f func(ctx context.Context) (getCostAndUsageAPI, error)) *Task {
	return &Task{clientFactory: f, now: time.Now}
}

func (t *Task) Name() string { return TaskName }

func (t *Task) Execute(ctx context.Context, rawPayload json.RawMessage) (*task.Result, error) {
	var payload Payload
	if len(rawPayload) > 0 {
		if err := json.Unmarshal(rawPayload, &payload); err != nil {
			return task.NewErrorResult(fmt.Sprintf("invalid payload: %v", err)), nil
		}
	}

	end := t.now().UTC().Format("2006-01-02")
	if payload.End != "" {
		end = payload.End
	}
	start := t.now().UTC().AddDate(0, 0, -30).Format("2006-01-02")
	if payload.Start != "" {
		start = payload.Start
	}
	granularity := cetypes.GranularityMonthly
	if payload.Granularity != "" {
		granularity = cetypes.Granularity(payload.Granularity)
	}

	input := &costexplorer.GetCostAndUsageInput{
		TimePeriod:  &cetypes.DateInterval{Start: aws.String(start), End: aws.String(end)},
		Granularity: granularity,
		Metrics:     []string{"UnblendedCost", "UsageQuantity"},
	}

	report := CostReport{Periods: []PeriodCost{}}
	if payload.Namespace != "" {
		service, ok := namespaceToService[payload.Namespace]
		if !ok {
			return task.NewErrorResult(fmt.Sprintf("unknown namespace %q (no service mapping)", payload.Namespace)), nil
		}
		report.Service = service
		input.Filter = &cetypes.Expression{
			Dimensions: &cetypes.DimensionValues{
				Key:    cetypes.DimensionService,
				Values: []string{service},
			},
		}
	}

	client, err := t.clientFactory(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to build cost explorer client: %w", err)
	}

	out, err := client.GetCostAndUsage(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("get cost and usage: %w", err)
	}

	for _, r := range out.ResultsByTime {
		p := PeriodCost{}
		if r.TimePeriod != nil {
			p.Start = aws.ToString(r.TimePeriod.Start)
			p.End = aws.ToString(r.TimePeriod.End)
		}
		if mv, ok := r.Total["UnblendedCost"]; ok {
			p.Amount = aws.ToString(mv.Amount)
			p.Unit = aws.ToString(mv.Unit)
		}
		report.Periods = append(report.Periods, p)
	}

	return task.NewSuccessResultWithDetails(fmt.Sprintf("cost report: %d periods", len(report.Periods)), report), nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/task/cost_explorer/`
Expected: PASS (2 tests).

- [ ] **Step 5: Commit**

```bash
git add internal/task/cost_explorer/
git commit -m "feat(cost_explorer): add AWS Cost Explorer cost/usage task"
```

---

## Phase 2 — metrics & logs (cloudwatch-mcp-server parity)

### Task 5: `cw_get_metrics` task

**Files:**
- Create: `internal/task/cw_get_metrics/task.go`
- Test: `internal/task/cw_get_metrics/task_test.go`

**Interfaces:**
- Consumes: `awshelper.LoadConfig`/`Options`; `task.*`.
- Produces:
  - `const TaskName = "cw_get_metrics"`
  - `type getMetricDataAPI interface { GetMetricData(ctx, *cloudwatch.GetMetricDataInput, ...func(*cloudwatch.Options)) (*cloudwatch.GetMetricDataOutput, error) }`
  - `func New() *Task`, `func NewWithClientFactory(func(ctx, region string) (getMetricDataAPI, error)) *Task`
  - Payload supports EITHER a metric query (`namespace`+`metric_name`+`dimensions`+`stat`+`period`) OR a Metrics Insights `expression`.

- [ ] **Step 1: Write the failing test**

Create `internal/task/cw_get_metrics/task_test.go`:
```go
package cw_get_metrics

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cwtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
)

type fakeGMD struct {
	in  *cloudwatch.GetMetricDataInput
	out *cloudwatch.GetMetricDataOutput
	err error
}

func (f *fakeGMD) GetMetricData(_ context.Context, in *cloudwatch.GetMetricDataInput, _ ...func(*cloudwatch.Options)) (*cloudwatch.GetMetricDataOutput, error) {
	f.in = in
	return f.out, f.err
}

func newTestTask(api *fakeGMD) *Task {
	return NewWithClientFactory(func(_ context.Context, _ string) (getMetricDataAPI, error) { return api, nil })
}

func TestExecute_MetricQuery(t *testing.T) {
	ts := time.Date(2026, 6, 30, 10, 0, 0, 0, time.UTC)
	api := &fakeGMD{out: &cloudwatch.GetMetricDataOutput{
		MetricDataResults: []cwtypes.MetricDataResult{{
			Id:         aws.String("m0"),
			Label:      aws.String("CPUUtilization"),
			Timestamps: []time.Time{ts},
			Values:     []float64{42.5},
		}},
	}}
	payload := `{"namespace":"AWS/EC2","metric_name":"CPUUtilization","dimensions":{"InstanceId":"i-1"},"period":300,"stat":"Average","start":"2026-06-30T09:00:00Z","end":"2026-06-30T11:00:00Z"}`
	res, err := newTestTask(api).Execute(context.Background(), json.RawMessage(payload))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	series := res.Details.(MetricResult).Series
	if len(series) != 1 || series[0].Values[0] != 42.5 {
		t.Fatalf("unexpected series: %+v", series)
	}
	q := api.in.MetricDataQueries[0]
	if q.MetricStat == nil || aws.ToString(q.MetricStat.Metric.MetricName) != "CPUUtilization" {
		t.Fatalf("expected MetricStat query, got %+v", q)
	}
}

func TestExecute_MetricsInsightsExpression(t *testing.T) {
	api := &fakeGMD{out: &cloudwatch.GetMetricDataOutput{}}
	payload := `{"expression":"SELECT AVG(CPUUtilization) FROM \"AWS/EC2\"","start":"2026-06-30T09:00:00Z","end":"2026-06-30T11:00:00Z"}`
	if _, err := newTestTask(api).Execute(context.Background(), json.RawMessage(payload)); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	q := api.in.MetricDataQueries[0]
	if q.Expression == nil {
		t.Fatal("expected Expression query for Metrics Insights")
	}
}

func TestExecute_MissingBoth(t *testing.T) {
	res, err := newTestTask(&fakeGMD{}).Execute(context.Background(), json.RawMessage(`{"start":"2026-06-30T09:00:00Z","end":"2026-06-30T11:00:00Z"}`))
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if res.Success {
		t.Fatal("expected success=false when neither metric_name nor expression provided")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/task/cw_get_metrics/`
Expected: FAIL — undefined symbols.

- [ ] **Step 3: Write minimal implementation**

Create `internal/task/cw_get_metrics/task.go`:
```go
// Package cw_get_metrics retrieves CloudWatch metric data via a metric query or
// a Metrics Insights SQL expression.
package cw_get_metrics

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cwtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"

	awshelper "github.com/loafoe/centcom-satellite/internal/aws"
	"github.com/loafoe/centcom-satellite/internal/task"
)

const TaskName = "cw_get_metrics"

const defaultPeriod = 300

type getMetricDataAPI interface {
	GetMetricData(context.Context, *cloudwatch.GetMetricDataInput, ...func(*cloudwatch.Options)) (*cloudwatch.GetMetricDataOutput, error)
}

// Payload for cw_get_metrics. Provide either a metric query (namespace +
// metric_name [+ dimensions, stat, period]) or a Metrics Insights expression.
type Payload struct {
	Namespace  string            `json:"namespace,omitempty"`
	MetricName string            `json:"metric_name,omitempty"`
	Dimensions map[string]string `json:"dimensions,omitempty"`
	Stat       string            `json:"stat,omitempty"` // default Average
	Period     int32             `json:"period,omitempty"`
	Expression string            `json:"expression,omitempty"` // Metrics Insights SQL
	Start      string            `json:"start"`                // RFC3339, required
	End        string            `json:"end"`                  // RFC3339, required
	Region     string            `json:"region,omitempty"`
}

// Series is one metric time series.
type Series struct {
	ID         string    `json:"id"`
	Label      string    `json:"label,omitempty"`
	Timestamps []string  `json:"timestamps"`
	Values     []float64 `json:"values"`
}

// MetricResult is the result payload.
type MetricResult struct {
	Series []Series `json:"series"`
}

type Task struct {
	clientFactory func(ctx context.Context, region string) (getMetricDataAPI, error)
}

func New() *Task {
	return &Task{clientFactory: func(ctx context.Context, region string) (getMetricDataAPI, error) {
		cfg, err := awshelper.LoadConfig(ctx, awshelper.Options{Region: region})
		if err != nil {
			return nil, err
		}
		return cloudwatch.NewFromConfig(cfg), nil
	}}
}

func NewWithClientFactory(f func(ctx context.Context, region string) (getMetricDataAPI, error)) *Task {
	return &Task{clientFactory: f}
}

func (t *Task) Name() string { return TaskName }

func (t *Task) Execute(ctx context.Context, rawPayload json.RawMessage) (*task.Result, error) {
	var payload Payload
	if err := json.Unmarshal(rawPayload, &payload); err != nil {
		return task.NewErrorResult(fmt.Sprintf("invalid payload: %v", err)), nil
	}
	if payload.MetricName == "" && payload.Expression == "" {
		return task.NewErrorResult("either metric_name or expression is required"), nil
	}
	start, err := time.Parse(time.RFC3339, payload.Start)
	if err != nil {
		return task.NewErrorResult(fmt.Sprintf("invalid start (want RFC3339): %v", err)), nil
	}
	end, err := time.Parse(time.RFC3339, payload.End)
	if err != nil {
		return task.NewErrorResult(fmt.Sprintf("invalid end (want RFC3339): %v", err)), nil
	}

	query := cwtypes.MetricDataQuery{Id: aws.String("m0"), ReturnData: aws.Bool(true)}
	if payload.Expression != "" {
		query.Expression = aws.String(payload.Expression)
	} else {
		period := payload.Period
		if period <= 0 {
			period = defaultPeriod
		}
		stat := payload.Stat
		if stat == "" {
			stat = "Average"
		}
		dims := make([]cwtypes.Dimension, 0, len(payload.Dimensions))
		for k, v := range payload.Dimensions {
			dims = append(dims, cwtypes.Dimension{Name: aws.String(k), Value: aws.String(v)})
		}
		query.MetricStat = &cwtypes.MetricStat{
			Metric: &cwtypes.Metric{
				Namespace:  aws.String(payload.Namespace),
				MetricName: aws.String(payload.MetricName),
				Dimensions: dims,
			},
			Period: aws.Int32(period),
			Stat:   aws.String(stat),
		}
	}

	client, err := t.clientFactory(ctx, payload.Region)
	if err != nil {
		return nil, fmt.Errorf("failed to build cloudwatch client: %w", err)
	}

	out, err := client.GetMetricData(ctx, &cloudwatch.GetMetricDataInput{
		StartTime:         aws.Time(start),
		EndTime:           aws.Time(end),
		MetricDataQueries: []cwtypes.MetricDataQuery{query},
	})
	if err != nil {
		return nil, fmt.Errorf("get metric data: %w", err)
	}

	result := MetricResult{Series: []Series{}}
	for _, r := range out.MetricDataResults {
		s := Series{
			ID:         aws.ToString(r.Id),
			Label:      aws.ToString(r.Label),
			Timestamps: make([]string, 0, len(r.Timestamps)),
			Values:     r.Values,
		}
		for _, ts := range r.Timestamps {
			s.Timestamps = append(s.Timestamps, ts.UTC().Format(time.RFC3339))
		}
		result.Series = append(result.Series, s)
	}

	return task.NewSuccessResultWithDetails(fmt.Sprintf("%d series", len(result.Series)), result), nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/task/cw_get_metrics/`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add internal/task/cw_get_metrics/
git commit -m "feat(cw_get_metrics): add CloudWatch GetMetricData task with Metrics Insights"
```

---

### Task 6: `cw_list_metrics` task

**Files:**
- Create: `internal/task/cw_list_metrics/task.go`
- Test: `internal/task/cw_list_metrics/task_test.go`

**Interfaces:**
- Consumes: `awshelper.LoadConfig`/`Options`; `task.*`.
- Produces:
  - `const TaskName = "cw_list_metrics"`
  - `type listMetricsAPI interface { ListMetrics(ctx, *cloudwatch.ListMetricsInput, ...func(*cloudwatch.Options)) (*cloudwatch.ListMetricsOutput, error) }`
  - `func New() *Task`, `func NewWithClientFactory(func(ctx, region string) (listMetricsAPI, error)) *Task`
  - `type MetricInfo struct { Namespace, MetricName string; Dimensions map[string]string }`, `type MetricList struct { Total int; Metrics []MetricInfo }`

- [ ] **Step 1: Write the failing test**

Create `internal/task/cw_list_metrics/task_test.go`:
```go
package cw_list_metrics

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cwtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
)

type fakeLM struct {
	in  *cloudwatch.ListMetricsInput
	out *cloudwatch.ListMetricsOutput
	err error
}

func (f *fakeLM) ListMetrics(_ context.Context, in *cloudwatch.ListMetricsInput, _ ...func(*cloudwatch.Options)) (*cloudwatch.ListMetricsOutput, error) {
	f.in = in
	return f.out, f.err
}

func newTestTask(api *fakeLM) *Task {
	return NewWithClientFactory(func(_ context.Context, _ string) (listMetricsAPI, error) { return api, nil })
}

func TestExecute_NormalizesMetrics(t *testing.T) {
	api := &fakeLM{out: &cloudwatch.ListMetricsOutput{
		Metrics: []cwtypes.Metric{{
			Namespace:  aws.String("AWS/EC2"),
			MetricName: aws.String("CPUUtilization"),
			Dimensions: []cwtypes.Dimension{{Name: aws.String("InstanceId"), Value: aws.String("i-1")}},
		}},
	}}
	res, err := newTestTask(api).Execute(context.Background(), json.RawMessage(`{"namespace":"AWS/EC2"}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	list := res.Details.(MetricList)
	if list.Total != 1 || list.Metrics[0].MetricName != "CPUUtilization" {
		t.Fatalf("unexpected list: %+v", list)
	}
	if aws.ToString(api.in.Namespace) != "AWS/EC2" {
		t.Fatalf("namespace not forwarded: %+v", api.in.Namespace)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/task/cw_list_metrics/`
Expected: FAIL — undefined symbols.

- [ ] **Step 3: Write minimal implementation**

Create `internal/task/cw_list_metrics/task.go`:
```go
// Package cw_list_metrics lists available CloudWatch metrics (discovery).
package cw_list_metrics

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cwtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"

	awshelper "github.com/loafoe/centcom-satellite/internal/aws"
	"github.com/loafoe/centcom-satellite/internal/task"
)

const TaskName = "cw_list_metrics"

type listMetricsAPI interface {
	ListMetrics(context.Context, *cloudwatch.ListMetricsInput, ...func(*cloudwatch.Options)) (*cloudwatch.ListMetricsOutput, error)
}

// Payload for cw_list_metrics. All fields optional.
type Payload struct {
	Namespace  string            `json:"namespace,omitempty"`
	MetricName string            `json:"metric_name,omitempty"`
	Dimensions map[string]string `json:"dimensions,omitempty"`
	Region     string            `json:"region,omitempty"`
}

// MetricInfo describes one discovered metric.
type MetricInfo struct {
	Namespace  string            `json:"namespace"`
	MetricName string            `json:"metric_name"`
	Dimensions map[string]string `json:"dimensions,omitempty"`
}

// MetricList is the result payload.
type MetricList struct {
	Total   int          `json:"total"`
	Metrics []MetricInfo `json:"metrics"`
}

type Task struct {
	clientFactory func(ctx context.Context, region string) (listMetricsAPI, error)
}

func New() *Task {
	return &Task{clientFactory: func(ctx context.Context, region string) (listMetricsAPI, error) {
		cfg, err := awshelper.LoadConfig(ctx, awshelper.Options{Region: region})
		if err != nil {
			return nil, err
		}
		return cloudwatch.NewFromConfig(cfg), nil
	}}
}

func NewWithClientFactory(f func(ctx context.Context, region string) (listMetricsAPI, error)) *Task {
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

	input := &cloudwatch.ListMetricsInput{}
	if payload.Namespace != "" {
		input.Namespace = aws.String(payload.Namespace)
	}
	if payload.MetricName != "" {
		input.MetricName = aws.String(payload.MetricName)
	}
	for k, v := range payload.Dimensions {
		input.Dimensions = append(input.Dimensions, cwtypes.DimensionFilter{
			Name:  aws.String(k),
			Value: aws.String(v),
		})
	}

	client, err := t.clientFactory(ctx, payload.Region)
	if err != nil {
		return nil, fmt.Errorf("failed to build cloudwatch client: %w", err)
	}

	result := MetricList{Metrics: []MetricInfo{}}
	paginator := cloudwatch.NewListMetricsPaginator(client, input)
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("list metrics: %w", err)
		}
		for _, m := range page.Metrics {
			dims := map[string]string{}
			for _, d := range m.Dimensions {
				dims[aws.ToString(d.Name)] = aws.ToString(d.Value)
			}
			result.Metrics = append(result.Metrics, MetricInfo{
				Namespace:  aws.ToString(m.Namespace),
				MetricName: aws.ToString(m.MetricName),
				Dimensions: dims,
			})
		}
	}
	result.Total = len(result.Metrics)

	return task.NewSuccessResultWithDetails(fmt.Sprintf("found %d metrics", result.Total), result), nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/task/cw_list_metrics/`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/task/cw_list_metrics/
git commit -m "feat(cw_list_metrics): add CloudWatch metric discovery task"
```

---

### Task 7: `cw_describe_log_groups` task

**Files:**
- Create: `internal/task/cw_describe_log_groups/task.go`
- Test: `internal/task/cw_describe_log_groups/task_test.go`

**Interfaces:**
- Consumes: `awshelper.LoadConfig`/`Options`; `task.*`.
- Produces:
  - `const TaskName = "cw_describe_log_groups"`
  - `type describeLogGroupsAPI interface { DescribeLogGroups(ctx, *cloudwatchlogs.DescribeLogGroupsInput, ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.DescribeLogGroupsOutput, error) }`
  - `func New() *Task`, `func NewWithClientFactory(func(ctx, region string) (describeLogGroupsAPI, error)) *Task`
  - `type LogGroup struct { Name, ARN string; StoredBytes int64; RetentionDays int32; Created string }`

- [ ] **Step 1: Write the failing test**

Create `internal/task/cw_describe_log_groups/task_test.go`:
```go
package cw_describe_log_groups

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	cwltypes "github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"
)

type fakeDLG struct {
	in  *cloudwatchlogs.DescribeLogGroupsInput
	out *cloudwatchlogs.DescribeLogGroupsOutput
	err error
}

func (f *fakeDLG) DescribeLogGroups(_ context.Context, in *cloudwatchlogs.DescribeLogGroupsInput, _ ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.DescribeLogGroupsOutput, error) {
	f.in = in
	return f.out, f.err
}

func newTestTask(api *fakeDLG) *Task {
	return NewWithClientFactory(func(_ context.Context, _ string) (describeLogGroupsAPI, error) { return api, nil })
}

func TestExecute_NormalizesLogGroups(t *testing.T) {
	api := &fakeDLG{out: &cloudwatchlogs.DescribeLogGroupsOutput{
		LogGroups: []cwltypes.LogGroup{{
			LogGroupName:    aws.String("/aws/lambda/fn"),
			Arn:             aws.String("arn:aws:logs:eu-west-1:1:log-group:/aws/lambda/fn:*"),
			StoredBytes:     aws.Int64(2048),
			RetentionInDays: aws.Int32(14),
			CreationTime:    aws.Int64(1751284800000),
		}},
	}}
	res, err := newTestTask(api).Execute(context.Background(), json.RawMessage(`{"name_prefix":"/aws/lambda/"}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	list := res.Details.(LogGroupList)
	if list.Total != 1 || list.LogGroups[0].Name != "/aws/lambda/fn" || list.LogGroups[0].StoredBytes != 2048 {
		t.Fatalf("unexpected list: %+v", list)
	}
	if aws.ToString(api.in.LogGroupNamePrefix) != "/aws/lambda/" {
		t.Fatalf("prefix not forwarded: %+v", api.in.LogGroupNamePrefix)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/task/cw_describe_log_groups/`
Expected: FAIL — undefined symbols.

- [ ] **Step 3: Write minimal implementation**

Create `internal/task/cw_describe_log_groups/task.go`:
```go
// Package cw_describe_log_groups lists CloudWatch Logs log groups (discovery).
package cw_describe_log_groups

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"

	awshelper "github.com/loafoe/centcom-satellite/internal/aws"
	"github.com/loafoe/centcom-satellite/internal/task"
)

const TaskName = "cw_describe_log_groups"

const defaultLimit = 50

type describeLogGroupsAPI interface {
	DescribeLogGroups(context.Context, *cloudwatchlogs.DescribeLogGroupsInput, ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.DescribeLogGroupsOutput, error)
}

// Payload for cw_describe_log_groups.
type Payload struct {
	NamePrefix string `json:"name_prefix,omitempty"`
	Limit      int32  `json:"limit,omitempty"`
	Region     string `json:"region,omitempty"`
}

// LogGroup describes one log group.
type LogGroup struct {
	Name          string `json:"name"`
	ARN           string `json:"arn,omitempty"`
	StoredBytes   int64  `json:"stored_bytes"`
	RetentionDays int32  `json:"retention_days,omitempty"`
	Created       string `json:"created,omitempty"`
}

// LogGroupList is the result payload.
type LogGroupList struct {
	Total     int        `json:"total"`
	LogGroups []LogGroup `json:"log_groups"`
}

type Task struct {
	clientFactory func(ctx context.Context, region string) (describeLogGroupsAPI, error)
}

func New() *Task {
	return &Task{clientFactory: func(ctx context.Context, region string) (describeLogGroupsAPI, error) {
		cfg, err := awshelper.LoadConfig(ctx, awshelper.Options{Region: region})
		if err != nil {
			return nil, err
		}
		return cloudwatchlogs.NewFromConfig(cfg), nil
	}}
}

func NewWithClientFactory(f func(ctx context.Context, region string) (describeLogGroupsAPI, error)) *Task {
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
	limit := payload.Limit
	if limit <= 0 {
		limit = defaultLimit
	}

	input := &cloudwatchlogs.DescribeLogGroupsInput{Limit: aws.Int32(limit)}
	if payload.NamePrefix != "" {
		input.LogGroupNamePrefix = aws.String(payload.NamePrefix)
	}

	client, err := t.clientFactory(ctx, payload.Region)
	if err != nil {
		return nil, fmt.Errorf("failed to build logs client: %w", err)
	}

	result := LogGroupList{LogGroups: []LogGroup{}}
	paginator := cloudwatchlogs.NewDescribeLogGroupsPaginator(client, input)
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("describe log groups: %w", err)
		}
		for _, g := range page.LogGroups {
			lg := LogGroup{
				Name:        aws.ToString(g.LogGroupName),
				ARN:         aws.ToString(g.Arn),
				StoredBytes: aws.ToInt64(g.StoredBytes),
			}
			if g.RetentionInDays != nil {
				lg.RetentionDays = *g.RetentionInDays
			}
			if g.CreationTime != nil {
				lg.Created = time.UnixMilli(*g.CreationTime).UTC().Format(time.RFC3339)
			}
			result.LogGroups = append(result.LogGroups, lg)
		}
	}
	result.Total = len(result.LogGroups)

	return task.NewSuccessResultWithDetails(fmt.Sprintf("found %d log groups", result.Total), result), nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/task/cw_describe_log_groups/`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/task/cw_describe_log_groups/
git commit -m "feat(cw_describe_log_groups): add CloudWatch Logs log-group discovery task"
```

---

### Task 8: `cw_logs_query` task (Logs Insights, start → poll)

**Files:**
- Create: `internal/task/cw_logs_query/task.go`
- Test: `internal/task/cw_logs_query/task_test.go`

**Interfaces:**
- Consumes: `awshelper.LoadConfig`/`Options`; `task.*`.
- Produces:
  - `const TaskName = "cw_logs_query"`
  - `type logsInsightsAPI interface { StartQuery(...); GetQueryResults(...); StopQuery(...) }` (exact signatures below).
  - `func New() *Task`, `func NewWithClientFactory(func(ctx, region string) (logsInsightsAPI, error)) *Task`
  - The poll interval is injectable (`pollInterval time.Duration`) so tests run instantly.

- [ ] **Step 1: Write the failing test**

Create `internal/task/cw_logs_query/task_test.go`:
```go
package cw_logs_query

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	cwltypes "github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"
)

type fakeLogs struct {
	getCalls int
}

func (f *fakeLogs) StartQuery(_ context.Context, _ *cloudwatchlogs.StartQueryInput, _ ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.StartQueryOutput, error) {
	return &cloudwatchlogs.StartQueryOutput{QueryId: aws.String("q-1")}, nil
}

func (f *fakeLogs) GetQueryResults(_ context.Context, _ *cloudwatchlogs.GetQueryResultsInput, _ ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.GetQueryResultsOutput, error) {
	f.getCalls++
	if f.getCalls < 2 {
		return &cloudwatchlogs.GetQueryResultsOutput{Status: cwltypes.QueryStatusRunning}, nil
	}
	return &cloudwatchlogs.GetQueryResultsOutput{
		Status: cwltypes.QueryStatusComplete,
		Results: [][]cwltypes.ResultField{{
			{Field: aws.String("@timestamp"), Value: aws.String("2026-06-30 10:00:00.000")},
			{Field: aws.String("@message"), Value: aws.String("hello")},
		}},
	}, nil
}

func (f *fakeLogs) StopQuery(_ context.Context, _ *cloudwatchlogs.StopQueryInput, _ ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.StopQueryOutput, error) {
	return &cloudwatchlogs.StopQueryOutput{}, nil
}

func newTestTask(api logsInsightsAPI) *Task {
	t := NewWithClientFactory(func(_ context.Context, _ string) (logsInsightsAPI, error) { return api, nil })
	t.pollInterval = time.Millisecond
	return t
}

func TestExecute_PollsUntilComplete(t *testing.T) {
	api := &fakeLogs{}
	payload := `{"log_groups":["/aws/lambda/fn"],"query":"fields @message","start":"2026-06-30T09:00:00Z","end":"2026-06-30T11:00:00Z"}`
	res, err := newTestTask(api).Execute(context.Background(), json.RawMessage(payload))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	qr := res.Details.(QueryResult)
	if qr.Status != "Complete" || len(qr.Rows) != 1 || qr.Rows[0]["@message"] != "hello" {
		t.Fatalf("unexpected result: %+v", qr)
	}
	if api.getCalls < 2 {
		t.Fatalf("expected polling (>=2 GetQueryResults calls), got %d", api.getCalls)
	}
}

func TestExecute_MissingQuery(t *testing.T) {
	res, err := newTestTask(&fakeLogs{}).Execute(context.Background(), json.RawMessage(`{"log_groups":["g"],"start":"2026-06-30T09:00:00Z","end":"2026-06-30T11:00:00Z"}`))
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if res.Success {
		t.Fatal("expected success=false when query missing")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/task/cw_logs_query/`
Expected: FAIL — undefined symbols.

- [ ] **Step 3: Write minimal implementation**

Create `internal/task/cw_logs_query/task.go`:
```go
// Package cw_logs_query runs a CloudWatch Logs Insights query and polls for
// results until the query completes or the deadline is reached.
package cw_logs_query

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	cwltypes "github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"

	awshelper "github.com/loafoe/centcom-satellite/internal/aws"
	"github.com/loafoe/centcom-satellite/internal/task"
)

const TaskName = "cw_logs_query"

const (
	defaultLimit    = 100
	defaultTimeout  = 30 * time.Second
	maxTimeout      = 60 * time.Second
	defaultPollWait = 1 * time.Second
)

type logsInsightsAPI interface {
	StartQuery(context.Context, *cloudwatchlogs.StartQueryInput, ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.StartQueryOutput, error)
	GetQueryResults(context.Context, *cloudwatchlogs.GetQueryResultsInput, ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.GetQueryResultsOutput, error)
	StopQuery(context.Context, *cloudwatchlogs.StopQueryInput, ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.StopQueryOutput, error)
}

// Payload for cw_logs_query.
type Payload struct {
	LogGroups []string `json:"log_groups"`
	Query     string   `json:"query"`
	Start     string   `json:"start"` // RFC3339, required
	End       string   `json:"end"`   // RFC3339, required
	Limit     int32    `json:"limit,omitempty"`
	TimeoutMs int      `json:"timeout_ms,omitempty"`
	Region    string   `json:"region,omitempty"`
}

// QueryResult is the result payload.
type QueryResult struct {
	Status string              `json:"status"`
	Rows   []map[string]string `json:"rows"`
}

type Task struct {
	clientFactory func(ctx context.Context, region string) (logsInsightsAPI, error)
	pollInterval  time.Duration
}

func New() *Task {
	return &Task{
		clientFactory: func(ctx context.Context, region string) (logsInsightsAPI, error) {
			cfg, err := awshelper.LoadConfig(ctx, awshelper.Options{Region: region})
			if err != nil {
				return nil, err
			}
			return cloudwatchlogs.NewFromConfig(cfg), nil
		},
		pollInterval: defaultPollWait,
	}
}

func NewWithClientFactory(f func(ctx context.Context, region string) (logsInsightsAPI, error)) *Task {
	return &Task{clientFactory: f, pollInterval: defaultPollWait}
}

func (t *Task) Name() string { return TaskName }

func (t *Task) Execute(ctx context.Context, rawPayload json.RawMessage) (*task.Result, error) {
	var payload Payload
	if err := json.Unmarshal(rawPayload, &payload); err != nil {
		return task.NewErrorResult(fmt.Sprintf("invalid payload: %v", err)), nil
	}
	if len(payload.LogGroups) == 0 {
		return task.NewErrorResult("log_groups is required"), nil
	}
	if payload.Query == "" {
		return task.NewErrorResult("query is required"), nil
	}
	start, err := time.Parse(time.RFC3339, payload.Start)
	if err != nil {
		return task.NewErrorResult(fmt.Sprintf("invalid start (want RFC3339): %v", err)), nil
	}
	end, err := time.Parse(time.RFC3339, payload.End)
	if err != nil {
		return task.NewErrorResult(fmt.Sprintf("invalid end (want RFC3339): %v", err)), nil
	}
	limit := payload.Limit
	if limit <= 0 {
		limit = defaultLimit
	}
	timeout := defaultTimeout
	if payload.TimeoutMs > 0 {
		timeout = time.Duration(payload.TimeoutMs) * time.Millisecond
		if timeout > maxTimeout {
			timeout = maxTimeout
		}
	}

	client, err := t.clientFactory(ctx, payload.Region)
	if err != nil {
		return nil, fmt.Errorf("failed to build logs client: %w", err)
	}

	startOut, err := client.StartQuery(ctx, &cloudwatchlogs.StartQueryInput{
		LogGroupNames: payload.LogGroups,
		QueryString:   aws.String(payload.Query),
		StartTime:     aws.Int64(start.Unix()),
		EndTime:       aws.Int64(end.Unix()),
		Limit:         aws.Int32(limit),
	})
	if err != nil {
		return nil, fmt.Errorf("start query: %w", err)
	}
	queryID := aws.ToString(startOut.QueryId)

	deadline := time.Now().Add(timeout)
	for {
		out, err := client.GetQueryResults(ctx, &cloudwatchlogs.GetQueryResultsInput{QueryId: aws.String(queryID)})
		if err != nil {
			return nil, fmt.Errorf("get query results: %w", err)
		}

		switch out.Status {
		case cwltypes.QueryStatusComplete:
			return task.NewSuccessResultWithDetails(
				fmt.Sprintf("query complete: %d rows", len(out.Results)),
				buildResult(out),
			), nil
		case cwltypes.QueryStatusFailed, cwltypes.QueryStatusCancelled, cwltypes.QueryStatusTimeout:
			return task.NewErrorResult(fmt.Sprintf("query ended with status %s", out.Status)), nil
		}

		if time.Now().After(deadline) {
			_, _ = client.StopQuery(ctx, &cloudwatchlogs.StopQueryInput{QueryId: aws.String(queryID)})
			return task.NewErrorResult(fmt.Sprintf("query timed out after %s (last status %s)", timeout, out.Status)), nil
		}

		select {
		case <-ctx.Done():
			_, _ = client.StopQuery(ctx, &cloudwatchlogs.StopQueryInput{QueryId: aws.String(queryID)})
			return nil, ctx.Err()
		case <-time.After(t.pollInterval):
		}
	}
}

func buildResult(out *cloudwatchlogs.GetQueryResultsOutput) QueryResult {
	qr := QueryResult{Status: string(out.Status), Rows: []map[string]string{}}
	for _, row := range out.Results {
		m := map[string]string{}
		for _, f := range row {
			m[aws.ToString(f.Field)] = aws.ToString(f.Value)
		}
		qr.Rows = append(qr.Rows, m)
	}
	return qr
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/task/cw_logs_query/`
Expected: PASS (2 tests).

- [ ] **Step 5: Commit**

```bash
git add internal/task/cw_logs_query/
git commit -m "feat(cw_logs_query): add CloudWatch Logs Insights query task with polling"
```

---

## Wiring & Documentation

### Task 9: Config flag, capability, and registration wiring

**Files:**
- Modify: `internal/config/config.go`
- Modify: `internal/task/cluster_info/task.go`
- Modify: `cmd/centcom-satellite/main.go`
- Test: `internal/config/config_test.go` (add case; file exists — append test function)

**Interfaces:**
- Consumes: all seven task packages' `New()` constructors.
- Produces: `cfg.Features.CloudWatchRCAEnabled bool`; `cluster_info.Capabilities.CloudWatchRCA bool`; registered tasks when the flag is true.

- [ ] **Step 1: Add the failing config test**

Append to `internal/config/config_test.go`:
```go
func TestLoad_CloudWatchRCAFlag(t *testing.T) {
	t.Setenv("ALLOW_UNAUTHENTICATED", "true")
	t.Setenv("CLOUDWATCH_RCA_ENABLED", "true")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !cfg.Features.CloudWatchRCAEnabled {
		t.Fatal("CloudWatchRCAEnabled = false, want true")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/config/ -run TestLoad_CloudWatchRCAFlag`
Expected: FAIL — `cfg.Features.CloudWatchRCAEnabled undefined`.

- [ ] **Step 3: Add the flag field**

In `internal/config/config.go`, add to the `FeaturesConfig` struct (after `AutoRemediateEnabled`):
```go
	// CloudWatchRCAEnabled enables the CloudWatch/Cost-Explorer data-retrieval
	// tasks (cw_list_alarms, cw_alarm_history, cw_get_metrics, cw_list_metrics,
	// cw_describe_log_groups, cw_logs_query, cost_explorer). Disabled by default
	// as it requires AWS credentials (IRSA) and IAM permissions.
	CloudWatchRCAEnabled bool
```

And in `Load()`, add to the `Features: FeaturesConfig{...}` literal (after `AutoRemediateEnabled`):
```go
			CloudWatchRCAEnabled: getEnvBool("CLOUDWATCH_RCA_ENABLED", false),
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/config/ -run TestLoad_CloudWatchRCAFlag`
Expected: PASS.

- [ ] **Step 5: Add the capability field**

In `internal/task/cluster_info/task.go`, add to the `Capabilities` struct (after `ConfigmapRead`):
```go
	CloudWatchRCA   bool `json:"cloudwatch_rca"`
```

- [ ] **Step 6: Wire registration in main.go**

In `cmd/centcom-satellite/main.go`, add these imports to the task import block (keep alphabetical grouping):
```go
	"github.com/loafoe/centcom-satellite/internal/task/cost_explorer"
	"github.com/loafoe/centcom-satellite/internal/task/cw_alarm_history"
	"github.com/loafoe/centcom-satellite/internal/task/cw_describe_log_groups"
	"github.com/loafoe/centcom-satellite/internal/task/cw_get_metrics"
	"github.com/loafoe/centcom-satellite/internal/task/cw_list_alarms"
	"github.com/loafoe/centcom-satellite/internal/task/cw_list_metrics"
	"github.com/loafoe/centcom-satellite/internal/task/cw_logs_query"
```

Add `CloudWatchRCA` to the `WithCapabilities(cluster_info.Capabilities{...})` literal:
```go
		CloudWatchRCA:   cfg.Features.CloudWatchRCAEnabled,
```

Add this flag-gated registration block after the `pv_resize` block (before the SPIRE setup):
```go
	// Optional: CloudWatch RCA data-retrieval tasks (require AWS credentials + IAM)
	if cfg.Features.CloudWatchRCAEnabled {
		registry.Register(cw_list_alarms.New())
		registry.Register(cw_alarm_history.New())
		registry.Register(cw_get_metrics.New())
		registry.Register(cw_list_metrics.New())
		registry.Register(cw_describe_log_groups.New())
		registry.Register(cw_logs_query.New())
		registry.Register(cost_explorer.New())
		slog.Info("cloudwatch RCA tasks enabled",
			"tasks", "cw_list_alarms,cw_alarm_history,cw_get_metrics,cw_list_metrics,cw_describe_log_groups,cw_logs_query,cost_explorer")
	}
```

- [ ] **Step 7: Build and run the full test suite**

Run:
```bash
cd /Users/andy/DEV/Go/centcom-satellite
go build ./... && make test
```
Expected: build succeeds; all tests pass.

- [ ] **Step 8: Verify tasks register (manual smoke test)**

Run:
```bash
ALLOW_UNAUTHENTICATED=true CLOUDWATCH_RCA_ENABLED=true go run ./cmd/centcom-satellite &
sleep 2
curl -s http://localhost:8080/tasks | grep -o 'cw_list_alarms'
kill %1
```
Expected: prints `cw_list_alarms` (task is registered and listed).

- [ ] **Step 9: Commit**

```bash
git add internal/config/ internal/task/cluster_info/ cmd/centcom-satellite/main.go
git commit -m "feat: wire CloudWatch RCA tasks behind CLOUDWATCH_RCA_ENABLED flag"
```

---

### Task 10: Documentation & IAM policy

**Files:**
- Modify: `README.md` (Available Tasks table + config env-var table)
- Modify: `CLAUDE.md` (Configuration section + task list)
- Create: `deploy/iam-policy-cloudwatch-rca.json`

- [ ] **Step 1: Add the IAM policy file**

Create `deploy/iam-policy-cloudwatch-rca.json`:
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "CentcomCloudWatchRCA",
      "Effect": "Allow",
      "Action": [
        "cloudwatch:DescribeAlarms",
        "cloudwatch:DescribeAlarmHistory",
        "cloudwatch:GetMetricData",
        "cloudwatch:ListMetrics",
        "logs:DescribeLogGroups",
        "logs:StartQuery",
        "logs:GetQueryResults",
        "logs:StopQuery",
        "ce:GetCostAndUsage"
      ],
      "Resource": "*"
    }
  ]
}
```

- [ ] **Step 2: Update README Available Tasks table**

In `README.md`, add these rows to the Available Tasks table (alphabetical):
```markdown
| `cost_explorer` | Get AWS cost & usage, optionally by service |
| `cw_alarm_history` | Get CloudWatch alarm state-change history |
| `cw_describe_log_groups` | List CloudWatch Logs log groups |
| `cw_get_metrics` | Get CloudWatch metric data (query or Metrics Insights) |
| `cw_list_alarms` | List CloudWatch alarms by state |
| `cw_list_metrics` | Discover available CloudWatch metrics |
| `cw_logs_query` | Run a CloudWatch Logs Insights query |
```

Add to the README config env-var table:
```markdown
| `CLOUDWATCH_RCA_ENABLED` | false | Enable CloudWatch/Cost-Explorer data-retrieval tasks (needs AWS IRSA + IAM) |
```

- [ ] **Step 3: Update CLAUDE.md**

In `CLAUDE.md` Configuration section, add under the environment variables list:
```markdown
- `CLOUDWATCH_RCA_ENABLED` (default: false) - Enable CloudWatch/Cost-Explorer data-retrieval tasks (cw_list_alarms, cw_alarm_history, cw_get_metrics, cw_list_metrics, cw_describe_log_groups, cw_logs_query, cost_explorer). Requires AWS credentials via IRSA and the IAM policy in `deploy/iam-policy-cloudwatch-rca.json`.
```

- [ ] **Step 4: Verify docs build / no broken references**

Run: `cd /Users/andy/DEV/Go/centcom-satellite && go build ./... && make test`
Expected: build + tests pass (docs are markdown; this confirms nothing else broke).

- [ ] **Step 5: Commit**

```bash
git add README.md CLAUDE.md deploy/iam-policy-cloudwatch-rca.json
git commit -m "docs: document CloudWatch RCA tasks and add IAM policy"
```

---

## Final Verification

- [ ] Run `cd /Users/andy/DEV/Go/centcom-satellite && go build ./... && make test` — all green.
- [ ] Run `gofmt -l internal/aws internal/task/cw_* internal/task/cost_explorer` — no files listed (all formatted).
- [ ] Confirm `curl -s localhost:8080/tasks` lists all 7 new task names when `CLOUDWATCH_RCA_ENABLED=true`.
- [ ] Confirm `/info` or `cluster_info` reports `capabilities.cloudwatch_rca: true` when enabled.
