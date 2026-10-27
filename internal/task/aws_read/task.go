// Package aws_read performs one allowlisted, read-only AWS API call (IAM,
// IAM Identity Center admin, Identity Store) and returns the raw response.
// It fills the data gaps the bespoke tasks leave for access reviews: users,
// groups, roles, policies, credential report, access-key and service
// last-used data, permission sets and assignments.
package aws_read

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"

	awshelper "github.com/loafoe/centcom-satellite/internal/aws"
	"github.com/loafoe/centcom-satellite/internal/task"
)

const TaskName = "aws_read"

const callTimeout = 45 * time.Second

// Payload for aws_read. Service and Operation accept the API name
// ("ListUsers") or the CLI spelling ("list-users"); Params are the SDK input
// fields in the API's own names (e.g. {"UserName": "bob", "Marker": "..."}).
type Payload struct {
	Service   string          `json:"service"`
	Operation string          `json:"operation"`
	Params    json.RawMessage `json:"params,omitempty"`
	Region    string          `json:"region,omitempty"`
}

// Output is the task's Details.
type Output struct {
	Service   string         `json:"service"`
	Operation string         `json:"operation"`
	Region    string         `json:"region,omitempty"`
	Response  map[string]any `json:"response"`
}

// ConfigFactory builds the AWS config for a call.
type ConfigFactory func(ctx context.Context, region string) (aws.Config, error)

func defaultConfigFactory(ctx context.Context, region string) (aws.Config, error) {
	cfg, err := awshelper.LoadConfig(ctx, awshelper.Options{Region: region})
	if err != nil {
		return aws.Config{}, err
	}
	cfg.RetryMode = aws.RetryModeAdaptive
	cfg.RetryMaxAttempts = 5
	return cfg, nil
}

type Task struct{ configFactory ConfigFactory }

func New() *Task { return &Task{configFactory: defaultConfigFactory} }

func NewWithConfigFactory(f ConfigFactory) *Task { return &Task{configFactory: f} }

func (t *Task) Name() string { return TaskName }

func (t *Task) Execute(ctx context.Context, rawPayload json.RawMessage) (*task.Result, error) {
	var p Payload
	if len(rawPayload) > 0 {
		if err := json.Unmarshal(rawPayload, &p); err != nil {
			return task.NewErrorResult(fmt.Sprintf("invalid payload: %v", err)), nil
		}
	}
	service, operation, fn, msg := resolve(p.Service, p.Operation)
	if fn == nil {
		return task.NewErrorResult(msg), nil
	}

	if err := limiterFor(service).Wait(ctx); err != nil {
		return nil, fmt.Errorf("rate limiter: %w", err)
	}
	cfg, err := t.configFactory(ctx, p.Region)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}
	callCtx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()

	out, err := fn(callCtx, cfg, p.Params)
	if err != nil {
		var pe *paramsError
		if errors.As(err, &pe) {
			return task.NewErrorResult(fmt.Sprintf("invalid params for %s %s: %v", service, operation, pe.err)), nil
		}
		return awshelper.WrapError(fmt.Sprintf("%s %s", service, operation), err)
	}

	resp, err := toResponse(out)
	if err != nil {
		return nil, fmt.Errorf("encode %s %s response: %w", service, operation, err)
	}
	return task.NewSuccessResultWithDetails(
		fmt.Sprintf("%s %s ok", service, operation),
		Output{Service: service, Operation: operation, Region: cfg.Region, Response: resp},
	), nil
}
