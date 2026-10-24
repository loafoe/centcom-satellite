package aws

import (
	"errors"
	"fmt"

	smithy "github.com/aws/smithy-go"

	"github.com/loafoe/centcom-satellite/internal/task"
)

// WrapError classifies an error returned by an AWS SDK call and returns the
// (*task.Result, error) pair a Task.Execute should return for it.
//
// Every generated AWS service error type (BadRequestException,
// AccessDeniedException, ResourceNotFoundException, ValidationException,
// ...) implements smithy.APIError, whose ErrorFault() says whether AWS
// itself blames the request (smithy.FaultClient, i.e. an HTTP 4xx) or its
// own infrastructure (smithy.FaultServer / FaultUnknown, i.e. 5xx or a
// network failure) — this works identically across every AWS service, with
// no per-exception-type or per-task hardcoding.
//
// A client-fault error is never something retrying fixes (bad detector ID,
// wrong region, access denied, ...), so it is turned into a self-describing
// task.Result (Success: false, Error: the real AWS message) — HandleTask
// responds 200 with that body, so centcom and the LLM see the exact AWS
// error instead of an opaque 500. This is the fix for a real incident
// (2026-10-24, ops-sandbox): a cron paired a GuardDuty detector ID with the
// wrong region, GuardDuty correctly replied 400 BadRequestException ("the
// input detectorId is not owned by the current account"), and the task's
// own `return nil, fmt.Errorf(...)` turned that into a generic 500 — hiding
// the real, immediately-actionable error and making a one-off input mistake
// look like a persistent satellite fault.
//
// Any other error keeps producing a real Go error, which HandleTask turns
// into a genuine 500 — the correct signal for "transient, retry later, not
// a request problem."
func WrapError(context string, err error) (*task.Result, error) {
	if err == nil {
		return nil, nil
	}
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) && apiErr.ErrorFault() == smithy.FaultClient {
		return task.NewErrorResult(fmt.Sprintf("%s: %v", context, err)), nil
	}
	return nil, fmt.Errorf("%s: %w", context, err)
}
