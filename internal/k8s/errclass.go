package k8s

import (
	"errors"
	"fmt"

	apierrors "k8s.io/apimachinery/pkg/api/errors"

	"github.com/loafoe/centcom-satellite/internal/task"
)

// WrapError classifies an error returned by a Kubernetes control-plane API
// call and returns the (*task.Result, error) pair a Task.Execute should
// return for it.
//
// Every error the apiserver itself produces (NotFound, BadRequest,
// Forbidden, Conflict, AlreadyExists, Invalid, Gone, MethodNotAllowed,
// RequestEntityTooLarge, UnsupportedMediaType, ...) implements
// apierrors.APIStatus, whose Status().Code carries the real HTTP status the
// apiserver replied with — this works identically for every resource type
// and verb, with no per-reason or per-task hardcoding (the same approach
// awshelper.WrapError uses for AWS SDK errors via smithy.APIError).
//
// A 4xx status (except 429, which is a real "retry later" signal, same as
// 5xx) is never something retrying fixes on its own — a GetLogs(previous:
// true) against a container with no previous terminated instance, a typo'd
// resource name, an RBAC-denied verb, a stale resourceVersion — so it is
// turned into a self-describing task.Result (Success: false, Error: the
// real apiserver message) instead of a bare Go error: HandleTask responds
// 200 with that body, so centcom and the LLM see the exact apiserver error
// instead of an opaque 500. Any other error (5xx, 429, a transport-level
// failure with no APIStatus at all — connection refused, timeout, TLS) keeps
// producing a real Go error, so HandleTask still responds with a genuine
// 500 — the correct "retry later" signal.
func WrapError(context string, err error) (*task.Result, error) {
	if err == nil {
		return nil, nil
	}
	var status apierrors.APIStatus
	if errors.As(err, &status) {
		code := status.Status().Code
		if code >= 400 && code < 500 && code != 429 {
			return task.NewErrorResult(fmt.Sprintf("%s: %v", context, err)), nil
		}
	}
	return nil, fmt.Errorf("%s: %w", context, err)
}
