package k8s

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

func TestWrapError_Nil(t *testing.T) {
	result, err := WrapError("get logs", nil)
	if result != nil || err != nil {
		t.Fatalf("WrapError(nil) = (%v, %v), want (nil, nil)", result, err)
	}
}

// TestWrapError_ClientFault is the regression test for the ri-obs-use1-ct
// incident: a GetLogs(previous: true) call against a container with no
// previous terminated instance returns a 400 BadRequest from the apiserver
// ("previous terminated container ... not found") — this must become a
// self-describing task.Result, not a bare Go error, or HandleTask turns it
// into an opaque 500 and the real, actionable apiserver message never
// reaches the caller.
func TestWrapError_ClientFault(t *testing.T) {
	podErr := apierrors.NewBadRequest(`previous terminated container "manager" in pod "provider-kubernetes-xyz" not found`)
	result, err := WrapError("get log stream", podErr)
	if err != nil {
		t.Fatalf("WrapError client fault: got error %v, want nil (must not become a 500)", err)
	}
	if result == nil {
		t.Fatal("WrapError client fault: got nil result, want a failed task.Result")
	}
	if result.Success {
		t.Error("result.Success = true, want false")
	}
	if !strings.Contains(result.Error, "previous terminated container") {
		t.Errorf("result.Error = %q, want it to contain the real apiserver message", result.Error)
	}
}

// TestWrapError_NotFound covers the other extremely common client-fault
// shape: a typo'd or already-deleted resource name.
func TestWrapError_NotFound(t *testing.T) {
	notFoundErr := apierrors.NewNotFound(schema.GroupResource{Resource: "pods"}, "provider-kubernetes-xyz")
	result, err := WrapError("get pod", notFoundErr)
	if err != nil {
		t.Fatalf("WrapError not found: got error %v, want nil", err)
	}
	if result == nil || result.Success {
		t.Fatalf("WrapError not found: got %+v, want a failed result", result)
	}
}

// TestWrapError_ClientFault_Wrapped verifies classification still works when
// the apiserver error has been wrapped (e.g. a client-go retry helper's own
// %w) rather than returned bare — errors.As must still find it.
func TestWrapError_ClientFault_Wrapped(t *testing.T) {
	forbiddenErr := apierrors.NewForbidden(schema.GroupResource{Resource: "pods"}, "x", errors.New("no permission"))
	wrapped := fmt.Errorf("list pods: %w", forbiddenErr)
	result, err := WrapError("get pod", wrapped)
	if err != nil {
		t.Fatalf("WrapError wrapped client fault: got error %v, want nil", err)
	}
	if result == nil || result.Success {
		t.Fatalf("WrapError wrapped client fault: got %+v, want a failed result", result)
	}
}

// TestWrapError_ServerFault verifies a server-side apiserver error (500
// InternalError) still produces a real Go error — HandleTask must keep
// turning this into a genuine 500, since it is a transient apiserver
// problem worth retrying, not a request mistake.
func TestWrapError_ServerFault(t *testing.T) {
	serverErr := apierrors.NewInternalError(errors.New("etcd request timed out"))
	result, err := WrapError("get pod", serverErr)
	if result != nil {
		t.Fatalf("WrapError server fault: got result %+v, want nil", result)
	}
	if err == nil {
		t.Fatal("WrapError server fault: got nil error, want a real error (must still produce a 500)")
	}
}

// TestWrapError_TooManyRequests verifies 429 (apiserver flow control / client
// rate limiting) is treated like a server fault, not a client fault — it is
// a real "retry later" signal, the same way AWS throttling is.
func TestWrapError_TooManyRequests(t *testing.T) {
	throttleErr := apierrors.NewTooManyRequests("client rate limiter Wait returned an error", 1)
	result, err := WrapError("list pods", throttleErr)
	if result != nil {
		t.Fatalf("WrapError 429: got result %+v, want nil", result)
	}
	if err == nil {
		t.Fatal("WrapError 429: got nil error, want a real error (must still produce a 500)")
	}
}

// TestWrapError_NonAPIStatusError verifies a plain transport-level error
// (network failure, context deadline, ...) — not an apiserver error at all
// — also still produces a real Go error, not a swallowed client-fault
// result.
func TestWrapError_NonAPIStatusError(t *testing.T) {
	plain := errors.New("dial tcp: connection refused")
	result, err := WrapError("get pod", plain)
	if result != nil {
		t.Fatalf("WrapError non-APIStatus error: got result %+v, want nil", result)
	}
	if err == nil {
		t.Fatal("WrapError non-APIStatus error: got nil error, want a real error")
	}
}
