package get_resource

import (
	"errors"
	"testing"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

func TestMapAPIError_NotFound(t *testing.T) {
	err := apierrors.NewNotFound(schema.GroupResource{Resource: "pods"}, "x")
	got := MapAPIError(err, "Pod", "x", "v1")
	if got.Code != ErrNotFound {
		t.Errorf("Code = %v, want %v", got.Code, ErrNotFound)
	}
}

func TestMapAPIError_Forbidden(t *testing.T) {
	err := apierrors.NewForbidden(schema.GroupResource{Resource: "pods"}, "x", errors.New("no permission"))
	got := MapAPIError(err, "Pod", "x", "v1")
	if got.Code != ErrForbidden {
		t.Errorf("Code = %v, want %v", got.Code, ErrForbidden)
	}
}

func TestMapAPIError_Timeout(t *testing.T) {
	err := apierrors.NewTimeoutError("took too long", 5)
	got := MapAPIError(err, "Pod", "x", "v1")
	if got.Code != ErrTimeout {
		t.Errorf("Code = %v, want %v", got.Code, ErrTimeout)
	}
}

// TestMapAPIError_ServerError is the regression test for the mislabeling
// bug: a genuine server-side apiserver error (500 InternalError) used to
// fall through to ErrInvalidRequest with the hint "Check apiVersion
// format" - actively misleading for a problem that has nothing to do with
// the request shape. It must now map to the distinct ErrServerError code
// with a hint that says to retry, not to fix the request.
func TestMapAPIError_ServerError(t *testing.T) {
	err := apierrors.NewInternalError(errors.New("etcd request timed out"))
	got := MapAPIError(err, "Pod", "x", "v1")
	if got.Code != ErrServerError {
		t.Errorf("Code = %v, want %v (got hint %q)", got.Code, ErrServerError, got.Hint)
	}
	if got.Hint == "Check apiVersion format (group/version)" {
		t.Error("hint still points at the request shape for a server-side error")
	}
}

// TestMapAPIError_TooManyRequestsIsServerError verifies 429 (apiserver flow
// control) is treated like a server fault, not a client mistake — the same
// "real retry later signal" semantics as AWS throttling.
func TestMapAPIError_TooManyRequestsIsServerError(t *testing.T) {
	err := apierrors.NewTooManyRequests("slow down", 1)
	got := MapAPIError(err, "Pod", "x", "v1")
	if got.Code != ErrServerError {
		t.Errorf("Code = %v, want %v", got.Code, ErrServerError)
	}
}

// TestMapAPIError_NonAPIStatusErrorIsServerError verifies a plain
// transport-level error (not an apiserver response at all) is also treated
// as a server fault rather than mislabeled as an invalid request.
func TestMapAPIError_NonAPIStatusErrorIsServerError(t *testing.T) {
	err := errors.New("dial tcp: connection refused")
	got := MapAPIError(err, "Pod", "x", "v1")
	if got.Code != ErrServerError {
		t.Errorf("Code = %v, want %v", got.Code, ErrServerError)
	}
}

// TestMapAPIError_GenuineBadRequestStaysInvalidRequest verifies an actual
// client-fault error that isn't one of the specially-named cases (NotFound/
// Forbidden/Timeout/NoKindMatch) still falls into ErrInvalidRequest, not
// ErrServerError - e.g. a malformed field selector.
func TestMapAPIError_GenuineBadRequestStaysInvalidRequest(t *testing.T) {
	err := apierrors.NewBadRequest("malformed field selector")
	got := MapAPIError(err, "Pod", "x", "v1")
	if got.Code != ErrInvalidRequest {
		t.Errorf("Code = %v, want %v", got.Code, ErrInvalidRequest)
	}
}
