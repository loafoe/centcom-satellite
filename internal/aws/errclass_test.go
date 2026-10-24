package aws

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	gdtypes "github.com/aws/aws-sdk-go-v2/service/guardduty/types"
)

func TestWrapError_Nil(t *testing.T) {
	result, err := WrapError("get findings statistics", nil)
	if result != nil || err != nil {
		t.Fatalf("WrapError(nil) = (%v, %v), want (nil, nil)", result, err)
	}
}

// TestWrapError_ClientFault is the regression test for the 2026-10-24
// ops-sandbox incident: a GuardDuty BadRequestException (ErrorFault ==
// smithy.FaultClient) must become a self-describing task.Result, not a bare
// Go error — otherwise HandleTask turns it into an opaque 500 and the real,
// actionable AWS message never reaches the caller.
func TestWrapError_ClientFault(t *testing.T) {
	apiErr := &gdtypes.BadRequestException{
		Message: aws.String("The request is rejected because the input detectorId is not owned by the current account"),
	}
	result, err := WrapError("get findings statistics", apiErr)
	if err != nil {
		t.Fatalf("WrapError client fault: got error %v, want nil (must not become a 500)", err)
	}
	if result == nil {
		t.Fatal("WrapError client fault: got nil result, want a failed task.Result")
	}
	if result.Success {
		t.Error("result.Success = true, want false")
	}
	if !strings.Contains(result.Error, "BadRequestException") || !strings.Contains(result.Error, "not owned by the current account") {
		t.Errorf("result.Error = %q, want it to contain the real AWS error (BadRequestException + the detector/account message)", result.Error)
	}
}

// TestWrapError_ClientFault_Wrapped verifies classification still works when
// the AWS SDK error has been wrapped (e.g. the SDK's own operation-error
// wrapping, or a %w elsewhere in the call chain) rather than returned bare —
// errors.As must still find it.
func TestWrapError_ClientFault_Wrapped(t *testing.T) {
	apiErr := &gdtypes.ResourceNotFoundException{Message: aws.String("no such detector")}
	wrapped := fmt.Errorf("operation error GuardDuty: GetFindingsStatistics, https response error: %w", apiErr)
	result, err := WrapError("get findings statistics", wrapped)
	if err != nil {
		t.Fatalf("WrapError wrapped client fault: got error %v, want nil", err)
	}
	if result == nil || result.Success {
		t.Fatalf("WrapError wrapped client fault: got %+v, want a failed result", result)
	}
}

// TestWrapError_ServerFault verifies a server-side AWS error (GuardDuty's
// InternalServerErrorException, ErrorFault == smithy.FaultServer) still
// produces a real Go error — HandleTask must keep turning this into a
// genuine 500, since it is a transient infrastructure problem worth
// retrying, not a request mistake.
func TestWrapError_ServerFault(t *testing.T) {
	apiErr := &gdtypes.InternalServerErrorException{Message: aws.String("internal error")}
	result, err := WrapError("get findings statistics", apiErr)
	if result != nil {
		t.Fatalf("WrapError server fault: got result %+v, want nil", result)
	}
	if err == nil {
		t.Fatal("WrapError server fault: got nil error, want a real error (must still produce a 500)")
	}
	if !errors.As(err, new(*gdtypes.InternalServerErrorException)) {
		t.Errorf("WrapError server fault: original error not unwrappable via errors.As, got %v", err)
	}
}

// TestWrapError_NonAPIError verifies a plain Go error (network failure,
// context deadline, ...) — not an AWS API error at all — also still
// produces a real Go error, not a swallowed client-fault result.
func TestWrapError_NonAPIError(t *testing.T) {
	plain := errors.New("dial tcp: connection refused")
	result, err := WrapError("get findings statistics", plain)
	if result != nil {
		t.Fatalf("WrapError non-API error: got result %+v, want nil", result)
	}
	if err == nil {
		t.Fatal("WrapError non-API error: got nil error, want a real error")
	}
}
