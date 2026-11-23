package grpc

import (
	"os"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// A ResourceExhausted that names the device cap is not recoverable by
// retrying: the fleet is full until an operator raises the cap. Every other
// ResourceExhausted (a stream bound, the pre-auth gate) stays retryable.
func TestDeviceCapRefusalIsNotRetried(t *testing.T) {
	c := &PlatformClient{}
	if c.isRecoverableError(status.Error(codes.ResourceExhausted, deviceCapRefusalMessage)) {
		t.Fatal("the device-cap refusal must not be classified as recoverable")
	}
	if !c.isRecoverableError(status.Error(codes.ResourceExhausted, "too many unauthenticated connections; retry shortly")) {
		t.Fatal("a transient bound must stay recoverable")
	}
}

// The two sides of the contract live in two modules that share no code, so
// the string is compared at the source level when the platform tree is
// beside this one (the public repository holds both); elsewhere this skips.
func TestDeviceCapRefusalMessageMatchesThePlatform(t *testing.T) {
	const rel = "../../../../backend/pkg/webapp/domain/entitlement/device_cap.go"
	data, err := os.ReadFile(rel)
	if err != nil {
		t.Skipf("platform source not beside this module (%v); the contract is checked in the full checkout", err)
	}
	want := `GRPCRefusalMessage = "` + deviceCapRefusalMessage + `"`
	if !strings.Contains(string(data), want) {
		t.Fatalf("the platform's entitlement.GRPCRefusalMessage no longer equals %q", deviceCapRefusalMessage)
	}
}

// The refusal at the device's account limit is held for like the device
// cap, and its string is the platform's.
func TestAccountLimitRefusalIsNotRetried(t *testing.T) {
	c := &PlatformClient{}
	err := status.Error(codes.ResourceExhausted, accountLimitRefusalMessage)
	if c.isRecoverableError(err) || !isDeviceCapRefusal(err) {
		t.Fatal("the account-limit refusal must be held for, not retried")
	}
	data, rerr := os.ReadFile("../../../../backend/pkg/webapp/domain/entitlement/account_limit.go")
	if rerr != nil {
		t.Skipf("platform source not beside this module (%v)", rerr)
	}
	if !strings.Contains(string(data), `GRPCAccountLimitMessage = "`+accountLimitRefusalMessage+`"`) {
		t.Fatalf("the platform's entitlement.GRPCAccountLimitMessage no longer equals %q", accountLimitRefusalMessage)
	}
}
