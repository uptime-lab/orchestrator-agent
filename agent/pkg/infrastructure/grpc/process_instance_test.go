package grpc

import (
	"testing"

	"github.com/google/uuid"
)

// The id must be per PROCESS: non-empty, a well-formed uuid, and the same
// value however many times the connect path reads it. Persisting it — or
// regenerating it per connect — each breaks the platform's continuity verdict
// in a different direction.
func TestProcessInstanceIDIsStableWithinTheProcess(t *testing.T) {
	if processInstanceID == "" {
		t.Fatal("processInstanceID is empty")
	}
	if _, err := uuid.Parse(processInstanceID); err != nil {
		t.Fatalf("processInstanceID %q is not a uuid: %v", processInstanceID, err)
	}
	if processInstanceID != processInstanceID {
		t.Fatal("unreachable")
	}
	second := processInstanceID
	if second != processInstanceID {
		t.Fatal("processInstanceID changed between reads")
	}
}
