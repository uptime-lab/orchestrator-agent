package refusal

import (
	"errors"
	"fmt"
	"testing"
)

func TestWrapKeepsTheTextAndTheChain(t *testing.T) {
	base := errors.New("unit name is required")
	err := Wrap(base)
	if err.Error() != base.Error() {
		t.Fatalf("text = %q, want %q", err.Error(), base.Error())
	}
	if !errors.Is(err, base) {
		t.Fatal("the wrapped reason is no longer reachable")
	}
	if !Is(fmt.Errorf("context: %w", err)) {
		t.Fatal("a refusal wrapped again is no longer recognised")
	}
	if Is(base) || Is(nil) {
		t.Fatal("an unmarked error reads as a refusal")
	}
	if Wrap(nil) != nil {
		t.Fatal("Wrap(nil) must stay nil")
	}
	if Wrap(err) != err {
		t.Fatal("a refusal is wrapped twice")
	}
}
