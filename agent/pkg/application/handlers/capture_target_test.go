package handlers

import (
	"testing"

	"agent/pkg/domain/refusal"
)

// A capture with no target disk is refused rather than guessed: it runs on
// the recovery system, whose root is RAM, so nothing on the device says which
// disk the installed system boots from, and a guess either fails on a board
// without that disk or, worse, copies a data disk the operator took for the
// boot disk.
func TestCaptureWithoutATargetDiskIsRefused(t *testing.T) {
	for _, raw := range []string{"", "   "} {
		if dev, err := captureTargetDevice(raw); err == nil || !refusal.Is(err) {
			t.Fatalf("captureTargetDevice(%q) = %q, %v; want a refusal", raw, dev, err)
		}
	}
	if dev, err := captureTargetDevice(" /dev/mmcblk0 "); err != nil || dev != "/dev/mmcblk0" {
		t.Fatalf("an explicit disk was not taken as given: %q, %v", dev, err)
	}
}
