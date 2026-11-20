package handlers

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeSysBlock builds the parts of /sys/class/block the holder check reads.
func fakeSysBlock(t *testing.T, disk string, parts []string, holders map[string][]string, dmNames map[string]string) string {
	t.Helper()
	root := t.TempDir()
	mk := func(p ...string) string {
		dir := filepath.Join(append([]string{root}, p...)...)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		return dir
	}
	mk(disk, "holders")
	for _, p := range parts {
		if err := os.WriteFile(filepath.Join(mk(disk, p), "partition"), []byte("1\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		mk(p, "holders")
	}
	for dev, hs := range holders {
		for _, h := range hs {
			mk(dev, "holders", h)
		}
	}
	for dm, name := range dmNames {
		if err := os.WriteFile(filepath.Join(mk(dm, "dm"), "name"), []byte(name+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func writeSwaps(t *testing.T, lines ...string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "swaps")
	body := "Filename\t\t\t\tType\t\tSize\t\tUsed\t\tPriority\n" + strings.Join(lines, "\n") + "\n"
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// A partition reached only through device-mapper, md or swap has no mount
// point of its own, so the mount checks pass it; the holder check must not.
func TestTargetDeviceHoldersNamesDeviceMapperMdAndSwap(t *testing.T) {
	sys := fakeSysBlock(t, "nvme0n1",
		[]string{"nvme0n1p1", "nvme0n1p2", "nvme0n1p3", "nvme0n1p4"},
		map[string][]string{"nvme0n1p2": {"dm-0"}, "nvme0n1p4": {"md0"}},
		map[string]string{"dm-0": "cryptroot"})
	swaps := writeSwaps(t, "/dev/nvme0n1p3                          partition\t1048572\t\t0\t\t-2")

	held := targetDeviceHolders(sys, swaps, "/dev/nvme0n1")
	joined := strings.Join(held, "\n")
	for _, want := range []string{
		"/dev/nvme0n1p2 is held by dm-0 (cryptroot)",
		"/dev/nvme0n1p4 is held by md0",
		"/dev/nvme0n1p3 is active swap",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing %q in %q", want, held)
		}
	}
	if len(held) != 3 {
		t.Errorf("held = %q, want exactly three entries", held)
	}
}

// A free disk, and swap on ANOTHER disk whose name shares a prefix, are not
// reported.
func TestTargetDeviceHoldersFreeDisk(t *testing.T) {
	sys := fakeSysBlock(t, "sda", []string{"sda1", "sda2"}, nil, nil)
	swaps := writeSwaps(t, "/dev/sdab1 partition 1024 0 -2", "/swapfile file 1024 0 -3")
	if held := targetDeviceHolders(sys, swaps, "/dev/sda"); len(held) != 0 {
		t.Fatalf("free disk reported as held: %q", held)
	}
	// Unreadable sources are not a refusal on their own.
	if held := targetDeviceHolders(filepath.Join(sys, "absent"), filepath.Join(sys, "absent"), "/dev/sda"); len(held) != 0 {
		t.Fatalf("missing sysfs reported as held: %q", held)
	}
}

// A busy refusal after a lazy detach names the mount and the likely holder,
// and is still a refusal of the same kind; any other refusal is untouched.
func TestExplainBusyAfterLazyUnmount(t *testing.T) {
	busy := fmt.Errorf("device /dev/mmcblk0 cannot be used for OS installation: %w", errTargetDeviceBusy)

	got := explainBusyAfterLazyUnmount(busy, []string{"/mnt/sdcard"})
	if !errors.Is(got, errTargetDeviceBusy) {
		t.Fatalf("the explained error lost its kind: %v", got)
	}
	for _, want := range []string{"/mnt/sdcard", "detached lazily", "working directory"} {
		if !strings.Contains(got.Error(), want) {
			t.Errorf("message %q does not name %q", got, want)
		}
	}

	if got := explainBusyAfterLazyUnmount(busy, nil); got != busy {
		t.Errorf("no lazy detach: error changed to %v", got)
	}
	other := errors.New("device /dev/mmcblk0 is mounted")
	if got := explainBusyAfterLazyUnmount(other, []string{"/mnt/sdcard"}); got != other {
		t.Errorf("a non-busy refusal was changed to %v", got)
	}
}
