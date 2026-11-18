//go:build linux

package handlers

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A fake block device: a regular file the stash functions can seek in exactly as
// they do on a disk.
func fakeDevice(t *testing.T, size int64) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "disk.img")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := f.Truncate(size); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	_ = f.Close()
	return path
}

// The stash must round-trip, and it must land OUTSIDE the capture extent.
//
// The capture is [0, shrunk root end), and the shrink only ever moves that end
// down — so the reserved window past the root partition can never travel inside
// the image the identity was stripped out of.
func TestIdentityStashRoundTrips(t *testing.T) {
	const deviceSize = 64 << 20
	const rootEnd = 16 << 20
	device := fakeDevice(t, deviceSize)

	offset, ok := identityStashOffset(deviceSize, rootEnd)
	if !ok {
		t.Fatal("no reserved window on a disk with 48 MiB free past the root partition")
	}
	if offset <= rootEnd {
		t.Fatalf("the stash at %d sits inside the capture extent (root ends at %d); the identity would travel inside the image", offset, rootEnd)
	}

	payload := []byte(strings.Repeat("identity-tar", 500))
	if err := writeIdentityStash(device, offset, payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, found, err := readIdentityStash(device, offset)
	if err != nil || !found {
		t.Fatalf("read = %v, found=%v, want the payload back", err, found)
	}
	if string(got) != string(payload) {
		t.Fatalf("payload did not round-trip (%d bytes back, %d written)", len(got), len(payload))
	}
}

// A disk whose root partition runs to the end has no reserved window, and the
// caller must fall back rather than write into the captured extent.
func TestNoStashWindowOnAFullDisk(t *testing.T) {
	if _, ok := identityStashOffset(64<<20, 64<<20); ok {
		t.Fatal("a reserved window was reported on a disk with no free space past the root partition")
	}
}

// An untouched disk is "no stash", not a corrupt one — nothing else writes the
// magic, so its absence is unambiguous.
func TestAnUntouchedDiskHasNoStash(t *testing.T) {
	const deviceSize = 64 << 20
	device := fakeDevice(t, deviceSize)
	offset, _ := identityStashOffset(deviceSize, 16<<20)

	_, found, err := readIdentityStash(device, offset)
	if err != nil {
		t.Fatalf("an untouched disk reported an error: %v", err)
	}
	if found {
		t.Fatal("an untouched disk reported a stash")
	}
}

// A half-written stash must be an ERROR, not silence. Restoring a partial
// identity is worse than restoring nothing: it would put back some host keys and
// no adoption file, and the node would look repaired while still being orphaned.
func TestATornStashIsRefusedRatherThanRestored(t *testing.T) {
	const deviceSize = 64 << 20
	device := fakeDevice(t, deviceSize)
	offset, _ := identityStashOffset(deviceSize, 16<<20)

	payload := []byte(strings.Repeat("identity-tar", 500))
	if err := writeIdentityStash(device, offset, payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	// Corrupt the payload, leaving the header's checksum describing the original.
	f, err := os.OpenFile(device, os.O_WRONLY, 0)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, err := f.WriteAt([]byte("xxxx"), offset+identityStashHeaderSize+10); err != nil {
		t.Fatalf("corrupt: %v", err)
	}
	_ = f.Close()

	if _, found, err := readIdentityStash(device, offset); err == nil {
		t.Fatalf("a torn stash was accepted (found=%v); a partial identity is worse than none", found)
	}
}

// Clearing must make the stash unfindable, so a later capture cannot restore an
// identity that is already back in place.
func TestClearingTheStashMakesItUnfindable(t *testing.T) {
	const deviceSize = 64 << 20
	device := fakeDevice(t, deviceSize)
	offset, _ := identityStashOffset(deviceSize, 16<<20)

	if err := writeIdentityStash(device, offset, []byte("identity")); err != nil {
		t.Fatalf("write: %v", err)
	}
	clearIdentityStash(device, offset, slog.New(slog.NewTextHandler(io.Discard, nil)))

	if _, found, err := readIdentityStash(device, offset); err != nil || found {
		t.Fatalf("the stash survived clearing (found=%v, err=%v)", found, err)
	}
}
