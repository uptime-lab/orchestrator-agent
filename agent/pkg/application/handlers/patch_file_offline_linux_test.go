//go:build linux

package handlers

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The target filesystem is the one this command exists to repair, so it is
// exactly the filesystem that may be strange. A symlink inside it that escapes
// the mount would have the root agent write into the RUNNING initramfs.
func TestResolveOfflinePathRefusesToLeaveTheMount(t *testing.T) {
	h := &CommandHandler{}
	mount := t.TempDir()
	outside := t.TempDir()

	// /etc inside the target is a symlink pointing out of the mount.
	if err := os.Symlink(outside, filepath.Join(mount, "etc")); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	_, err := h.resolveOfflinePath(mount, "/etc/hosts", false)
	if err == nil {
		t.Fatal("resolveOfflinePath followed a symlink out of the mounted target")
	}
	if !strings.Contains(err.Error(), "outside") {
		t.Errorf("error = %q, want it to say the path leaves the target", err)
	}
}

// A symlinked directory WITHIN the target is ordinary (/var/run, a merged
// /usr), and must resolve rather than be refused.
func TestResolveOfflinePathFollowsSymlinksInsideTheTarget(t *testing.T) {
	h := &CommandHandler{}
	mount := t.TempDir()
	real := filepath.Join(mount, "real")
	if err := os.MkdirAll(real, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, filepath.Join(mount, "etc")); err != nil {
		t.Fatal(err)
	}

	got, err := h.resolveOfflinePath(mount, "/etc/hosts", false)
	if err != nil {
		t.Fatalf("resolveOfflinePath() = %v, want the inside-the-target link followed", err)
	}
	if want := filepath.Join(real, "hosts"); got != want {
		t.Errorf("path = %q, want %q", got, want)
	}
}

// A /boot/firmware path is relative to the BOOT PARTITION's own root: the
// prefix is the installed system's mount point, not a directory on the
// partition. Getting this backwards writes config.txt into a directory the
// firmware never reads.
func TestResolveOfflinePathStripsTheBootMountPrefix(t *testing.T) {
	h := &CommandHandler{}
	mount := t.TempDir()

	got, err := h.resolveOfflinePath(mount, "/boot/firmware/config.txt", true)
	if err != nil {
		t.Fatalf("resolveOfflinePath() = %v", err)
	}
	if want := filepath.Join(mount, "config.txt"); got != want {
		t.Errorf("path = %q, want %q — the /boot/firmware prefix is the mount point, not a directory on the partition", got, want)
	}
}

// A path whose directory does not exist on the target is reported as such,
// rather than created: this command edits an installed system, and inventing
// directories in it is not editing.
func TestResolveOfflinePathReportsAMissingDirectory(t *testing.T) {
	h := &CommandHandler{}
	mount := t.TempDir()

	if _, err := h.resolveOfflinePath(mount, "/etc/nope/deeper/file.conf", false); err == nil {
		t.Fatal("resolveOfflinePath() = nil, want a missing-directory error")
	}
}
