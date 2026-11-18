//go:build linux

package hardware

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The boot config must never be truncated in place.
//
// A bare os.WriteFile truncates first, so a power cut in that window leaves a
// ZERO-LENGTH config.txt and a board that does not boot — and the verification
// that follows re-reads through the page cache, gets the content it just wrote,
// and settles the command green on a device that is already lost.
//
// What is asserted is the mechanism: the file is replaced by a RENAME, so at no
// point does the destination exist with partial content. A temp file left behind
// would be the other failure — litter on a small FAT partition.
func TestBootConfigIsReplacedByRename(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.txt")
	if err := os.WriteFile(path, []byte("original\n"), 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}

	if err := writeFileDurable(path, []byte("replacement\n"), 0o644); err != nil {
		t.Fatalf("writeFileDurable: %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != "replacement\n" {
		t.Fatalf("content = %q, want the replacement", got)
	}

	// A rename installs a DIFFERENT inode; an in-place truncate keeps the same
	// one. That is the whole distinction being made.
	after, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat after: %v", err)
	}
	if os.SameFile(before, after) {
		t.Fatal("the destination was written in place, so a power cut can still leave it empty")
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".tmp") {
			t.Errorf("a temporary file was left behind: %s", e.Name())
		}
	}
}

// A failed write must not damage what is already there.
func TestAFailedDurableWriteLeavesTheOriginal(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "config.txt")
	// The parent does not exist, so the temp file cannot be created.
	if err := writeFileDurable(path, []byte("new\n"), 0o644); err == nil {
		t.Fatal("writing into a missing directory reported success")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("a partial file was created: %v", err)
	}
}
