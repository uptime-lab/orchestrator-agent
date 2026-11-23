//go:build linux

package handlers

import (
	"os"
	"path/filepath"
	"testing"
)

// read_file had no agent-side path enforcement at all: readFileBounded refuses
// a symlinked FINAL component, but a symlinked PARENT walked straight through,
// so a directory link was enough to read the adoption file — whose unique_token
// is the ability to impersonate the node. The backend's policy was the only
// thing in the way, and the agent must not depend on its caller for that.

func TestResolveForFileRead_RefusesTheAdoptionFileThroughASymlinkedParent(t *testing.T) {
	dir := t.TempDir()
	adoption := filepath.Join(dir, "real", "node-adoption.txt")
	if err := os.MkdirAll(filepath.Dir(adoption), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(adoption, []byte("unique_token"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(filepath.Join(dir, "real"), link); err != nil {
		t.Fatal(err)
	}

	h := &CommandHandler{}
	if _, err := h.resolveForFileRead(filepath.Join(link, "node-adoption.txt"), adoption); err == nil {
		t.Fatal("a symlinked parent must not reach the adoption file")
	}
	if _, err := h.resolveForFileRead(adoption, adoption); err == nil {
		t.Fatal("the adoption file must be refused by name too")
	}
}

func TestResolveForFileRead_RefusesCredentialsAndPseudoFilesystems(t *testing.T) {
	h := &CommandHandler{}
	for _, path := range []string{
		"/etc/shadow",
		"/etc/gshadow-",
		"/etc/ssl/private/server.key",
		"/home/user/id_rsa.pem",
		"/proc/self/mem",
		"/sys/class/net/eth0/address",
		"/dev/watchdog",
		"/run/some.sock",
		// /var/run and /var/lock are the historical names for /run; refusing
		// only the modern spelling refused the same FIFO under one name and
		// accepted it under the other.
		"/var/run/some.sock",
		"/var/lock/thing",
	} {
		if _, err := h.resolveForFileRead(path, ""); err == nil {
			t.Errorf("%s must not be readable", path)
		}
	}
}

func TestResolveForFileRead_AllowsTheFilesTheEditorExistsFor(t *testing.T) {
	// protectedFiles answers "what strands the device if deleted" and includes
	// config.txt, watchdog.conf and passwd — the very files the tracked-file
	// editor shows. Using that list to gate reads would have broken the feature,
	// so the read gate is its own, shorter list.
	h := &CommandHandler{}
	for _, path := range []string{
		"/boot/firmware/config.txt",
		"/etc/watchdog.conf",
		"/etc/passwd",
		"/etc/fstab",
		"/etc/netplan/50-cloud-init.yaml",
	} {
		if _, err := h.resolveForFileRead(path, ""); err != nil {
			t.Errorf("%s must stay readable: %v", path, err)
		}
	}
}

func TestResolveForFileRead_RejectsMalformedPaths(t *testing.T) {
	h := &CommandHandler{}
	for _, path := range []string{"", "relative/path", "/etc/with\x00null"} {
		if _, err := h.resolveForFileRead(path, ""); err == nil {
			t.Errorf("%q must be rejected", path)
		}
	}
}

// Reads refused six kernel/runtime prefixes while writes and
// deletes refused three. The backend grew /var/run and /var/lock; the agent's
// write side never followed, so a platform command could still write into or
// delete from the runtime tree.
//
// The two lists are now one declaration each, checked against each other here:
// a prefix added to reads and forgotten for writes is the exact shape of the bug.
func TestWriteSideRefusesEveryRuntimePrefixTheReadSideDoes(t *testing.T) {
	for _, prefix := range refusedReadPrefixes {
		found := false
		for _, p := range protectedPrefixes {
			if p == prefix {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("%s is refused for reads but permitted for writes and deletes", prefix)
		}
	}
}

func TestResolveForFileOp_RefusesTheRuntimeTree(t *testing.T) {
	h := &CommandHandler{}
	for _, path := range []string{
		"/run/systemd/system/foo.conf",
		"/run/orchestrator.pid",
		"/var/run/sshd.pid",
		"/var/lock/subsys/thing",
	} {
		if _, err := h.resolveForFileOp(path, ""); err == nil {
			t.Errorf("%s must not be writable or deletable by a platform command", path)
		}
	}
}

// The write list is deliberately WIDER than the read list: these two are
// editable-but-protected, so a read may see them and a write may not touch them.
// Guarding this stops a future "make the lists identical" tidy-up from quietly
// making the agent's own sudoers and authorized_keys files writable.
func TestTheWriteListKeepsItsOwnEntries(t *testing.T) {
	h := &CommandHandler{}
	for _, path := range []string{
		"/etc/ssh/authorized_keys.d/deploy",
		"/" + accessSudoersPrefix + "deploy",
	} {
		if _, err := h.resolveForFileOp(path, ""); err == nil {
			t.Errorf("%s must stay refused for writes", path)
		}
	}
}

// read_file's max_bytes is caller-supplied, so a huge
// value would make readFileBounded pull the whole file into memory before the
// size check — the check compares against that very number. DefaultReadMaxBytes
// is the hard ceiling: a request above it is clamped, so a file larger than the
// ceiling is reported truncated and never read into memory, whatever was asked.
func TestReadFileBoundedClampsAnOversizedRequestedMax(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "big.txt")
	// One byte over the ceiling is enough to prove the clamp: with an honored
	// huge max it would be read and returned; clamped, it is truncated.
	if err := os.WriteFile(path, make([]byte, DefaultReadMaxBytes+1), 0o600); err != nil {
		t.Fatalf("seeding file: %v", err)
	}

	content, meta, err := readFileBounded(path, 2<<30) // request 2 GiB
	if err != nil {
		t.Fatalf("readFileBounded: %v", err)
	}
	if meta["truncated"] != "true" {
		t.Fatalf("a file above the ceiling must be truncated even with a huge requested max; meta=%v", meta)
	}
	if content != "" {
		t.Fatal("truncated read must return no content")
	}
}

// A request BELOW the ceiling is still honored as an upper bound.
func TestReadFileBoundedHonorsASmallerRequestedMax(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "small.txt")
	if err := os.WriteFile(path, []byte("hello world"), 0o600); err != nil {
		t.Fatalf("seeding file: %v", err)
	}

	// Under the file size → truncated.
	if _, meta, err := readFileBounded(path, 4); err != nil {
		t.Fatalf("readFileBounded: %v", err)
	} else if meta["truncated"] != "true" {
		t.Fatalf("a max below the file size must truncate; meta=%v", meta)
	}
	// Above the file size (and below the ceiling) → full content.
	if content, meta, err := readFileBounded(path, 1024); err != nil {
		t.Fatalf("readFileBounded: %v", err)
	} else if meta["truncated"] == "true" || content != "hello world" {
		t.Fatalf("a max above the file size must return full content; content=%q meta=%v", content, meta)
	}
}
