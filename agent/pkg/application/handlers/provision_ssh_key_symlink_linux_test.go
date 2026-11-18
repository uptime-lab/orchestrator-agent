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

// The threat this closes: an unprivileged local user replaces their own ~/.ssh
// with a symlink somewhere else, and the root agent's provisioning follows it.
//
// The product manufactures exactly such a user — a non-sudo access entry is one
// — and with target_device empty, which is the default and what the
// provision-access starter sends, rootPath is "/" and this runs against the LIVE
// system. os.MkdirAll stats THROUGH the link, sees a directory and returns nil;
// the ownership step that followed was os.Chown plus os.Chmod on the same
// string, so root chowned the link's destination to that user at mode 0700.
//
// The test asserts the DESTINATION is untouched, not merely that an error came
// back: an implementation that refuses after chowning /etc has still handed the
// machine over.
func TestProvisionSSHKeyRefusesASymlinkedSSHDirectory(t *testing.T) {
	root := t.TempDir()
	home := writeProvisionPasswd(t, root, "ops")

	// The victim directory the link points at, standing in for /etc.
	elsewhere := filepath.Join(root, "elsewhere")
	if err := os.MkdirAll(elsewhere, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	before, err := os.Stat(elsewhere)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}

	if err := os.MkdirAll(home, 0o755); err != nil {
		t.Fatalf("mkdir home: %v", err)
	}
	if err := os.Symlink(elsewhere, filepath.Join(home, ".ssh")); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	h := &CommandHandler{logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	err = h.provisionSSHKeyOnRoot(root, "ops", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5 test")

	if err == nil {
		t.Fatal("provisioning followed a symlinked .ssh and reported success")
	}
	if !strings.Contains(err.Error(), "not a directory") {
		t.Errorf("error = %q, want it to name the refusal", err)
	}
	after, err := os.Stat(elsewhere)
	if err != nil {
		t.Fatalf("stat after: %v", err)
	}
	if after.Mode().Perm() != before.Mode().Perm() {
		t.Errorf("the symlink's destination was chmodded to %v (was %v) — this is the privilege escalation",
			after.Mode().Perm(), before.Mode().Perm())
	}
	if _, err := os.Stat(filepath.Join(elsewhere, "authorized_keys")); err == nil {
		t.Error("a key was written into the symlink's destination")
	}
}

// A symlink at authorized_keys is the same bug one level down: root used to
// write through it with os.WriteFile.
func TestProvisionSSHKeyReplacesASymlinkedAuthorizedKeys(t *testing.T) {
	root := t.TempDir()
	home := writeProvisionPasswd(t, root, "ops")

	victim := filepath.Join(root, "victim")
	if err := os.WriteFile(victim, []byte("original\n"), 0o644); err != nil {
		t.Fatalf("write victim: %v", err)
	}
	sshDir := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		t.Fatalf("mkdir .ssh: %v", err)
	}
	if err := os.Symlink(victim, filepath.Join(sshDir, "authorized_keys")); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	h := &CommandHandler{logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	err := h.provisionSSHKeyOnRoot(root, "ops", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5 test")

	// Either outcome is acceptable for the KEY — what must not happen is the
	// victim file being written through the link.
	content, readErr := os.ReadFile(victim)
	if readErr != nil {
		t.Fatalf("read victim: %v", readErr)
	}
	if string(content) != "original\n" {
		t.Fatalf("root wrote through the symlink: victim now reads %q (provision err: %v)", content, err)
	}
}

// The ordinary path must still work, or the hardening has traded one failure
// for another.
func TestProvisionSSHKeyInstallsAndIsIdempotent(t *testing.T) {
	root := t.TempDir()
	home := writeProvisionPasswd(t, root, "ops")
	if err := os.MkdirAll(home, 0o755); err != nil {
		t.Fatalf("mkdir home: %v", err)
	}

	h := &CommandHandler{logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	key := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5 test"
	for i := 0; i < 2; i++ {
		if err := h.provisionSSHKeyOnRoot(root, "ops", key); err != nil {
			t.Fatalf("provision (pass %d): %v", i+1, err)
		}
	}

	got, err := os.ReadFile(filepath.Join(home, ".ssh", "authorized_keys"))
	if err != nil {
		t.Fatalf("read authorized_keys: %v", err)
	}
	if strings.Count(string(got), key) != 1 {
		t.Errorf("authorized_keys = %q, want the key exactly once", got)
	}
	info, err := os.Stat(filepath.Join(home, ".ssh"))
	if err != nil {
		t.Fatalf("stat .ssh: %v", err)
	}
	if !info.IsDir() {
		t.Error(".ssh is not a directory")
	}
}

// An existing key set must survive: appending is the whole contract, and a
// read that failed open would silently revoke every key already installed.
func TestProvisionSSHKeyKeepsExistingKeys(t *testing.T) {
	root := t.TempDir()
	home := writeProvisionPasswd(t, root, "ops")
	sshDir := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	existing := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5 someone-else\n"
	if err := os.WriteFile(filepath.Join(sshDir, "authorized_keys"), []byte(existing), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}

	h := &CommandHandler{logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	if err := h.provisionSSHKeyOnRoot(root, "ops", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5 new"); err != nil {
		t.Fatalf("provision: %v", err)
	}

	got, err := os.ReadFile(filepath.Join(sshDir, "authorized_keys"))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !strings.Contains(string(got), "someone-else") {
		t.Errorf("authorized_keys = %q, want the pre-existing key kept", got)
	}
	if !strings.Contains(string(got), "new") {
		t.Errorf("authorized_keys = %q, want the new key appended", got)
	}
}

// writeProvisionPasswd seeds a rootfs whose passwd names one user, and returns
// the absolute home directory inside that rootfs.
func writeProvisionPasswd(t *testing.T, root, username string) string {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(root, "etc"), 0o755); err != nil {
		t.Fatalf("mkdir etc: %v", err)
	}
	line := username + ":x:1000:1000::/home/" + username + ":/bin/bash\n"
	if err := os.WriteFile(filepath.Join(root, "etc", "passwd"), []byte(line), 0o644); err != nil {
		t.Fatalf("write passwd: %v", err)
	}
	return filepath.Join(root, "home", username)
}
