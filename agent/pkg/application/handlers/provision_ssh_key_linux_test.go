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

// provision_connection used to install the key into /home/<username> whatever
// the account's real home was. Every chown and chmod that followed targeted the
// directory it had just created, so they all succeeded and the command reported
// success — with the key in a directory sshd never reads.
func TestSSHKeyLandsInThePasswdHome(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	passwd := "relocated:x:1001:1001::/srv/relocated:/bin/bash\n"
	if err := os.WriteFile(filepath.Join(root, "etc", "passwd"), []byte(passwd), 0o644); err != nil {
		t.Fatal(err)
	}

	// provisionSSHKeyOnRoot creates the home only as root: on a device the
	// parent of a home is root-owned and nothing else may create it. An
	// unprivileged test run stands in for an image whose home already exists.
	if os.Geteuid() != 0 {
		if err := os.MkdirAll(filepath.Join(root, "srv", "relocated"), 0o755); err != nil {
			t.Fatal(err)
		}
	}

	h := &CommandHandler{logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	key := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIexamplekeymaterialexamplekeymaterial operator"
	if err := h.provisionSSHKeyOnRoot(root, "relocated", key); err != nil {
		t.Fatalf("provisionSSHKeyOnRoot: %v", err)
	}

	content, err := os.ReadFile(filepath.Join(root, "srv", "relocated", ".ssh", "authorized_keys"))
	if err != nil {
		t.Fatalf("key was not written to the passwd home: %v", err)
	}
	if !strings.Contains(string(content), key) {
		t.Fatalf("authorized_keys does not carry the key: %q", content)
	}
	if _, err := os.Stat(filepath.Join(root, "home", "relocated")); err == nil {
		t.Fatal("the key was also installed into /home/<username>, which sshd never reads")
	}
}

// A user the target rootfs does not know has no home to resolve, and a guessed
// one grants nothing — so the command must fail rather than report success.
func TestUnknownUserFailsTheKeyProvisioning(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "etc", "passwd"), []byte("user:x:1000:1000::/srv/user:/bin/bash\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	h := &CommandHandler{logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	if err := h.provisionSSHKeyOnRoot(root, "ghost", "ssh-ed25519 AAAA operator"); err == nil {
		t.Fatal("expected provisioning to fail for a user that is not in passwd")
	}
}
