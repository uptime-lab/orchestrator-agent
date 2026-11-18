package handlers

import (
	"os"
	"path/filepath"
	"testing"
)

func writePasswd(t *testing.T, lines string) string {
	t.Helper()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "etc", "passwd"), []byte(lines), 0o644); err != nil {
		t.Fatal(err)
	}
	return root
}

// The home directory is what decides where sshd reads authorized_keys. Guessing
// /home/<username> writes the key into a directory nobody reads and every step
// after it still succeeds, so the command reports a green success with no access.
func TestPasswdHomeIsUsedInsteadOfHomeUsername(t *testing.T) {
	root := writePasswd(t, "root:x:0:0:root:/root:/bin/bash\nrelocated:x:1001:1001::/srv/relocated:/bin/bash\n")

	for _, tc := range []struct {
		username string
		want     string
	}{
		{"root", "/root"},
		{"relocated", "/srv/relocated"},
	} {
		entry, err := lookupPasswdEntry(root, tc.username)
		if err != nil {
			t.Fatalf("lookup %s: %v", tc.username, err)
		}
		home, err := resolveProvisionHome(tc.username, entry.Home)
		if err != nil {
			t.Fatalf("resolve %s: %v", tc.username, err)
		}
		if home != tc.want {
			t.Fatalf("home for %s = %q, want %q", tc.username, home, tc.want)
		}
	}
}

func TestUnknownUserFailsInsteadOfGuessingAHome(t *testing.T) {
	root := writePasswd(t, "user:x:1000:1000::/srv/user:/bin/bash\n")
	if _, err := lookupPasswdEntry(root, "missing"); err == nil {
		t.Fatal("expected an error for a user that is not in passwd")
	}
}

func TestUnreadablePasswdFails(t *testing.T) {
	if _, err := lookupPasswdEntry(t.TempDir(), "ubuntu"); err == nil {
		t.Fatal("expected an error when /etc/passwd cannot be read")
	}
}

func TestHomelessAccountsAreRefused(t *testing.T) {
	for _, home := range []string{"/", "/nonexistent", "relative/path"} {
		if _, err := resolveProvisionHome("svc", home); err == nil {
			t.Fatalf("expected home %q to be refused", home)
		}
	}
}

// An empty field says nothing about the account, so the useradd default is a
// better answer than failing a setup that works today.
func TestEmptyPasswdHomeFallsBackToHomeUsername(t *testing.T) {
	home, err := resolveProvisionHome("user", "")
	if err != nil {
		t.Fatal(err)
	}
	if home != "/home/user" {
		t.Fatalf("home = %q, want /home/user", home)
	}
}

func TestProvisionConnectionRefusesRoot(t *testing.T) {
	if err := validateProvisionConnectionUsername("root"); err == nil {
		t.Fatal("provision_connection must refuse root")
	}
	if err := validateProvisionConnectionUsername("ubuntu"); err != nil {
		t.Fatalf("ubuntu must stay valid: %v", err)
	}
	// The shared validator keeps its own contract: the access-config path skips
	// root rather than failing a whole config over one name.
	if err := validateProvisionUsername("root"); err != nil {
		t.Fatalf("validateProvisionUsername must still accept root: %v", err)
	}
}
