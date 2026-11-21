//go:build linux

package handlers

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// The provision path (the running system and an installed rootfs mounted from
// recovery alike) writes env secrets to the root-only file and takes the copies
// an older agent left out of /etc/environment, keeping an operator's line.
func TestWriteEnvironmentOnRootDeliversRootOnly(t *testing.T) {
	root := t.TempDir()
	envPath := filepath.Join(root, "etc", "environment")
	if err := os.MkdirAll(filepath.Dir(envPath), 0o755); err != nil {
		t.Fatal(err)
	}
	legacy := "PATH=/usr/bin\n" + envBegin + "\nOLD_TOKEN=stale\n" + envEnd + "\n"
	if err := os.WriteFile(envPath, []byte(legacy), 0o600); err != nil {
		t.Fatal(err)
	}

	h := &CommandHandler{logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	if _, err := h.writeEnvironmentOnRoot(root, map[string]string{"NEW_TOKEN": "v"}); err != nil {
		t.Fatalf("writeEnvironmentOnRoot: %v", err)
	}

	secretsPath := filepath.Join(root, "etc", "orchestrator", "env")
	fi, err := os.Stat(secretsPath)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %o, want 0600", fi.Mode().Perm())
	}
	if got := readFile(t, secretsPath); !strings.Contains(got, `NEW_TOKEN="v"`) {
		t.Fatalf("secret missing:\n%s", got)
	}
	if got := readFile(t, envPath); got != "PATH=/usr/bin\n" {
		t.Fatalf("/etc/environment after apply: %q", got)
	}
	if os.Geteuid() == 0 {
		if st, ok := fi.Sys().(*syscall.Stat_t); ok && (st.Uid != 0 || st.Gid != 0) {
			t.Fatalf("owner = %d:%d, want 0:0", st.Uid, st.Gid)
		}
	}

	if _, err := h.writeEnvironmentOnRoot(root, nil); err != nil {
		t.Fatalf("writeEnvironmentOnRoot (empty): %v", err)
	}
	if _, err := os.Stat(secretsPath); !os.IsNotExist(err) {
		t.Fatalf("empty set must remove the file, stat err=%v", err)
	}
}
