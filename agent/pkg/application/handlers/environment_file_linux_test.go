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

// The write path must land the file at 0600: /etc/environment carries account
// secrets, and pam_env reads it privileged, so tightening from the historical
// 0644 costs logins nothing.
func TestWriteEnvironmentOnRootModeAndPrune(t *testing.T) {
	root := t.TempDir()
	envPath := filepath.Join(root, "etc", "environment")
	if err := os.MkdirAll(filepath.Dir(envPath), 0o755); err != nil {
		t.Fatal(err)
	}
	// A pre-marker file as an older agent left it: 0644, secrets in the body.
	if err := os.WriteFile(envPath, []byte("PATH=/usr/bin\nOLD_TOKEN=stale\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	h := &CommandHandler{logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	if err := h.writeEnvironmentOnRoot(root, map[string]string{"OLD_TOKEN": "fresh", "NEW_TOKEN": "v"}); err != nil {
		t.Fatalf("writeEnvironmentOnRoot: %v", err)
	}

	fi, err := os.Stat(envPath)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %o, want 0600", fi.Mode().Perm())
	}
	content, err := os.ReadFile(envPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(content), "OLD_TOKEN=fresh") || !strings.Contains(string(content), "NEW_TOKEN=v") {
		t.Fatalf("managed keys missing:\n%s", content)
	}

	// Detach one secret: the next apply's effective set no longer carries it.
	if err := h.writeEnvironmentOnRoot(root, map[string]string{"NEW_TOKEN": "v"}); err != nil {
		t.Fatalf("writeEnvironmentOnRoot (prune): %v", err)
	}
	content, err = os.ReadFile(envPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(content), "OLD_TOKEN") {
		t.Fatalf("detached secret survived on disk:\n%s", content)
	}
	if !strings.Contains(string(content), "PATH=/usr/bin") {
		t.Fatalf("operator line lost:\n%s", content)
	}

	// Detach the last secret: block gone, operator content intact.
	if err := h.writeEnvironmentOnRoot(root, nil); err != nil {
		t.Fatalf("writeEnvironmentOnRoot (empty): %v", err)
	}
	content, err = os.ReadFile(envPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(content), "orchestrator:environment") || strings.Contains(string(content), "NEW_TOKEN") {
		t.Fatalf("managed block survived an empty set:\n%s", content)
	}
	if !strings.Contains(string(content), "PATH=/usr/bin") {
		t.Fatalf("operator line lost on final prune:\n%s", content)
	}
}

// An empty set against a host whose /etc/environment we never touched must not
// rewrite (or re-mode) the stock file, and a missing file must not appear.
func TestWriteEnvironmentOnRootEmptySetLeavesStockFileAlone(t *testing.T) {
	root := t.TempDir()
	envPath := filepath.Join(root, "etc", "environment")
	if err := os.MkdirAll(filepath.Dir(envPath), 0o755); err != nil {
		t.Fatal(err)
	}

	h := &CommandHandler{logger: slog.New(slog.NewTextHandler(io.Discard, nil))}

	// Missing file + empty set: nothing is created.
	if err := h.writeEnvironmentOnRoot(root, nil); err != nil {
		t.Fatalf("writeEnvironmentOnRoot: %v", err)
	}
	if _, err := os.Stat(envPath); !os.IsNotExist(err) {
		t.Fatalf("expected no file, got stat err=%v", err)
	}

	// Stock file + empty set: content and mode untouched.
	if err := os.WriteFile(envPath, []byte("PATH=/usr/bin\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := h.writeEnvironmentOnRoot(root, map[string]string{}); err != nil {
		t.Fatalf("writeEnvironmentOnRoot: %v", err)
	}
	fi, err := os.Stat(envPath)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o644 {
		t.Fatalf("stock file mode changed to %o", fi.Mode().Perm())
	}
	content, err := os.ReadFile(envPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "PATH=/usr/bin\n" {
		t.Fatalf("stock file content changed: %q", content)
	}
}
