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

// provision_connection must not rewrite the access policy's own settings.
//
// On an image with no Include directive the access reconciler keeps its
// configuration in a marker block inside the MAIN sshd_config. This function
// rewrote EVERY PasswordAuthentication line in that file, the one inside the
// block included, so an account that had switched password logins off got them
// back — and the next apply_access_config computed the same DESIRED hash, saw it
// unchanged, reported "already current" and never corrected the drift.
func TestProvisioningLeavesTheAccessMarkerBlockAlone(t *testing.T) {
	root := t.TempDir()
	sshDir := filepath.Join(root, "etc", "ssh")
	if err := os.MkdirAll(sshDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	original := strings.Join([]string{
		"# distro defaults",
		"PasswordAuthentication no",
		accessMarkerBegin,
		"PasswordAuthentication no",
		"PubkeyAuthentication yes",
		accessMarkerEnd,
		"",
	}, "\n")
	cfg := filepath.Join(sshDir, "sshd_config")
	if err := os.WriteFile(cfg, []byte(original), 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}

	h := &CommandHandler{logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	if err := h.configureSSHServiceOnRoot(root); err != nil {
		t.Fatalf("configureSSHServiceOnRoot: %v", err)
	}

	got, err := os.ReadFile(cfg)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	lines := strings.Split(string(got), "\n")

	inBlock := false
	sawBlockSetting := false
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, accessMarkerBegin) {
			inBlock = true
			continue
		}
		if strings.HasPrefix(trimmed, accessMarkerEnd) {
			inBlock = false
			continue
		}
		if inBlock && strings.HasPrefix(strings.ToLower(trimmed), "passwordauthentication") {
			sawBlockSetting = true
			if !strings.EqualFold(trimmed, "PasswordAuthentication no") {
				t.Fatalf("the access policy's own setting was rewritten to %q; the next apply cannot detect this because the desired hash did not change", trimmed)
			}
		}
	}
	if !sawBlockSetting {
		t.Fatal("the access marker block lost its PasswordAuthentication line entirely")
	}

	// And the setting OUTSIDE the block is still the one provisioning came to
	// change, or the fix has broken what the command is for.
	if !strings.Contains(string(got), "PasswordAuthentication yes") {
		t.Fatalf("provisioning did not enable password authentication outside the block:\n%s", got)
	}
}
