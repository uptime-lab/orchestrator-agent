//go:build linux

package handlers

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	ports "agent/pkg/application/ports/out"
	"agent/pkg/domain/node"
	proto "agent/pkg/infrastructure/grpc/proto"
)

// silentPlatformClient satisfies the reporting the handler does on its way
// through. Nothing is asserted on it: what this file is about happens on the
// filesystem.
type silentPlatformClient struct{ ports.PlatformClient }

func (silentPlatformClient) Connect(context.Context, string, node.ConnectionRequest) error {
	return nil
}
func (silentPlatformClient) SendStatusUpdate(_, _, _, _, _ string) error { return nil }
func (silentPlatformClient) SendCommandStatus(_, _, _, _, _ string, _ int32, _ string) error {
	return nil
}
func (silentPlatformClient) SendCommandStatusWithResult(_, _, _, _, _ string, _ int32, _ string, _ map[string]string) error {
	return nil
}
func (silentPlatformClient) SendSystemInfo(_, _, _ string, _ *proto.SystemInfoUpdate) error {
	return nil
}
func (silentPlatformClient) SendMetrics(_, _, _ string, _ *proto.MetricsUpdate) error { return nil }

func downloadTestHandler() *CommandHandler {
	return NewCommandHandler(slog.New(slog.NewTextHandler(io.Discard, nil)),
		silentPlatformClient{}, "node", "account", "token")
}

// The download is staged in the DESTINATION's parent so the final rename is
// atomic — and that parent is routinely a directory an unprivileged local user
// owns, which is a user this product manufactures (a non-sudo access entry is
// exactly one). Applying the final mode with os.Chmod(tmpPath, …) — chmod(2),
// which follows symlinks — let that user unlink the root-owned temp and plant a
// symlink at the same name, so the agent chmodded the LINK TARGET as root.
//
// The race is generous rather than tight (the whole download, minutes for a
// large artifact), so it is made deterministic here: the server holds the body
// open until the swap has happened.
func TestDownloadDoesNotChmodThroughASwappedSymlink(t *testing.T) {
	dir := t.TempDir()
	destPath := filepath.Join(dir, "bundle.bin")

	// The file an attacker would aim at. 0600 stands in for /etc/shadow.
	victim := filepath.Join(t.TempDir(), "victim")
	if err := os.WriteFile(victim, []byte("root secret"), 0o600); err != nil {
		t.Fatalf("seeding the victim: %v", err)
	}

	swapped := make(chan struct{})
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", "11")
		_, _ = w.Write([]byte("hel"))
		w.(http.Flusher).Flush()
		<-release // the swap happens while the body is still open
		_, _ = w.Write([]byte("lo world"))
	}))
	defer srv.Close()

	// Stand in for the local user: find the staging temp and replace it with a
	// symlink to the victim.
	go func() {
		defer close(swapped)
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			entries, _ := os.ReadDir(dir)
			for _, e := range entries {
				if !strings.HasPrefix(e.Name(), ".orchestrator-") {
					continue
				}
				tmp := filepath.Join(dir, e.Name())
				if err := os.Remove(tmp); err != nil {
					continue
				}
				_ = os.Symlink(victim, tmp)
				return
			}
			time.Sleep(5 * time.Millisecond)
		}
	}()

	go func() {
		<-swapped
		close(release)
	}()

	h := downloadTestHandler()
	_ = h.handleDownloadFile("cmd-1", &proto.DownloadFileCommand{
		Url:      srv.URL,
		DestPath: destPath,
		Mode:     "666",
	})

	info, err := os.Lstat(victim)
	if err != nil {
		t.Fatalf("stat victim: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("the victim's mode became %o — the agent chmodded through a symlink as root", info.Mode().Perm())
	}
	if body, err := os.ReadFile(victim); err == nil && string(body) != "root secret" {
		t.Error("the victim's contents were replaced")
	}
}

// The ordinary case still works: the file lands at its destination with the
// mode the block asked for, applied before it is ever visible there.
func TestDownloadAppliesTheRequestedMode(t *testing.T) {
	dir := t.TempDir()
	destPath := filepath.Join(dir, "artifact.bin")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("payload"))
	}))
	defer srv.Close()

	h := downloadTestHandler()
	if err := h.handleDownloadFile("cmd-2", &proto.DownloadFileCommand{
		Url: srv.URL, DestPath: destPath, Mode: "640",
	}); err != nil {
		t.Fatalf("download: %v", err)
	}

	info, err := os.Stat(destPath)
	if err != nil {
		t.Fatalf("stat destination: %v", err)
	}
	if info.Mode().Perm() != 0o640 {
		t.Errorf("mode = %o, want 640", info.Mode().Perm())
	}
	body, _ := os.ReadFile(destPath)
	if string(body) != "payload" {
		t.Errorf("content = %q", string(body))
	}
}

// With no mode set the default is 0644 — the case the swap test drives, and the
// ordinary one for "deliver an artifact".
func TestDownloadDefaultsToSixFourFour(t *testing.T) {
	dir := t.TempDir()
	destPath := filepath.Join(dir, "artifact.bin")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("payload"))
	}))
	defer srv.Close()

	h := downloadTestHandler()
	if err := h.handleDownloadFile("cmd-3", &proto.DownloadFileCommand{
		Url: srv.URL, DestPath: destPath,
	}); err != nil {
		t.Fatalf("download: %v", err)
	}
	info, err := os.Stat(destPath)
	if err != nil {
		t.Fatalf("stat destination: %v", err)
	}
	if info.Mode().Perm() != 0o644 {
		t.Errorf("mode = %o, want 644", info.Mode().Perm())
	}
}
