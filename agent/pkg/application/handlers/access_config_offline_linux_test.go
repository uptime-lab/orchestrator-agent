//go:build linux

package handlers

import (
	"io"
	"log/slog"
	"strings"
	"testing"

	proto "agent/pkg/infrastructure/grpc/proto"
)

func offlineTestHandler() *CommandHandler {
	return NewCommandHandler(slog.New(slog.NewTextHandler(io.Discard, nil)),
		silentPlatformClient{}, "node", "account", "token")
}

// An empty payload must fail cleanly, before any environment checks.
func TestOfflineAccessApplyRefusesNilConfig(t *testing.T) {
	h := offlineTestHandler()
	err := h.handleApplyAccessConfigOffline("cmd-1", &proto.ApplyAccessConfigOfflineCommand{})
	if err == nil {
		t.Fatal("expected refusal for a payload with no access config")
	}
	if !strings.Contains(err.Error(), "no access config") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// The offline apply is recovery-only: on an installed OS (which is what a CI
// runner is — a persistent, non-RAM root) it must refuse and point at the live
// apply instead. This is the inverse of capture_image's gate and the guard
// that keeps "mount another disk and chroot into it" away from live systems.
func TestOfflineAccessApplyRefusesOutsideRecovery(t *testing.T) {
	h := offlineTestHandler()
	err := h.handleApplyAccessConfigOffline("cmd-2", &proto.ApplyAccessConfigOfflineCommand{
		Config:       &proto.ApplyAccessConfigCommand{ConfigHash: "abc"},
		TargetDevice: "/dev/null",
	})
	if err == nil {
		t.Fatal("expected refusal outside the recovery bootstrap")
	}
	if !strings.Contains(err.Error(), "recovery bootstrap") {
		t.Fatalf("unexpected error: %v", err)
	}
}
