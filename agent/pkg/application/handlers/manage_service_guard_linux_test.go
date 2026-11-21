//go:build linux

package handlers

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	proto "agent/pkg/infrastructure/grpc/proto"
)

// manage_service could write and control the agent's own unit.
//
// unitNameRe permits "orchestrator-agent.service", and every other file-writing
// handler routes through resolveForFileOp, whose protectedFiles names that exact
// unit. This handler bypassed it and the dispatch builder only trimmed the name,
// so a playbook could overwrite the packaged unit — root code on the next boot —
// or disable_now it, which takes the node off the platform permanently with no
// way back but a physical visit.
func TestPlatformManagedUnitsAreRefused(t *testing.T) {
	refused := []string{
		"orchestrator-agent.service",
		"orchestrator-watcher.service",
		// A refusal that can be stepped around by capitalising a letter is not a
		// refusal.
		"Orchestrator-Agent.Service",
		"  orchestrator-agent.service  ",
	}
	for _, name := range refused {
		if !platformManagedUnit(name) {
			t.Errorf("manage_service accepts %q, which is the unit that keeps the node reachable", name)
		}
	}
}

// The refusal must not spread to units an operator legitimately manages.
//
// watchdog.service in particular: the platform has its own managed path for it
// (system.apply_watchdog, and the uninstall script's deliberate disarm), and
// taking a node's watchdog down by hand during maintenance is a real thing to
// want.
func TestOrdinaryUnitsAreStillAllowed(t *testing.T) {
	allowed := []string{
		"nginx.service",
		"watchdog.service",
		"my-orchestrator-agent.service",
		"orchestrator-agent-helper.service",
		"tailscaled.service",
	}
	for _, name := range allowed {
		if platformManagedUnit(name) {
			t.Errorf("manage_service refuses %q, which the platform does not own", name)
		}
	}
}

// An unknown action is refused before the unit is written: nothing lands in
// /etc/systemd/system and systemd is not reloaded for a command that was never
// going to run. Without root the old order failed at the write instead, so the
// reported reason pins the order on either kind of runner.
func TestManageServiceUnknownActionWritesNothing(t *testing.T) {
	rec := &recordingPlatformClient{}
	h := NewCommandHandler(slog.New(slog.NewTextHandler(io.Discard, nil)), rec, "node", "account", "token")
	name := fmt.Sprintf("orchestrator-test-%d.service", os.Getpid())
	unitPath := filepath.Join("/etc/systemd/system", name)
	t.Cleanup(func() { _ = os.Remove(unitPath) })

	err := h.handleManageService("cmd", &proto.ManageServiceCommand{
		Name:        name,
		Action:      "create",
		UnitContent: "[Service]\nExecStart=/bin/true\n",
	})
	if err == nil {
		t.Fatal("expected the unknown action to be refused")
	}
	if _, statErr := os.Lstat(unitPath); !os.IsNotExist(statErr) {
		t.Fatalf("an unknown action left %s on disk (stat err=%v)", unitPath, statErr)
	}
	rec.mu.Lock()
	reported := strings.Join(rec.details, "\n")
	rec.mu.Unlock()
	if !strings.Contains(reported, "unknown action: create") || strings.Contains(reported, "failed to write unit") {
		t.Fatalf("reported %q; want the action refusal before any write", reported)
	}
}
