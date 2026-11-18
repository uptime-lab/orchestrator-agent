//go:build linux

package handlers

import (
	"testing"
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
