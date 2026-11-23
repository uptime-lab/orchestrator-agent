package main

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"agent/pkg/application/config"
	"agent/pkg/domain/node"
	"agent/pkg/infrastructure/hardware"

	"github.com/google/uuid"
)

// Exit codes of `orchestrator-agent --status`. 78 matches the
// interactive-start "not provisioned" code, so a script gets one number for
// "this machine holds no node identity" from either entry point.
const (
	statusExitRunning        = 0
	statusExitNotRunning     = 1
	statusExitNotProvisioned = exitCodeNotProvisioned
)

// statusReport is everything --status prints, gathered first and rendered
// second so the wording and the exit-code rule are testable without a live
// system behind them.
type statusReport struct {
	Version string

	// Identity: where this node's identity was looked for and what was found.
	AdoptionFile  string
	IdentityState string // "file" | "eeprom" | "unreadable" | "absent"
	IdentityNote  string // one extra line, e.g. why the EEPROM was not consulted

	// Non-secret identity fields, set only when the identity was readable.
	NodeID       string
	AccountID    string
	PlatformURL  string
	GRPCEndpoint string
	MasterToken  bool // master-token mode (pre-adoption); the value itself is never shown

	// Liveness: what is actually running here.
	ServiceState string // systemctl is-active output, or "" when systemd is unavailable
	AgentPID     int    // another orchestrator-agent process, 0 if none found
}

func (r *statusReport) identityPresent() bool {
	return r.IdentityState == "file" || r.IdentityState == "eeprom" || r.IdentityState == "unreadable"
}

func (r *statusReport) agentRunning() bool {
	return r.ServiceState == "active" || r.AgentPID != 0
}

// exitCode is the monitoring contract: 0 = identity present and the agent is
// running; 1 = identity present but nothing is running it; 78 = this machine
// holds no node identity at all.
func (r *statusReport) exitCode() int {
	if !r.identityPresent() {
		return statusExitNotProvisioned
	}
	if r.agentRunning() {
		return statusExitRunning
	}
	return statusExitNotRunning
}

func (r *statusReport) render(w io.Writer) {
	fmt.Fprintf(w, "orchestrator-agent %s\n\n", r.Version)

	switch r.IdentityState {
	case "file":
		fmt.Fprintf(w, "Identity: adoption file %s\n", r.AdoptionFile)
	case "eeprom":
		fmt.Fprintf(w, "Identity: EEPROM (no adoption file at %s)\n", r.AdoptionFile)
	case "unreadable":
		fmt.Fprintf(w, "Identity: present at %s, not readable by this user. Run with sudo for the details.\n", r.AdoptionFile)
	default:
		fmt.Fprintf(w, "Identity: none found at %s\n", r.AdoptionFile)
	}
	if r.IdentityNote != "" {
		fmt.Fprintf(w, "  %s\n", r.IdentityNote)
	}
	if r.MasterToken {
		fmt.Fprintf(w, "  Mode: master token (this device has not completed its first adoption yet)\n")
	}
	if r.NodeID != "" {
		fmt.Fprintf(w, "  Node ID:    %s\n", r.NodeID)
	}
	if r.AccountID != "" {
		fmt.Fprintf(w, "  Account ID: %s\n", r.AccountID)
	}
	if r.PlatformURL != "" {
		fmt.Fprintf(w, "  Platform:   %s\n", r.PlatformURL)
	}
	if r.GRPCEndpoint != "" {
		fmt.Fprintf(w, "  Endpoint:   %s\n", r.GRPCEndpoint)
	}

	fmt.Fprintln(w)
	switch {
	case r.ServiceState != "":
		fmt.Fprintf(w, "Service: orchestrator-agent.service is %s\n", r.ServiceState)
	default:
		fmt.Fprintf(w, "Service: systemd is not available here\n")
	}
	if r.AgentPID != 0 {
		fmt.Fprintf(w, "Process: orchestrator-agent is running (pid %d)\n", r.AgentPID)
	} else if r.ServiceState != "active" {
		fmt.Fprintf(w, "Process: no running orchestrator-agent found\n")
	}

	fmt.Fprintln(w)
	switch r.exitCode() {
	case statusExitRunning:
		fmt.Fprintln(w, "Status: OK — this node is provisioned and the agent is running.")
	case statusExitNotProvisioned:
		fmt.Fprintln(w, "Status: this machine holds no node identity. To adopt it, use the install command from the platform UI (Nodes -> Add node).")
	default:
		fmt.Fprintln(w, "Status: provisioned, but the agent is not running. Try: sudo systemctl start orchestrator-agent")
	}
}

// runStatus gathers and prints the local diagnostic for `--status`. Read-only
// on purpose: it talks to no platform, needs no credentials, and degrades
// per probe when run unprivileged instead of failing whole.
func runStatus(adoptionFile string) int {
	r := &statusReport{Version: version, AdoptionFile: adoptionFile}

	// A silent parser: --status output should be the report, not log lines.
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	parser := config.NewParserWithLogger(quiet)

	if _, err := os.Stat(adoptionFile); err == nil {
		if cfg, perr := parser.ParseAdoptionFile(adoptionFile, nil); perr == nil {
			r.IdentityState = "file"
			fillIdentity(r, cfg)
		} else if errors.Is(perr, os.ErrPermission) {
			r.IdentityState = "unreadable"
		} else {
			r.IdentityState = "file"
			r.IdentityNote = fmt.Sprintf("The file exists but could not be parsed: %v", perr)
		}
	} else if errors.Is(err, os.ErrPermission) {
		r.IdentityState = "unreadable"
	} else {
		// No file. The EEPROM fallback needs root (vcgencmd); only say it was
		// not consulted rather than error on the common unprivileged run.
		if os.Geteuid() == 0 {
			eeprom := hardware.NewEEPROMAdoptionStorage(quiet)
			if cfg, perr := parser.ParseAdoptionFile(adoptionFile, eeprom); perr == nil {
				r.IdentityState = "eeprom"
				fillIdentity(r, cfg)
			} else {
				r.IdentityState = "absent"
			}
		} else {
			r.IdentityState = "absent"
			r.IdentityNote = "The EEPROM fallback was not checked; that needs root."
		}
	}

	r.ServiceState = systemdUnitState("orchestrator-agent.service")
	r.AgentPID = findRunningAgentPID(os.Getpid())

	r.render(os.Stdout)
	return r.exitCode()
}

// fillIdentity copies the NON-SECRET identity fields into the report. The
// tokens (unique or master) must never appear in --status output: the whole
// point of the flag is being safe to run and paste into a support thread.
func fillIdentity(r *statusReport, cfg *node.AdoptionConfig) {
	r.MasterToken = cfg.IsMasterTokenMode()
	if cfg.NodeID != uuid.Nil {
		r.NodeID = cfg.NodeID.String()
	}
	if cfg.AccountID != uuid.Nil {
		r.AccountID = cfg.AccountID.String()
	}
	r.PlatformURL = cfg.PlatformURL
	r.GRPCEndpoint = cfg.GRPCEndpoint
}

// systemdUnitState answers `systemctl is-active <unit>` ("active",
// "inactive", "failed", …) or "" when systemd itself is unavailable.
func systemdUnitState(unit string) string {
	out, err := exec.Command("systemctl", "is-active", unit).Output()
	state := strings.TrimSpace(string(out))
	if state == "" && err != nil {
		return ""
	}
	return state
}

// findRunningAgentPID scans /proc for another orchestrator-agent process.
// comm is truncated to 15 bytes by the kernel, hence the prefix match. Returns
// 0 when none is found (including on systems with no /proc).
func findRunningAgentPID(selfPID int) int {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return 0
	}
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid == selfPID {
			continue
		}
		comm, err := os.ReadFile("/proc/" + e.Name() + "/comm")
		if err != nil {
			continue
		}
		if strings.HasPrefix(strings.TrimSpace(string(comm)), "orchestrator-ag") {
			return pid
		}
	}
	return 0
}
