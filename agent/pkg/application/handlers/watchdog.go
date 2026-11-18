package handlers

// Watchdog supervision: pure logic shared by the Linux command handler, the
// startup breaker and the watchdog-gate subcommand. Everything here must stay
// free of syscalls and systemd so `make agent/test` exercises it on any OS —
// the side-effecting half lives in watchdog_linux.go (see the
// access_config.go / access_config_linux.go precedent).

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	proto "agent/pkg/infrastructure/grpc/proto"
)

const (
	watchdogConfPath    = "/etc/watchdog.conf"
	watchdogDropInDir   = "/etc/systemd/system/watchdog.service.d"
	watchdogDropIn      = "/etc/systemd/system/watchdog.service.d/10-orchestrator.conf"
	legacySystemdDropIn = "/etc/systemd/system.conf.d/10-orchestrator-watchdog.conf"
	watchdogStateDir    = "/var/lib/orchestrator-agent"
	watchdogStateFile   = "/var/lib/orchestrator-agent/watchdog-armed"
	watchdogStateLock   = "/var/lib/orchestrator-agent/.watchdog-armed.lock"
	agentHeartbeatFile  = "/run/orchestrator-agent/alive"
	watchdogLogDir      = "/var/log/watchdog"

	// agentBinaryFallback is where the .deb installs the agent. The watchdog
	// drop-in's ExecStartPre gate prefers os.Executable() at apply time and
	// falls back to this.
	agentBinaryFallback = "/usr/bin/orchestrator-agent"

	// WatchdogGateSubcommand is the hidden CLI mode systemd runs as
	// ExecStartPre= of watchdog.service. It lives in the agent binary (not a
	// shell script) so the breaker works even when the agent SERVICE cannot —
	// a broken adoption file exits the agent, but the gate needs no adoption.
	// If the binary itself is corrupt, ExecStartPre fails and watchdog.service
	// never starts: no supervision, but no reboot loop either.
	WatchdogGateSubcommand = "watchdog-gate"

	// watchdogBreakerLimit is how many REBOOTS under an armed watchdog it takes
	// to disarm it. Three is "the device rebooted twice and came back a third
	// time", which no healthy node does inside the reset window. Agent or
	// service restarts within one boot do not count (boot_id comparison).
	watchdogBreakerLimit = 3
	// watchdogBreakerResetAfter is how long a boot must survive before it
	// counts as healthy. A watchdog loop reboots far faster than this.
	watchdogBreakerResetAfter = 20 * time.Minute
)

// Refusal codes returned in the command result's "refusal" key. The backend
// stores them verbatim; keep them machine-stable.
const (
	refusalPackageInstallFailed  = "package_install_failed"
	refusalPingUnreachable       = "ping_target_unreachable"
	refusalLoadAboveThreshold    = "load_already_above_threshold"
	refusalMemoryBelowThreshold  = "memory_already_below_threshold"
	refusalTempAboveThreshold    = "temperature_already_above_threshold"
	refusalTempSensorMissing     = "temp_sensor_missing"
	refusalHwWatchdogMissing     = "hw_watchdog_missing"
	refusalDeviceStateUnreadable = "device_state_unreadable"
	refusalBreakerUnwritable     = "breaker_state_unwritable"
)

// watchdogState is the on-disk breaker record. It lives outside /run on
// purpose: a loop is only visible across reboots.
type watchdogState struct {
	ConfigHash   string `json:"config_hash"`
	BootID       string `json:"boot_id,omitempty"`
	BootCount    int    `json:"boot_count"`
	Disarmed     bool   `json:"disarmed"`
	DisarmReason string `json:"disarm_reason,omitempty"`
	// DisarmSource says WHO disarmed: the local breaker, or the platform asking
	// for it. Both used to write the same Disarmed flag, so an operator pressing
	// "disarm" produced a state indistinguishable from a runaway-reboot trip —
	// the platform then reported the device's own safety breaker as having
	// fired, on every probe and on every agent start, for a routine action. That
	// is the one signal this feature exists to raise, so it must not be spent on
	// the platform's own command.
	//
	// Empty means a state file written before this field existed. It is read as
	// the breaker (the conservative reading: an unexplained disarm deserves
	// attention), which also keeps every already-fielded device behaving as it
	// does today.
	DisarmSource string `json:"disarm_source,omitempty"`
}

// Disarm sources. Machine-stable: the backend compares against these strings.
const (
	// DisarmSourceBreaker — the agent's own breaker tripped after repeated
	// reboots under an armed watchdog. This is a fault report.
	DisarmSourceBreaker = "breaker"
	// DisarmSourcePlatform — the platform asked for the watchdog to be
	// disabled. This is not a fault and must never be reported as one.
	DisarmSourcePlatform = "platform"
)

// BreakerDisarmed reports whether the recorded disarm was the local breaker
// rather than a platform request. An empty source predates the field and counts
// as the breaker, so fielded devices keep their current behaviour.
func (st *watchdogState) BreakerDisarmed() bool {
	return st.Disarmed && st.DisarmSource != DisarmSourcePlatform
}

func parseWatchdogState(data []byte) (*watchdogState, error) {
	var st watchdogState
	if err := json.Unmarshal(data, &st); err != nil {
		return nil, err
	}
	return &st, nil
}

func (st *watchdogState) marshal() ([]byte, error) {
	return json.Marshal(st)
}

// advanceBreaker advances the breaker state machine for one observed start
// (agent startup or the watchdog-gate ExecStartPre — both call it, serialized
// by a file lock, so whichever runs first this boot claims the increment and
// the other sees a matching boot_id and no-ops).
//
// Returns trip=true when this call reached the limit (caller disarms) and
// changed=true when the state must be persisted.
func advanceBreaker(st *watchdogState, bootID string, uptime time.Duration) (trip, changed bool) {
	if st.Disarmed {
		return false, false
	}
	// Same boot: an agent or service restart, not a reboot. A failed
	// update_agent retried three times must never disarm a healthy watchdog.
	if bootID != "" && st.BootID == bootID {
		return false, false
	}
	if uptime >= watchdogBreakerResetAfter {
		// A boot that already survived the window is healthy: start counting
		// afresh from it (e.g. watchdog.service restarted long after boot).
		st.BootID = bootID
		st.BootCount = 0
		return false, true
	}
	st.BootID = bootID
	st.BootCount++
	return st.BootCount >= watchdogBreakerLimit, true
}

// renderWatchdogConf builds /etc/watchdog.conf from the typed fields. The agent
// renders it rather than receiving a blob because it has to understand what it
// is arming — the pre-arm checks and the breaker both read these semantics.
// sensorPath is injected so the renderer stays testable off-device.
func renderWatchdogConf(cmd *proto.ApplyWatchdogConfigCommand, sensorPath string) string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("# Managed by orchestrator — apply_watchdog_config (config %s)\n", cmd.ConfigHash))
	b.WriteString("# Manual edits are overwritten on the next apply.\n\n")

	if cmd.OsHang {
		b.WriteString("watchdog-device = /dev/watchdog\n")
		b.WriteString(fmt.Sprintf("watchdog-timeout = %d\n", clamp32(cmd.WatchdogTimeoutSec, 5, 15, 15)))
	}
	if cmd.Network {
		for _, t := range cmd.PingTargets {
			b.WriteString(fmt.Sprintf("ping = %s\n", t))
		}
		b.WriteString(fmt.Sprintf("ping-count = %d\n", renderedPingCount(cmd)))
		if cmd.Interface != "" {
			b.WriteString(fmt.Sprintf("interface = %s\n", cmd.Interface))
		}
	}
	if cmd.AgentHealth {
		b.WriteString(fmt.Sprintf("file = %s\n", agentHeartbeatFile))
		b.WriteString(fmt.Sprintf("change = %d\n", clamp32(cmd.AgentChangeSec, 120, 3600, 300)))
	}
	if cmd.MaxLoad_1 > 0 {
		b.WriteString(fmt.Sprintf("max-load-1 = %d\n", cmd.MaxLoad_1))
	}
	if cmd.MaxLoad_5 > 0 {
		b.WriteString(fmt.Sprintf("max-load-5 = %d\n", cmd.MaxLoad_5))
	}
	if cmd.MaxLoad_15 > 0 {
		b.WriteString(fmt.Sprintf("max-load-15 = %d\n", cmd.MaxLoad_15))
	}
	if cmd.MinMemoryPages > 0 {
		b.WriteString(fmt.Sprintf("min-memory = %d\n", cmd.MinMemoryPages))
	}
	if cmd.MaxTemperatureC > 0 {
		b.WriteString(fmt.Sprintf("max-temperature = %d\n", cmd.MaxTemperatureC))
		if sensorPath != "" {
			b.WriteString(fmt.Sprintf("temperature-sensor = %s\n", sensorPath))
		}
	}
	b.WriteString(fmt.Sprintf("interval = %d\n", clamp32(cmd.IntervalSec, 1, 60, 10)))
	b.WriteString(fmt.Sprintf("retry-timeout = %d\n", clamp32(cmd.RetryTimeoutSec, 30, 600, 60)))
	b.WriteString(fmt.Sprintf("log-dir = %s\n", watchdogLogDir))
	b.WriteString("realtime = yes\npriority = 1\n")
	return b.String()
}

// watchdogForbiddenDirectives are /etc/watchdog.conf keys this renderer must
// never emit, whatever a future config field looks like.
//
// `test-binary` and `repair-binary` name an executable the daemon runs as root,
// on a timer, in the process whose job is rebooting the machine. Wiring either
// to a stored per-node value would turn the watchdog config into arbitrary
// remote root execution — a security review of its own — and `run_script`
// already covers every ad-hoc need without inheriting a reboot daemon's
// privileges and schedule. The refusal is permanent, not a "not yet".
//
// This list is a statement, not a filter: nothing here is reachable today,
// because renderWatchdogConf writes fixed keys from typed proto fields and has
// no pass-through. TestRenderedWatchdogConfEmitsOnlyKnownDirectives is what
// makes it load-bearing — a new directive fails the test until its author
// lists it, and that is the moment they read this.
var watchdogForbiddenDirectives = []string{"test-binary", "repair-binary"}

// watchdogAllowedDirectives is every key renderWatchdogConf may emit. Adding a
// key here is a deliberate act; see watchdogForbiddenDirectives for the two
// that must never join it.
var watchdogAllowedDirectives = []string{
	"watchdog-device", "watchdog-timeout",
	"ping", "ping-count", "interface",
	"file", "change",
	"max-load-1", "max-load-5", "max-load-15",
	"min-memory", "max-temperature", "temperature-sensor",
	"interval", "retry-timeout", "log-dir",
	"realtime", "priority",
}

// renderedPingCount is the ping count the daemon will actually run with; the
// pre-arm check probes with the SAME count so the check is never weaker than
// the armed reality.
func renderedPingCount(cmd *proto.ApplyWatchdogConfigCommand) int32 {
	return clamp32(cmd.PingCount, 1, 10, 3)
}

// buildWatchdogDropIn renders the systemd drop-in for watchdog.service:
// ordering (arming must wait for the network and this agent, or a slow boot
// looks exactly like a dead network to the daemon) plus the ExecStartPre
// breaker gate. The gate line must NOT use the "-" failure-ignoring prefix —
// a failing gate is exactly what blocks a reboot loop.
func buildWatchdogDropIn(gateBinary string) string {
	return "[Unit]\n" +
		"After=network-online.target orchestrator-agent.service\n" +
		"Wants=network-online.target\n\n" +
		"[Service]\n" +
		"ExecStartPre=" + gateBinary + " " + WatchdogGateSubcommand + "\n"
}

func confSHA256(conf string) string {
	sum := sha256.Sum256([]byte(conf))
	return hex.EncodeToString(sum[:])
}

func clamp32(v, min, max, fallback int32) int32 {
	if v <= 0 {
		return fallback
	}
	if v < min {
		return min
	}
	if v > max {
		return max
	}
	return v
}

func max32(v, min int32) int32 {
	if v < min {
		return min
	}
	return v
}

func tail(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return s[len(s)-n:]
}
