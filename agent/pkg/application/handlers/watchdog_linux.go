//go:build linux

package handlers

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	proto "agent/pkg/infrastructure/grpc/proto"
)

func readWatchdogStateFrom(path string) (*watchdogState, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return parseWatchdogState(data)
}

func writeWatchdogStateTo(path string, st *watchdogState) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	data, err := st.marshal()
	if err != nil {
		return err
	}
	return atomicWriteFile(path, data, 0o600)
}

// withWatchdogStateLock serializes breaker read-modify-write cycles between the
// agent's startup check and the watchdog-gate ExecStartPre, which can run
// concurrently at boot. Without it both would count the same boot.
func withWatchdogStateLock(fn func()) {
	_ = os.MkdirAll(watchdogStateDir, 0o755)
	f, err := os.OpenFile(watchdogStateLock, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		fn() // better an unserialized breaker than none
		return
	}
	defer f.Close()
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err == nil {
		defer func() { _ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN) }()
	}
	fn()
}

func readBootID() string {
	data, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func readUptime() time.Duration {
	data, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0
	}
	fields := strings.Fields(string(data))
	if len(fields) == 0 {
		return 0
	}
	secs, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return 0
	}
	return time.Duration(secs * float64(time.Second))
}

// handleApplyWatchdogConfig converges the node's watchdog supervision.
func (h *CommandHandler) handleApplyWatchdogConfig(commandID string, cmd *proto.ApplyWatchdogConfigCommand) error {
	h.logger.Info("apply watchdog config command received",
		"command_id", commandID, "enabled", cmd.Enabled, "hash", cmd.ConfigHash)
	h.reportCommandStatus(commandID, "in_progress", 0, "Converging watchdog configuration")

	if !cmd.Enabled {
		if err := h.disableWatchdogSupervision("disabled by the platform"); err != nil {
			h.reportCommandResult(commandID, "failed", err.Error(), nil)
			return err
		}
		h.reportCommandResult(commandID, "success", "watchdog disabled", map[string]string{
			"applied_hash":  cmd.ConfigHash,
			"service_state": serviceState("watchdog.service"),
		})
		return nil
	}

	conf := renderWatchdogConf(cmd, temperatureSensorPath())

	// 1. Already converged? The rendered content is the source of truth — a
	// hand-edited /etc/watchdog.conf must be restored, not reported as done —
	// with the breaker state and the running service as corroboration.
	if st, err := readWatchdogStateFrom(watchdogStateFile); err == nil && !st.Disarmed &&
		st.ConfigHash == cmd.ConfigHash && onDiskMatches(watchdogConfPath, conf) &&
		serviceState("watchdog.service") == "active" {
		h.reportCommandResult(commandID, "success", "watchdog already converged", map[string]string{
			"applied_hash":  cmd.ConfigHash,
			"service_state": "active",
			"conf":          conf,
			"conf_sha256":   confSHA256(conf),
		})
		return nil
	}

	// 2. Package. Debian enables and starts watchdog.service on install with its
	// stock config; stop it immediately — the distro default supervises nothing
	// we chose and could reboot on a threshold we never asked for. wd_keepalive
	// is the package's companion daemon and would fight over /dev/watchdog.
	h.reportCommandStatus(commandID, "in_progress", 20, "Ensuring the watchdog package")
	if _, err := os.Stat("/usr/sbin/watchdog"); os.IsNotExist(err) {
		if out, ierr := runWithEnv(aptEnv(), 10*time.Minute, "apt-get", "install", "-y", "watchdog"); ierr != nil {
			msg := fmt.Sprintf("failed to install the watchdog package: %v (%s)", ierr, tail(out, 300))
			h.reportCommandResult(commandID, "failed", msg, map[string]string{"refusal": refusalPackageInstallFailed})
			return fmt.Errorf("%s", msg)
		}
		_, _ = runWithEnv(nil, 30*time.Second, "systemctl", "stop", "watchdog.service")
	}
	_, _ = runWithEnv(nil, 30*time.Second, "systemctl", "disable", "--now", "wd_keepalive.service")

	// 3. Pre-arm checks against live state. A refusal changes NOTHING beyond the
	// package above: the point is that an operator who typo'd a ping target gets
	// an error, not a device that reboots every minute until someone drives to
	// it. The deterministic checks (ping reachability, missing sensor, missing
	// hardware) always run; VerifyBeforeArm=false — which the platform never
	// sends today — could only relax the transient threshold-value checks.
	h.reportCommandStatus(commandID, "in_progress", 40, "Checking the proposed configuration against the device")
	if refusal, detail := h.preArmChecks(cmd, !cmd.VerifyBeforeArm); refusal != "" {
		h.reportCommandResult(commandID, "failed", detail, map[string]string{"refusal": refusal})
		return fmt.Errorf("%s", detail)
	}

	// 4. Render and write the config.
	h.reportCommandStatus(commandID, "in_progress", 60, "Writing /etc/watchdog.conf")
	if err := backupOnce(watchdogConfPath); err != nil {
		h.reportCommandResult(commandID, "failed", "backup failed: "+err.Error(), nil)
		return err
	}
	if err := atomicWriteFile(watchdogConfPath, []byte(conf), 0o644); err != nil {
		h.reportCommandResult(commandID, "failed", "write failed: "+err.Error(), nil)
		return err
	}
	_ = os.MkdirAll(watchdogLogDir, 0o755)

	// 5. Unit drop-in: boot ordering + the ExecStartPre breaker gate (the gate
	// is this same binary, so it runs even when the agent service cannot).
	gateBinary := agentBinaryFallback
	if exe, err := os.Executable(); err == nil && exe != "" {
		gateBinary = exe
	}
	if err := os.MkdirAll(watchdogDropInDir, 0o755); err == nil {
		_ = atomicWriteFile(watchdogDropIn, []byte(buildWatchdogDropIn(gateBinary)), 0o644)
	}

	// 6. Single owner of /dev/watchdog: the daemon takes it, so the legacy
	// systemd RuntimeWatchdogSec drop-in has to go or neither can open it.
	if _, err := os.Stat(legacySystemdDropIn); err == nil {
		_ = os.Remove(legacySystemdDropIn)
		_, _ = runWithEnv(nil, 30*time.Second, "systemctl", "daemon-reexec")
	}

	// 7. Hardware device via the existing managed block in config.txt. Absent
	// /dev/watchdog is not fatal — the software supervisors work now and the
	// device attaches on the next reboot.
	hwNote := ""
	if cmd.OsHang {
		if err := patchConfigTxtWatchdog("dtparam=watchdog=on"); err != nil {
			hwNote = "; could not update config.txt: " + err.Error()
		}
		if _, err := os.Stat("/dev/watchdog"); os.IsNotExist(err) {
			hwNote += "; /dev/watchdog is not present yet — it attaches after the next reboot"
		}
	}

	// 8. Record the breaker state BEFORE starting the service so a reboot loop
	// that begins immediately is still counted. If the state cannot be
	// persisted the breaker cannot count, and an uncounted watchdog must not
	// arm — the gate would refuse to start it anyway.
	h.reportCommandStatus(commandID, "in_progress", 80, "Enabling watchdog.service")
	if err := writeWatchdogStateTo(watchdogStateFile, &watchdogState{
		ConfigHash: cmd.ConfigHash,
		BootID:     readBootID(),
	}); err != nil {
		msg := "cannot persist the watchdog breaker state; refusing to arm: " + err.Error()
		h.reportCommandResult(commandID, "failed", msg, map[string]string{"refusal": refusalBreakerUnwritable})
		return fmt.Errorf("%s", msg)
	}
	_, _ = runWithEnv(nil, 30*time.Second, "systemctl", "daemon-reload")
	if out, err := runWithEnv(nil, 60*time.Second, "systemctl", "enable", "--now", "watchdog.service"); err != nil {
		msg := fmt.Sprintf("failed to enable watchdog.service: %v (%s)", err, tail(out, 300))
		h.reportCommandResult(commandID, "failed", msg, nil)
		return fmt.Errorf("%s", msg)
	}
	time.Sleep(5 * time.Second)
	state := serviceState("watchdog.service")
	if state != "active" {
		msg := "watchdog.service did not stay active after arming (state: " + state + ")"
		h.reportCommandResult(commandID, "failed", msg, map[string]string{"service_state": state})
		return fmt.Errorf("%s", msg)
	}

	h.reportCommandResult(commandID, "success", "watchdog armed"+hwNote, map[string]string{
		"applied_hash":  cmd.ConfigHash,
		"service_state": state,
		"conf":          conf,
		"conf_sha256":   confSHA256(conf),
	})
	return nil
}

func onDiskMatches(path, want string) bool {
	data, err := os.ReadFile(path)
	return err == nil && string(data) == want
}

// preArmChecks runs the proposed config against live device state. It returns a
// refusal key and an operator-readable reason, or empty strings to proceed.
// relaxThresholds skips only the transient VALUE comparisons (current load /
// memory / temperature); reachability, missing sensors and unreadable device
// state always refuse — "the ping target is temporarily down" IS the reboot
// loop, not a reason to skip the check.
func (h *CommandHandler) preArmChecks(cmd *proto.ApplyWatchdogConfigCommand, relaxThresholds bool) (string, string) {
	if cmd.Network {
		if len(cmd.PingTargets) == 0 {
			return refusalPingUnreachable, "network supervision needs at least one ping target"
		}
		count := renderedPingCount(cmd)
		for _, target := range cmd.PingTargets {
			args := []string{"-c", strconv.Itoa(int(count)), "-W", "2"}
			if cmd.Interface != "" {
				args = append(args, "-I", cmd.Interface)
			}
			args = append(args, target)
			if _, err := runWithEnv(nil, 60*time.Second, "ping", args...); err != nil {
				return refusalPingUnreachable, fmt.Sprintf(
					"%s does not answer from this node; arming would reboot it every cycle", target)
			}
		}
	}

	if cmd.MaxLoad_1 > 0 {
		load, err := readLoad1()
		if err != nil {
			return refusalDeviceStateUnreadable, "cannot read /proc/loadavg to verify the load threshold: " + err.Error()
		}
		if !relaxThresholds && load >= float64(cmd.MaxLoad_1) {
			return refusalLoadAboveThreshold, fmt.Sprintf(
				"the 1-minute load is already %.2f, at or above the %d limit", load, cmd.MaxLoad_1)
		}
	}

	if cmd.MinMemoryPages > 0 {
		pages, err := readFreePages()
		if err != nil {
			return refusalDeviceStateUnreadable, "cannot read /proc/meminfo to verify the memory threshold: " + err.Error()
		}
		if !relaxThresholds && pages < int64(cmd.MinMemoryPages) {
			return refusalMemoryBelowThreshold, fmt.Sprintf(
				"free memory is already %d pages, below the %d limit", pages, cmd.MinMemoryPages)
		}
	}

	if cmd.MaxTemperatureC > 0 {
		temp, err := readTemperatureC()
		if err != nil {
			return refusalTempSensorMissing, "this node exposes no temperature sensor, so a temperature limit cannot be supervised"
		}
		if !relaxThresholds && temp >= float64(cmd.MaxTemperatureC) {
			return refusalTempAboveThreshold, fmt.Sprintf(
				"the CPU is already at %.1f°C, at or above the %d°C limit", temp, cmd.MaxTemperatureC)
		}
	}

	if cmd.OsHang {
		if _, err := os.Stat("/dev/watchdog"); os.IsNotExist(err) {
			if _, cerr := os.Stat("/boot/firmware/config.txt"); cerr != nil {
				if _, c2 := os.Stat("/boot/config.txt"); c2 != nil {
					return refusalHwWatchdogMissing, "this node has no /dev/watchdog and no Raspberry Pi config.txt to enable one"
				}
			}
		}
	}
	return "", ""
}

// disableWatchdogSupervision is the platform-requested disable path: full
// teardown including the hardware dtparam marker. The breaker's disarm keeps
// the marker (harmless while nothing holds /dev/watchdog) so a later re-arm
// does not need another reboot.
func (h *CommandHandler) disableWatchdogSupervision(reason string) error {
	if err := h.disarmWatchdog(reason, DisarmSourcePlatform); err != nil {
		return err
	}
	if err := patchConfigTxtWatchdog("# hardware watchdog managed block disabled by orchestrator"); err != nil {
		h.logger.Warn("could not revert the config.txt watchdog block", "error", err)
	}
	return nil
}

// disarmWatchdog stops and disables the daemon and records why — and WHO. The
// source matters as much as the reason: the platform reads a breaker disarm as
// a fault worth alarming on, and its own disable request is not one.
func (h *CommandHandler) disarmWatchdog(reason, source string) error {
	_, _ = runWithEnv(nil, 60*time.Second, "systemctl", "disable", "--now", "watchdog.service")
	_, _ = runWithEnv(nil, 30*time.Second, "systemctl", "disable", "--now", "wd_keepalive.service")
	_ = os.Remove(watchdogDropIn)
	_, _ = runWithEnv(nil, 30*time.Second, "systemctl", "daemon-reload")
	st, err := readWatchdogStateFrom(watchdogStateFile)
	if err != nil {
		st = &watchdogState{}
	}
	st.Disarmed = true
	st.DisarmReason = reason
	st.DisarmSource = source
	st.BootCount = 0
	return writeWatchdogStateTo(watchdogStateFile, st)
}

// CheckWatchdogBreaker runs at agent startup. If the node keeps REBOOTING with
// an armed watchdog, the watchdog itself is the most likely cause, and the
// platform cannot always see it (a node that reboots before reporting is just
// "flapping"). Three boots inside the reset window disarms it locally. Agent
// restarts within one boot are not reboots and never count.
func (h *CommandHandler) CheckWatchdogBreaker() {
	var report string
	withWatchdogStateLock(func() {
		st, err := readWatchdogStateFrom(watchdogStateFile)
		if err != nil {
			return
		}
		// A BREAKER disarm may have happened while nothing could reach the
		// platform (the ExecStartPre gate trips without the agent running, and a
		// pre-connect report can die with the process). Re-reporting every start
		// while disarmed is idempotent on the platform side.
		//
		// A PLATFORM disarm is never re-reported: the platform asked for it and
		// already knows. Reporting it back made every deliberate disarm resurface
		// as "the device disarmed itself after repeated reboots" on the next
		// agent start, complete with a red fleet-list pill.
		if st.Disarmed {
			if st.BreakerDisarmed() {
				report = st.DisarmReason
			}
			return
		}
		if serviceState("watchdog.service") != "active" && !isServiceEnabled("watchdog.service") {
			return
		}

		trip, changed := advanceBreaker(st, readBootID(), readUptime())
		if trip {
			reason := fmt.Sprintf("the node rebooted %d times with the watchdog armed", st.BootCount)
			h.logger.Warn("watchdog breaker tripped; disarming", "boot_count", st.BootCount)
			if derr := h.disarmWatchdog(reason, DisarmSourceBreaker); derr != nil {
				h.logger.Error("failed to disarm the watchdog after the breaker tripped", "error", derr)
			}
			report = reason
			return
		}
		if changed {
			if werr := writeWatchdogStateTo(watchdogStateFile, st); werr != nil {
				h.logger.Warn("failed to persist the watchdog breaker count", "error", werr)
			}
		}

		// A node that stays up has not looped: clear the counter after the window.
		go func(hash string) {
			time.Sleep(watchdogBreakerResetAfter)
			withWatchdogStateLock(func() {
				current, rerr := readWatchdogStateFrom(watchdogStateFile)
				if rerr != nil || current.Disarmed || current.ConfigHash != hash {
					return
				}
				current.BootCount = 0
				if werr := writeWatchdogStateTo(watchdogStateFile, current); werr != nil {
					h.logger.Warn("failed to reset the watchdog breaker count", "error", werr)
				}
			})
		}(st.ConfigHash)
	})
	if report != "" {
		h.sendStatusUpdate("watchdog_disarmed", report)
	}
}

// RunWatchdogBreakerGate is the ExecStartPre= of watchdog.service (subcommand
// `orchestrator-agent watchdog-gate`). Exit 0 lets the daemon start; any other
// exit blocks it. It is deliberately independent of the agent service, its
// adoption file and the platform: a reboot loop must stop even when all three
// are broken. Fail-closed: no breaker state, a tripped breaker, or state that
// cannot be persisted all refuse the start.
func RunWatchdogBreakerGate() int {
	// Boot grace for the agent-health file test: guarantee a fresh alive file
	// so a slow agent start is never misread as a dead agent.
	_ = os.MkdirAll(filepath.Dir(agentHeartbeatFile), 0o755)
	_ = os.WriteFile(agentHeartbeatFile, nil, 0o644)
	_ = os.MkdirAll(watchdogLogDir, 0o755)

	code := 0
	withWatchdogStateLock(func() {
		st, err := readWatchdogStateFrom(watchdogStateFile)
		if err != nil {
			fmt.Fprintln(os.Stderr, "watchdog-gate: no readable breaker state; refusing to start an unaccounted watchdog")
			_, _ = runWithEnv(nil, 30*time.Second, "systemctl", "disable", "watchdog.service")
			code = 1
			return
		}
		if st.Disarmed {
			fmt.Fprintf(os.Stderr, "watchdog-gate: breaker is disarmed (%s); refusing to start\n", st.DisarmReason)
			_, _ = runWithEnv(nil, 30*time.Second, "systemctl", "disable", "watchdog.service")
			code = 1
			return
		}
		trip, changed := advanceBreaker(st, readBootID(), readUptime())
		if trip {
			st.Disarmed = true
			st.DisarmReason = fmt.Sprintf("the node rebooted %d times with the watchdog armed", st.BootCount)
			st.BootCount = 0
			if werr := writeWatchdogStateTo(watchdogStateFile, st); werr != nil {
				fmt.Fprintln(os.Stderr, "watchdog-gate: failed to persist the tripped breaker:", werr)
			}
			fmt.Fprintf(os.Stderr, "watchdog-gate: breaker tripped (%s); disabling watchdog.service\n", st.DisarmReason)
			_, _ = runWithEnv(nil, 30*time.Second, "systemctl", "disable", "watchdog.service")
			code = 1
			return
		}
		if changed {
			if werr := writeWatchdogStateTo(watchdogStateFile, st); werr != nil {
				// If the count cannot be persisted the breaker cannot count;
				// hold the daemon for this boot rather than run unaccounted.
				fmt.Fprintln(os.Stderr, "watchdog-gate: cannot persist the breaker count; holding watchdog.service:", werr)
				code = 1
				return
			}
		}
	})
	return code
}

// --- helpers ---

func serviceState(unit string) string {
	out, _ := runWithEnv(nil, 15*time.Second, "systemctl", "is-active", unit)
	return strings.TrimSpace(out)
}

func isServiceEnabled(unit string) bool {
	out, _ := runWithEnv(nil, 15*time.Second, "systemctl", "is-enabled", unit)
	return strings.TrimSpace(out) == "enabled"
}

func aptEnv() []string {
	return append(os.Environ(), "DEBIAN_FRONTEND=noninteractive")
}

func readLoad1() (float64, error) {
	data, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return 0, err
	}
	fields := strings.Fields(string(data))
	if len(fields) == 0 {
		return 0, fmt.Errorf("unexpected /proc/loadavg")
	}
	return strconv.ParseFloat(fields[0], 64)
}

func readFreePages() (int64, error) {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "MemAvailable:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				kb, perr := strconv.ParseInt(fields[1], 10, 64)
				if perr != nil {
					return 0, perr
				}
				return kb / 4, nil // 4 KiB pages, which is what watchdog.conf counts
			}
		}
	}
	return 0, fmt.Errorf("MemAvailable not found")
}

func temperatureSensorPath() string {
	candidates, _ := filepath.Glob("/sys/class/thermal/thermal_zone*/temp")
	if len(candidates) > 0 {
		return candidates[0]
	}
	return ""
}

func readTemperatureC() (float64, error) {
	path := temperatureSensorPath()
	if path == "" {
		return 0, fmt.Errorf("no thermal zone")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	milli, err := strconv.ParseFloat(strings.TrimSpace(string(data)), 64)
	if err != nil {
		return 0, err
	}
	return milli / 1000, nil
}

// patchConfigTxtWatchdog rewrites the managed `watchdog` marker block in
// config.txt through the same mechanism the old panel used, so the two do not
// fight over the file.
func patchConfigTxtWatchdog(content string) error {
	path := "/boot/firmware/config.txt"
	if _, err := os.Stat(path); err != nil {
		path = "/boot/config.txt"
		if _, err2 := os.Stat(path); err2 != nil {
			return fmt.Errorf("no config.txt found")
		}
	}
	current, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	patched, err := patchManagedBlock(current, content, "watchdog")
	if err != nil {
		return err
	}
	if string(patched) == string(current) {
		return nil
	}
	if err := backupOnce(path); err != nil {
		return err
	}
	return atomicWriteFile(path, patched, 0o644)
}

// backupOnce keeps the pre-orchestrator copy of a file, once.
func backupOnce(path string) error {
	backup := path + ".orchestrator.bak"
	if _, err := os.Stat(backup); err == nil {
		return nil
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil // nothing to back up yet
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return os.WriteFile(backup, data, info.Mode().Perm())
}
