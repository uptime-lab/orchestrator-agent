//go:build linux

package handlers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	proto "agent/pkg/infrastructure/grpc/proto"
	"agent/pkg/infrastructure/hardware"
)

// handleApplyUtilityConfig applies the node's resolved utility set as ONE
// wholesale command (docs/UTILITIES-PLAN.md). Each utility id has a NATIVE
// applier here — the registry never ships shell — and reports its own marker
// in the result map (utility.<id> = "applied" | "failed: <reason>") so the
// platform's settle can converge each utility independently: one refused
// utility must not clear converged siblings.
//
// Appliers are idempotent by construction — the platform re-dispatches on
// drift, on reconnect redelivery and after reimage, so "already installed and
// configured" must be a fast no-op, not an error.
func (h *CommandHandler) handleApplyUtilityConfig(commandID string, cmd *proto.ApplyUtilityConfigCommand) error {
	h.logger.Info("apply utility config command received",
		"command_id", commandID, "union_hash", cmd.UnionHash, "utilities", len(cmd.Utilities))

	// Belt to the platform's braces: the managed-OS hold should keep this off
	// the recovery bootstrap, but an apply "succeeding" against the initramfs
	// would record state that evaporates on the next boot.
	if hardware.RootIsEphemeral() {
		msg := "utilities cannot be applied in the netboot recovery environment"
		h.reportCommandResult(commandID, "failed", msg, nil)
		return fmt.Errorf("%s", msg)
	}
	if len(cmd.Utilities) == 0 {
		msg := "no utilities in the apply set"
		h.reportCommandResult(commandID, "failed", msg, nil)
		return fmt.Errorf("%s", msg)
	}

	h.reportCommandStatus(commandID, "in_progress", 0, "Applying utilities")

	result := map[string]string{"union_hash": cmd.UnionHash}
	var failures []string
	for i, u := range cmd.Utilities {
		progress := int32(10 + (80*i)/len(cmd.Utilities))
		h.reportCommandStatus(commandID, "in_progress", progress, "Applying "+u.UtilityId)

		params := map[string]interface{}{}
		if strings.TrimSpace(u.ParamsJson) != "" {
			if err := json.Unmarshal([]byte(u.ParamsJson), &params); err != nil {
				result["utility."+u.UtilityId] = "failed: invalid params: " + err.Error()
				failures = append(failures, u.UtilityId)
				continue
			}
		}

		var err error
		switch u.UtilityId {
		case "docker":
			err = h.applyDockerUtility(params)
		case "sd_endurance":
			err = h.applySDEnduranceUtility(params)
		case "node_exporter":
			err = h.applyNodeExporterUtility(params)
		case "unattended_upgrades":
			err = h.applyUnattendedUpgradesUtility(params)
		case "kiosk":
			err = h.applyKioskUtility(params)
		case "zerotier":
			err = h.applyZeroTierUtility(params)
		case "tailscale":
			err = h.applyTailscaleUtility(params)
		default:
			// An unknown id means a newer platform catalog than this agent —
			// refused per utility, not per command, so known siblings still
			// converge. The remedy the message names is the real one.
			err = fmt.Errorf("this agent does not implement utility %q (update the agent)", u.UtilityId)
		}
		if err != nil {
			result["utility."+u.UtilityId] = "failed: " + truncateOutput(err.Error())
			failures = append(failures, u.UtilityId)
			continue
		}
		result["utility."+u.UtilityId] = "applied"
	}

	if len(failures) > 0 {
		sort.Strings(failures)
		msg := "failed utilities: " + strings.Join(failures, ", ")
		h.reportCommandResult(commandID, "failed", msg, result)
		return fmt.Errorf("%s", msg)
	}
	h.reportCommandResult(commandID, "success", "utilities applied", result)
	return nil
}

// dockerDaemonJSONPath is where dockerd reads its configuration.
const dockerDaemonJSONPath = "/etc/docker/daemon.json"

// applyDockerUtility converges the Docker runtime: install the distro package
// when absent, render daemon.json from the params, restart/enable the service
// as needed, and verify it is actually active — a green apply with a dead
// dockerd is the failure mode the confirmation exists to catch.
func (h *CommandHandler) applyDockerUtility(params map[string]interface{}) error {
	// 1. Install when absent. dpkg-query, not `docker --version`: a leftover
	// binary from a hand install must not skip the package that carries the
	// systemd unit this applier manages.
	if err := aptInstallIfAbsent("docker.io"); err != nil {
		return err
	}

	// 2. Render daemon.json by MERGING the managed keys into whatever is on
	// disk — a wholesale replace reverts an operator's own data-root (orphaning
	// every existing container) and drops any key we never heard of. Written
	// only when the merged document differs from what is on disk, so a
	// converged re-apply touches nothing and no daemon restart happens.
	existing, readErr := os.ReadFile(dockerDaemonJSONPath)
	if readErr != nil && !os.IsNotExist(readErr) {
		return fmt.Errorf("failed to read %s: %w", dockerDaemonJSONPath, readErr)
	}
	daemonCfg, err := mergeDockerDaemonJSON(existing, params)
	if err != nil {
		return err
	}
	// Backed up once (the patch_file idiom) BEFORE the first modification, so
	// the pre-orchestrator config stays recoverable however many applies follow.
	if len(existing) > 0 && !bytes.Equal(existing, daemonCfg) {
		if err := backupOnce(dockerDaemonJSONPath); err != nil {
			return fmt.Errorf("failed to back up %s: %w", dockerDaemonJSONPath, err)
		}
	}
	changed, err := writeIfChanged(dockerDaemonJSONPath, daemonCfg, 0o644)
	if err != nil {
		return fmt.Errorf("failed to write daemon.json: %w", err)
	}

	// 3. Service state. enable --now is idempotent; a config change restarts a
	// running daemon so the new limits actually bind.
	if out, err := runWithEnv(nil, softwareCmdTimeout, "systemctl", "enable", "--now", "docker"); err != nil {
		return fmt.Errorf("failed to enable docker: %v: %s", err, truncateOutput(out))
	}
	if changed {
		if out, err := runWithEnv(nil, softwareCmdTimeout, "systemctl", "restart", "docker"); err != nil {
			return fmt.Errorf("failed to restart docker after config change: %v: %s", err, truncateOutput(out))
		}
	}

	// 4. Verify. `is-active` answers the only question that matters.
	if out, _ := runWithEnv(nil, softwareCmdTimeout, "systemctl", "is-active", "docker"); strings.TrimSpace(out) != "active" {
		return fmt.Errorf("dockerd is not active after apply (state: %s)", strings.TrimSpace(out))
	}
	return nil
}

// dockerLogSizeRe is dockerd's accepted max-size shape: a positive integer
// with an optional k/m/g unit. Second line of defense behind the registry
// bounds — an unvalidated typo here does not fail the apply, it takes dockerd
// down on every node of the assignment when the daemon rereads its config.
var (
	dockerLogSizeRe = regexp.MustCompile(`^[1-9][0-9]*[kmg]?$`)
	dockerLogFileRe = regexp.MustCompile(`^[1-9][0-9]*$`)
)

// renderDockerManagedKeys builds the daemon.json keys this applier owns. The
// agent re-validates what it consumes (the platform's registry bounds are the
// first line, this is the second): log caps must be values dockerd will start
// with, mirrors must be https, the data root must be an absolute path.
func renderDockerManagedKeys(params map[string]interface{}) (map[string]interface{}, error) {
	doc := map[string]interface{}{
		"log-driver": "json-file",
	}
	logOpts := map[string]string{}
	if v, ok := params["log_max_size"].(string); ok && strings.TrimSpace(v) != "" {
		size := strings.ToLower(strings.TrimSpace(v))
		if !dockerLogSizeRe.MatchString(size) {
			return nil, fmt.Errorf("log_max_size must be a positive integer with an optional k/m/g unit (e.g. 10m), got %q", v)
		}
		logOpts["max-size"] = size
	}
	switch v := params["log_max_file"].(type) {
	case float64:
		if v >= 1 {
			logOpts["max-file"] = fmt.Sprintf("%d", int(v))
		}
	case string:
		if s := strings.TrimSpace(v); s != "" {
			// Same daemon-down failure shape as max-size: dockerd refuses to
			// start on a non-numeric max-file.
			if !dockerLogFileRe.MatchString(s) {
				return nil, fmt.Errorf("log_max_file must be a positive integer, got %q", v)
			}
			logOpts["max-file"] = s
		}
	}
	if len(logOpts) > 0 {
		doc["log-opts"] = logOpts
	}
	if v, ok := params["data_root"].(string); ok && strings.TrimSpace(v) != "" {
		root := strings.TrimSpace(v)
		if !strings.HasPrefix(root, "/") || strings.Contains(root, "..") {
			return nil, fmt.Errorf("data_root must be an absolute path")
		}
		doc["data-root"] = root
	}
	if v, ok := params["registry_mirrors"].(string); ok && strings.TrimSpace(v) != "" {
		var mirrors []string
		for _, m := range strings.Split(v, ",") {
			m = strings.TrimSpace(m)
			if m == "" {
				continue
			}
			if !strings.HasPrefix(m, "https://") {
				return nil, fmt.Errorf("registry mirror %q must be https", m)
			}
			mirrors = append(mirrors, m)
		}
		if len(mirrors) > 0 {
			doc["registry-mirrors"] = mirrors
		}
	}
	if v, ok := params["live_restore"].(bool); ok && v {
		doc["live-restore"] = true
	}
	return doc, nil
}

// mergeDockerDaemonJSON merges the managed keys into the existing daemon.json
// (nil/empty = none), preserving every key the applier does not own. An
// existing file that is not valid JSON is REFUSED, never clobbered — the
// operator wrote it, and "fix or remove it" is their call to make. A managed
// key absent from the params is retained, not deleted: without stored state
// the applier cannot tell its own earlier value from the operator's
// (unassign-is-retain, one level down).
func mergeDockerDaemonJSON(existing []byte, params map[string]interface{}) ([]byte, error) {
	managed, err := renderDockerManagedKeys(params)
	if err != nil {
		return nil, err
	}
	doc := map[string]interface{}{}
	if len(bytes.TrimSpace(existing)) > 0 {
		if err := json.Unmarshal(existing, &doc); err != nil {
			return nil, fmt.Errorf("%s exists but is not valid JSON (%v) — fix or remove it before applying the docker utility", dockerDaemonJSONPath, err)
		}
	}
	for k, v := range managed {
		doc[k] = v
	}
	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(out, '\n'), nil
}

// writeIfChanged atomically writes content when the file differs, reporting
// whether a write happened. Reads first so a converged re-apply is a no-op —
// the property the drift loop depends on. Creates the parent directory (the
// hardcoded /etc/docker it replaced would have leaked into every later
// applier's drop-in writes).
func writeIfChanged(path string, content []byte, mode os.FileMode) (bool, error) {
	if existing, err := os.ReadFile(path); err == nil && string(existing) == string(content) {
		return false, nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return false, err
	}
	if err := atomicWriteFile(path, content, mode); err != nil {
		return false, err
	}
	return true, nil
}

// aptInstallIfAbsent installs one distro package when dpkg does not already
// record it installed. DPkg::Lock::Timeout makes apt WAIT on a held lock
// instead of failing instantly — the unattended_upgrades utility makes
// apt-daily runs hold that lock at random times fleet-wide, and without the
// timeout every apt-based apply would gain a random transient failure mode.
func aptInstallIfAbsent(pkg string) error {
	if out, err := runWithEnv(nil, softwareCmdTimeout, "dpkg-query", "-W", "-f", "${Status}", pkg); err == nil &&
		strings.Contains(out, "install ok installed") {
		return nil
	}
	if _, err := exec.LookPath("apt-get"); err != nil {
		return fmt.Errorf("this utility requires apt (Debian/Ubuntu)")
	}
	env := append(os.Environ(), "DEBIAN_FRONTEND=noninteractive")
	if out, err := runWithEnv(env, softwareCmdTimeout, "apt-get", "-o", "DPkg::Lock::Timeout=300", "update"); err != nil {
		return fmt.Errorf("apt-get update failed: %v: %s", err, truncateOutput(out))
	}
	if out, err := runWithEnv(env, softwareCmdTimeout, "apt-get", "-o", "DPkg::Lock::Timeout=300",
		"install", "-y", "--no-install-recommends", "--", pkg); err != nil {
		return fmt.Errorf("apt-get install %s failed: %v: %s", pkg, err, truncateOutput(out))
	}
	return nil
}

// paramStr / paramBool / paramInt read a defaulted param with a fallback —
// the platform applies registry defaults before dispatch, so the fallback
// only covers a platform older than the registry entry.
func paramStr(params map[string]interface{}, key, fallback string) string {
	if v, ok := params[key].(string); ok && strings.TrimSpace(v) != "" {
		return strings.TrimSpace(v)
	}
	return fallback
}

func paramBool(params map[string]interface{}, key string, fallback bool) bool {
	if v, ok := params[key].(bool); ok {
		return v
	}
	return fallback
}

func paramInt(params map[string]interface{}, key string, fallback, min, max int) int {
	v := fallback
	switch n := params[key].(type) {
	case float64:
		v = int(n)
	case int:
		v = n
	}
	if v < min {
		v = min
	}
	if v > max {
		v = max
	}
	return v
}
