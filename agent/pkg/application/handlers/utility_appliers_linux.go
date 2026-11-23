//go:build linux

package handlers

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// The utility appliers (docs/UTILITIES-RESEARCH.md): each is
// install + render + enable + verify, idempotent, nothing more. Verification
// is per-case ON PURPOSE — `is-active` alone is the "green unit, black HDMI"
// bug wearing a different hat (a zram service can be active with no swap
// mounted; unattended-upgrades is a timer, not a service).

// --- sd_endurance: zram swap + journald caps -----------------------------

func (h *CommandHandler) applySDEnduranceUtility(params map[string]interface{}) error {
	// zram half. Disabled = the service is disabled, never uninstalled —
	// unassign-is-retain reasoning one level down.
	if paramBool(params, "zram_enabled", true) {
		if err := aptInstallIfAbsent("zram-tools"); err != nil {
			return err
		}
		algo := paramStr(params, "zram_algo", "zstd")
		switch algo {
		case "zstd", "lz4", "lzo-rle":
		default:
			return fmt.Errorf("unsupported zram algorithm %q", algo)
		}
		percent := paramInt(params, "zram_percent", 25, 5, 75)
		conf := fmt.Sprintf("# Managed by orchestrator (utility: sd_endurance)\nALGO=%s\nPERCENT=%d\n", algo, percent)
		changed, err := writeIfChanged("/etc/default/zramswap", []byte(conf), 0o644)
		if err != nil {
			return fmt.Errorf("failed to write zramswap config: %w", err)
		}
		if out, err := runWithEnv(nil, softwareCmdTimeout, "systemctl", "enable", "--now", "zramswap"); err != nil {
			return fmt.Errorf("failed to enable zramswap: %v: %s", err, truncateOutput(out))
		}
		if changed {
			if out, err := runWithEnv(nil, softwareCmdTimeout, "systemctl", "restart", "zramswap"); err != nil {
				return fmt.Errorf("failed to restart zramswap: %v: %s", err, truncateOutput(out))
			}
		}
		// Verify the swap actually EXISTS — is-active alone passes on a unit
		// that ran and mounted nothing.
		swaps, err := os.ReadFile("/proc/swaps")
		if err != nil || !strings.Contains(string(swaps), "zram") {
			return fmt.Errorf("zramswap applied but no zram device is in /proc/swaps")
		}
	} else {
		// Best-effort disable; a node that never had the package is converged.
		_, _ = runWithEnv(nil, softwareCmdTimeout, "systemctl", "disable", "--now", "zramswap")
	}

	// journald half. A drop-in, never an edit of journald.conf.
	maxUse := paramStr(params, "journald_max_use", "64M")
	switch maxUse {
	case "16M", "64M", "256M", "1G":
	default:
		return fmt.Errorf("journald_max_use must be one of 16M/64M/256M/1G, got %q", maxUse)
	}
	storage := paramStr(params, "journald_storage", "persistent")
	if storage != "persistent" && storage != "volatile" {
		return fmt.Errorf("journald_storage must be persistent or volatile, got %q", storage)
	}
	dropIn := fmt.Sprintf("# Managed by orchestrator (utility: sd_endurance)\n[Journal]\nSystemMaxUse=%s\nStorage=%s\n", maxUse, storage)
	changed, err := writeIfChanged("/etc/systemd/journald.conf.d/60-orchestrator.conf", []byte(dropIn), 0o644)
	if err != nil {
		return fmt.Errorf("failed to write journald drop-in: %w", err)
	}
	if changed {
		// Safe since systemd 246: the fd store survives a journald restart.
		if out, err := runWithEnv(nil, softwareCmdTimeout, "systemctl", "restart", "systemd-journald"); err != nil {
			return fmt.Errorf("failed to restart journald: %v: %s", err, truncateOutput(out))
		}
	}
	if out, _ := runWithEnv(nil, softwareCmdTimeout, "systemctl", "is-active", "systemd-journald"); strings.TrimSpace(out) != "active" {
		return fmt.Errorf("systemd-journald is not active after apply")
	}
	return nil
}

// --- node_exporter: prometheus host metrics ------------------------------

const nodeExporterDefaultsPath = "/etc/default/prometheus-node-exporter"
const nodeExporterTextfileDir = "/var/lib/prometheus/node-exporter"

func (h *CommandHandler) applyNodeExporterUtility(params map[string]interface{}) error {
	if err := aptInstallIfAbsent("prometheus-node-exporter"); err != nil {
		return err
	}
	port := paramInt(params, "listen_port", 9100, 1024, 65535)
	addr := "0.0.0.0"
	if paramStr(params, "listen_address", "all") == "localhost" {
		addr = "127.0.0.1"
	}
	args := fmt.Sprintf("--web.listen-address=%s:%d", addr, port)
	if paramBool(params, "textfile_collector", true) {
		if err := os.MkdirAll(nodeExporterTextfileDir, 0o755); err != nil {
			return fmt.Errorf("failed to create the textfile collector dir: %w", err)
		}
		args += " --collector.textfile.directory=" + nodeExporterTextfileDir
	}
	conf := fmt.Sprintf("# Managed by orchestrator (utility: node_exporter)\nARGS=%q\n", args)
	changed, err := writeIfChanged(nodeExporterDefaultsPath, []byte(conf), 0o644)
	if err != nil {
		return fmt.Errorf("failed to write node exporter defaults: %w", err)
	}
	if out, err := runWithEnv(nil, softwareCmdTimeout, "systemctl", "enable", "--now", "prometheus-node-exporter"); err != nil {
		return fmt.Errorf("failed to enable prometheus-node-exporter: %v: %s", err, truncateOutput(out))
	}
	if changed {
		if out, err := runWithEnv(nil, softwareCmdTimeout, "systemctl", "restart", "prometheus-node-exporter"); err != nil {
			return fmt.Errorf("failed to restart prometheus-node-exporter: %v: %s", err, truncateOutput(out))
		}
	}
	// Verify by scraping: metrics is the product, not the unit state. Both
	// listen addresses answer on loopback (0.0.0.0 includes it). Retried:
	// systemctl restart returns before the exporter binds its socket, and a
	// single instant probe raced exactly that gap on real hardware.
	client := &http.Client{Timeout: 5 * time.Second}
	var lastErr error
	for i := 0; i < 5; i++ {
		if i > 0 {
			time.Sleep(2 * time.Second)
		}
		resp, err := client.Get(fmt.Sprintf("http://127.0.0.1:%d/metrics", port))
		if err != nil {
			lastErr = fmt.Errorf("node exporter is not answering on port %d: %v", port, err)
			continue
		}
		// The output is SORTED, so go_* and process_* metrics fill the first
		// kilobytes and node_* appears later — a 4 KiB head missed it on real
		// hardware. Half a megabyte bounds the read and covers any exporter.
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
		resp.Body.Close()
		if resp.StatusCode == http.StatusOK && strings.Contains(string(body), "node_") {
			return nil
		}
		lastErr = fmt.Errorf("node exporter answered %d without node_ metrics", resp.StatusCode)
	}
	return lastErr
}

// --- unattended_upgrades: security patching ------------------------------

const unattendedUpgradesConfPath = "/etc/apt/apt.conf.d/60orchestrator-unattended"

func (h *CommandHandler) applyUnattendedUpgradesUtility(params map[string]interface{}) error {
	if err := aptInstallIfAbsent("unattended-upgrades"); err != nil {
		return err
	}
	interval := paramInt(params, "update_interval_days", 1, 1, 7)
	securityOnly := paramBool(params, "security_only", true)
	removeUnused := paramBool(params, "remove_unused_deps", true)

	var b strings.Builder
	b.WriteString("// Managed by orchestrator (utility: unattended_upgrades)\n")
	fmt.Fprintf(&b, "APT::Periodic::Update-Package-Lists \"%d\";\n", interval)
	fmt.Fprintf(&b, "APT::Periodic::Unattended-Upgrade \"%d\";\n", interval)
	// Hardcoded, not a param: nothing reboots a device without a human
	// present — the platform doctrine, restated where an operator will read it.
	b.WriteString("Unattended-Upgrade::Automatic-Reboot \"false\";\n")
	fmt.Fprintf(&b, "Unattended-Upgrade::Remove-Unused-Dependencies \"%t\";\n", removeUnused)
	if !securityOnly {
		b.WriteString("Unattended-Upgrade::Allowed-Origins {\n")
		b.WriteString("\t\"${distro_id}:${distro_codename}-security\";\n")
		b.WriteString("\t\"${distro_id}:${distro_codename}-updates\";\n")
		b.WriteString("};\n")
	}
	if _, err := writeIfChanged(unattendedUpgradesConfPath, []byte(b.String()), 0o644); err != nil {
		return fmt.Errorf("failed to write the unattended-upgrades config: %w", err)
	}
	for _, timer := range []string{"apt-daily.timer", "apt-daily-upgrade.timer"} {
		if out, err := runWithEnv(nil, softwareCmdTimeout, "systemctl", "enable", "--now", timer); err != nil {
			return fmt.Errorf("failed to enable %s: %v: %s", timer, err, truncateOutput(out))
		}
	}
	// Verify against the RENDERED value, not a literal "1" — an interval of 3
	// renders 3, and a verify hardwired to 1 would permanently redden a valid
	// config.
	out, err := runWithEnv(nil, softwareCmdTimeout, "apt-config", "dump", "APT::Periodic::Unattended-Upgrade")
	if err != nil || !strings.Contains(out, fmt.Sprintf("\"%d\"", interval)) {
		return fmt.Errorf("apt-config does not report the rendered interval %d: %s", interval, truncateOutput(out))
	}
	return nil
}

// --- kiosk: fullscreen browser container on the docker utility -----------

const kioskContainerName = "orchestrator-kiosk"

func (h *CommandHandler) applyKioskUtility(params map[string]interface{}) error {
	url := paramStr(params, "url", "")
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		return fmt.Errorf("kiosk url must be http(s), got %q", url)
	}
	// No fallback image on purpose: a pinned default image is not
	// pullable anonymously by every device, so defaulting here would turn a
	// missing param into a pull failure. The platform refuses to
	// dispatch an imageless kiosk config; this covers an older backend.
	image := paramStr(params, "image", "")
	if image == "" {
		return fmt.Errorf("kiosk: no container image configured — set the image param on the assignment (the device pulls anonymously, so it must be public or already loaded)")
	}
	headless := paramBool(params, "headless", false)

	// depends_on: docker is implied platform-side into every SET that holds
	// kiosk and applied before it; this is the device-side truth check (the
	// platform cannot see a node where dockerd broke after the docker
	// utility converged).
	if out, err := runWithEnv(nil, softwareCmdTimeout, "systemctl", "is-active", "docker"); strings.TrimSpace(out) != "active" || err != nil {
		return fmt.Errorf("the kiosk utility needs the docker utility applied and dockerd active")
	}

	// Converged? Compare the running container's image and env against the
	// desired ones — the writeIfChanged idea applied to a container, so a
	// re-apply of the same config never flickers the screen.
	inspect, err := runWithEnv(nil, softwareCmdTimeout, "docker", "inspect",
		"--format", "{{.State.Running}}|{{.Config.Image}}|{{range .Config.Env}}{{.}},{{end}}", kioskContainerName)
	if err == nil {
		parts := strings.SplitN(strings.TrimSpace(inspect), "|", 3)
		if len(parts) == 3 && parts[0] == "true" && parts[1] == image &&
			strings.Contains(parts[2], "KIOSK_URL="+url+",") &&
			strings.Contains(parts[2], "KIOSK_HEADLESS_WLR="+headlessEnvValue(headless)+",") {
			return h.verifyKioskContainer()
		}
	}

	// Pull only when the image is absent locally: a hand-loaded image (test
	// benches, air-gapped sites) must not be re-fetched over it.
	if _, err := runWithEnv(nil, softwareCmdTimeout, "docker", "image", "inspect", "--format", "ok", image); err != nil {
		if out, err := runWithEnv(nil, softwareCmdTimeout, "docker", "pull", image); err != nil {
			return fmt.Errorf("failed to pull the kiosk image %s: %v: %s", image, err, truncateOutput(out))
		}
	}

	_, _ = runWithEnv(nil, softwareCmdTimeout, "docker", "rm", "-f", kioskContainerName)
	runArgs := []string{
		"run", "-d", "--name", kioskContainerName,
		"--restart", "unless-stopped",
		"--device", "/dev/dri",
		"--shm-size", "512m",
		"--security-opt", "no-new-privileges=true",
		"-e", "KIOSK_URL=" + url,
		"-e", "KIOSK_HEADLESS_WLR=" + headlessEnvValue(headless),
	}
	if headless {
		runArgs = append(runArgs, "-e", "WLR_BACKENDS=headless")
	}
	// /dev/input is deliberately NOT passed: withholding it IS the input
	// lockdown. A future touchscreen kiosk adds an explicit opt-in param —
	// it must never come back as a "fix".
	runArgs = append(runArgs, image)
	if out, err := runWithEnv(nil, softwareCmdTimeout, "docker", runArgs...); err != nil {
		return fmt.Errorf("failed to start the kiosk container: %v: %s", err, truncateOutput(out))
	}
	time.Sleep(3 * time.Second)
	return h.verifyKioskContainer()
}

// headlessEnvValue keeps the env marker comparable in the convergence check.
func headlessEnvValue(headless bool) string {
	if headless {
		return "1"
	}
	return "0"
}

// verifyKioskContainer asks two questions: is the container running, and did
// chromium come up (DevTools answers inside the container's own netns — the
// port is never on the LAN). A compositor crash-loop fails here, not at some
// later scan.
func (h *CommandHandler) verifyKioskContainer() error {
	out, err := runWithEnv(nil, softwareCmdTimeout, "docker", "inspect", "--format", "{{.State.Running}}", kioskContainerName)
	if err != nil || strings.TrimSpace(out) != "true" {
		return fmt.Errorf("the kiosk container is not running: %s", truncateOutput(out))
	}
	// Chromium needs a few seconds on first boot; retry briefly rather than
	// fail an honest slow start.
	var probeErr error
	for i := 0; i < 5; i++ {
		probe, err := runWithEnv(nil, softwareCmdTimeout, "docker", "exec", kioskContainerName,
			"curl", "-s", "-m", "5", "http://127.0.0.1:9222/json/version")
		if err == nil && strings.Contains(probe, "Chrome") {
			return nil
		}
		probeErr = fmt.Errorf("chromium DevTools did not answer: %s", truncateOutput(probe))
		time.Sleep(3 * time.Second)
	}
	return probeErr
}
