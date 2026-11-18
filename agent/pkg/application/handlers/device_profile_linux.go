//go:build linux

package handlers

import (
	"fmt"
	"os"
	"strings"
	"time"

	proto "agent/pkg/infrastructure/grpc/proto"
)

// handleApplyDeviceProfile applies the platform-rendered device-profile block
// to config.txt and runs the equipage's typed setup steps — ONE command, one
// terminal status, so the platform's applied-hash ladder settles from a single
// report. Deliberately not patch_file + run_script (opposite queueability
// would let half an apply land on an offline node).
func (h *CommandHandler) handleApplyDeviceProfile(commandID string, cmd *proto.ApplyDeviceProfileCommand) error {
	path := cmd.Path
	marker := cmd.Marker
	if path == "" || marker == "" {
		msg := "path and marker are required"
		h.reportCommandStatus(commandID, "failed", 0, msg)
		return fmt.Errorf("%s", msg)
	}
	// The only file this command exists for is the boot config. Refusing
	// everything else is defence in depth: the platform never sends another
	// path, so any other value means a confused or hostile dispatcher.
	if !isPlatformConfigPath(path) {
		msg := fmt.Sprintf("apply_device_profile only patches the boot config, not %s", path)
		h.reportCommandStatus(commandID, "failed", 0, msg)
		return fmt.Errorf("%s", msg)
	}

	h.reportCommandStatus(commandID, "in_progress", 10, "applying device profile")

	info, err := os.Stat(path)
	if err != nil {
		msg := fmt.Sprintf("cannot stat %s: %v", path, err)
		h.reportCommandStatus(commandID, "failed", 0, msg)
		return fmt.Errorf("%s", msg)
	}
	current, meta, err := readFileBounded(path, DefaultReadMaxBytes)
	if err != nil {
		msg := fmt.Sprintf("cannot read %s: %v", path, err)
		h.reportCommandStatus(commandID, "failed", 0, msg)
		return fmt.Errorf("%s", msg)
	}
	if meta["truncated"] == "true" || meta["binary"] == "true" {
		msg := fmt.Sprintf("%s is not a patchable text file", path)
		h.reportCommandStatus(commandID, "failed", 0, msg)
		return fmt.Errorf("%s", msg)
	}

	patched, err := patchManagedBlock([]byte(current), cmd.Content, marker)
	if err != nil {
		msg := fmt.Sprintf("cannot patch managed block: %v", err)
		h.reportCommandStatus(commandID, "failed", 0, msg)
		return fmt.Errorf("%s", msg)
	}
	if string(patched) != current {
		if err := backupOnce(path); err != nil {
			h.logger.Warn("device profile: backup failed, continuing", "path", path, "error", err)
		}
		if err := atomicWriteFile(path, patched, info.Mode().Perm()); err != nil {
			msg := fmt.Sprintf("cannot write %s: %v", path, err)
			h.reportCommandStatus(commandID, "failed", 0, msg)
			return fmt.Errorf("%s", msg)
		}
	}

	// Typed setup steps. An unknown kind FAILS the command rather than being
	// skipped: a platform registry entry the agent does not implement must
	// surface as a version mismatch, not as silently missing configuration.
	for i, kind := range cmd.SetupKinds {
		h.reportCommandStatus(commandID, "in_progress",
			int32(50+40*i/max(1, len(cmd.SetupKinds))), "setup: "+kind)
		var stepErr error
		switch kind {
		case "rtc_hwclock":
			stepErr = h.applyRTCHwclockSetup()
		default:
			stepErr = fmt.Errorf("setup kind %q is not implemented by this agent", kind)
		}
		if stepErr != nil {
			msg := fmt.Sprintf("setup step %s failed: %v", kind, stepErr)
			h.reportCommandResult(commandID, "failed", msg, nil)
			return fmt.Errorf("%s", msg)
		}
	}

	// Button desired state: persisted locally (survives restarts) and the
	// watcher re-armed live. Best-effort — a button that fails to arm must not
	// fail the config apply that carried it; the warning names the remedy.
	if err := persistButtonState(buttonState{
		ButtonGPIO:          int(cmd.ButtonGpio),
		IdentifyBackend:     cmd.IdentifyBackend,
		IdentifyGPIO:        int(cmd.IdentifyGpio),
		IdentifyColor:       cmd.IdentifyColor,
		IdentifyDurationSec: int(cmd.IdentifyDurationSec),
	}); err != nil {
		h.logger.Warn("device profile: cannot persist button state", "error", err)
	}
	if h.buttonReconfigure != nil {
		h.buttonReconfigure(int(cmd.ButtonGpio))
	}

	// Echo the platform's content hash so the settle records exactly what was
	// dispatched (the payload is the source of truth either way).
	h.reportCommandResult(commandID, "success", "device profile applied; reboot required for overlay changes",
		map[string]string{"applied_hash": cmd.ContentHash})
	return nil
}

// applyRTCHwclockSetup makes the OS trust a hardware RTC. Idempotent:
//   - fake-hwclock (present on Raspberry Pi OS images) saves/restores a FAKE
//     time across boots and fights a real RTC — disable it where it exists;
//     its absence is fine, not an error.
//   - /lib/udev/hwclock-set is the udev hook that runs when an RTC appears;
//     stock Raspberry Pi OS ships it calling --systz (kernel timezone only)
//     and gated on fake-hwclock's presence. Switch --systz to --hctosys so
//     the system clock is actually SET from the RTC. Absent file = modern
//     systemd distro that reads the RTC itself = nothing to do.
//   - seed the module itself, which is the half that was missing: on Ubuntu
//     both steps above are no-ops (measured — neither fake-hwclock nor the udev
//     hook is installed), so before this the apply left a brand-new module
//     holding 2000-01-01 and the next boot set the system clock to it.
//
// The seed is best-effort HERE on purpose: the overlay this same command just
// wrote to config.txt only takes effect on the reboot it asks for, so on a
// first apply there is no /dev/rtc* to write yet. StartRTCKeeper is what
// catches that boot; this call is what makes a RE-apply (a swapped module, a
// replaced battery) take effect without waiting for one.
func (h *CommandHandler) applyRTCHwclockSetup() error {
	if err := trustHardwareClock(); err != nil {
		return err
	}
	// After every success path, not only the one that patched the udev hook:
	// on Ubuntu neither of those steps has anything to do, so hanging the seed
	// off one of their early returns is the same as not seeding at all.
	h.seedRTCIfPresent()
	return nil
}

func trustHardwareClock() error {
	if out, err := runWithEnv(nil, 30*time.Second, "systemctl", "disable", "--now", "fake-hwclock.service"); err != nil {
		low := strings.ToLower(out + " " + err.Error())
		if !strings.Contains(low, "does not exist") && !strings.Contains(low, "not-found") &&
			!strings.Contains(low, "not loaded") && !strings.Contains(low, "no such file") {
			return fmt.Errorf("disabling fake-hwclock: %v (%s)", err, strings.TrimSpace(out))
		}
	}

	const hookPath = "/lib/udev/hwclock-set"
	raw, err := os.ReadFile(hookPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("reading %s: %w", hookPath, err)
	}
	content := string(raw)
	updated := strings.ReplaceAll(content, "--systz", "--hctosys")
	if updated == content {
		return nil
	}
	info, err := os.Stat(hookPath)
	if err != nil {
		return fmt.Errorf("stat %s: %w", hookPath, err)
	}
	if err := backupOnce(hookPath); err != nil {
		return fmt.Errorf("backing up %s: %w", hookPath, err)
	}
	if err := atomicWriteFile(hookPath, []byte(updated), info.Mode().Perm()); err != nil {
		return fmt.Errorf("writing %s: %w", hookPath, err)
	}
	return nil
}

// seedRTCIfPresent writes the system clock into an already-present module.
// Never fails the apply: the profile IS applied either way, and the keeper
// retries after the reboot the apply asks for.
func (h *CommandHandler) seedRTCIfPresent() {
	dev, ok := externalRTCDevice()
	if !ok {
		return
	}
	h.seedRTCOnce(dev)
}
