//go:build linux

package hardware

import (
	"bufio"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"syscall"
)

// ApplyRecoveryHostname names a netbooted (bootstrap) host
// "rpi-<serial-tail>-recovery" so recovery nodes are self-describing in DHCP
// leases, SSH prompts and the platform UI. It is a no-op on a disk-booted
// system. The netboot rootfs lives in RAM, so a runtime sethostname per boot
// is exactly the right persistence model.
func ApplyRecoveryHostname(logger *slog.Logger) {
	if !rootIsEphemeral() {
		return
	}

	serial := (&FingerprintReader{}).harvestHardwareSerial()
	tail := serial
	if len(tail) > 8 {
		tail = tail[len(tail)-8:]
	}
	name := fmt.Sprintf("rpi-%s-recovery", tail)

	if err := syscall.Sethostname([]byte(name)); err != nil {
		logger.Warn("failed to set recovery hostname", "hostname", name, "error", err)
		return
	}
	// Best-effort: keep /etc/hostname (tmpfs) in sync for tools that read it.
	if err := os.WriteFile("/etc/hostname", []byte(name+"\n"), 0o644); err != nil {
		logger.Debug("failed to write /etc/hostname", "error", err)
	}
	logger.Info("recovery hostname applied", "hostname", name)
}

// RootIsEphemeral reports whether the agent is running inside the netboot
// bootstrap (a RAM-backed root) rather than on an installed OS. Disk capture
// requires it: the target filesystem must be unmounted to be fsck'd and shrunk.
func RootIsEphemeral() bool {
	return rootIsEphemeral()
}

// rootIsEphemeral reports whether / is a RAM-backed filesystem (rootfs, ramfs
// or tmpfs) — i.e. the agent is running inside the netboot bootstrap rather
// than on an installed OS.
func rootIsEphemeral() bool {
	f, err := os.Open("/proc/mounts")
	if err != nil {
		return false
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 3 && fields[1] == "/" {
			switch fields[2] {
			case "rootfs", "ramfs", "tmpfs":
				return true
			default:
				return false
			}
		}
	}
	return false
}
