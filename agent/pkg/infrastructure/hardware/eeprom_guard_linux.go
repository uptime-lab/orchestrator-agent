//go:build linux

package hardware

import (
	"bufio"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// bootPartitionCandidates are the FAT boot partitions an EEPROM recovery
// package may sit on: SD/eMMC and USB (honored by the ROM) plus NVMe boot
// partitions (never honored — anything found there is dead weight).
var bootPartitionCandidates = []string{
	"/dev/mmcblk1p1", "/dev/mmcblk0p1", "/dev/sda1",
	"/dev/nvme0n1p1", "/dev/nvme1n1p1",
}

// CleanupStaleEEPROMArtifacts removes EEPROM recovery packages that must never
// be applied from every reachable boot partition:
//
//   - packages baked for a DIFFERENT device serial — a reused provisioning SD
//     card would otherwise reflash the next device it is inserted into with
//     another node's identity (per-serial HTTP_PATH + adoption token);
//   - spent packages (the ROM renames recovery.bin to RECOVERY.000 on
//     success, but the rest of the package lingers on the card);
//   - packages staged on NVMe, which the ROM never applies (dead files left
//     by an update_boot_order issued to a netbooted device without a card).
//
// Best-effort by design: it must never prevent the agent from starting.
func CleanupStaleEEPROMArtifacts(logger *slog.Logger) {
	ownSerial := (&FingerprintReader{}).harvestHardwareSerial()

	for _, dev := range bootPartitionCandidates {
		if _, err := os.Stat(dev); err != nil {
			continue
		}
		if err := withWritableMount(dev, func(dir string) error {
			return cleanupEEPROMPackageAt(logger, dev, dir, ownSerial)
		}); err != nil {
			logger.Debug("EEPROM guard: skipping boot partition", "device", dev, "error", err)
		}
	}
}

// cleanupEEPROMPackageAt inspects one mounted boot partition and removes the
// staged EEPROM package if it must not survive (see CleanupStaleEEPROMArtifacts).
func cleanupEEPROMPackageAt(logger *slog.Logger, dev, dir, ownSerial string) error {
	exists := func(name string) bool {
		_, err := os.Stat(filepath.Join(dir, name))
		return err == nil
	}
	active := exists("recovery.bin")
	spentMarker := exists("RECOVERY.000") || exists("recovery.000")
	hasImage := exists("pieeprom.upd")
	if !active && !spentMarker && !hasImage {
		return nil
	}

	var pkgSerial string
	if hasImage {
		if data, err := os.ReadFile(filepath.Join(dir, "pieeprom.upd")); err == nil {
			pkgSerial = extractEEPROMPackageSerial(data)
		}
	}

	inertMedium := strings.HasPrefix(filepath.Base(dev), "nvme")
	remove, reason := classifyEEPROMPackage(pkgSerial, ownSerial, spentMarker && !active, inertMedium)
	if !remove {
		logger.Info("EEPROM guard: leaving staged package in place",
			"device", dev, "package_serial", pkgSerial)
		return nil
	}

	var removed []string
	for _, name := range eepromPackageArtifacts {
		path := filepath.Join(dir, name)
		if _, err := os.Stat(path); err != nil {
			continue
		}
		if err := os.Remove(path); err != nil {
			logger.Warn("EEPROM guard: failed to remove artifact", "path", path, "error", err)
			continue
		}
		removed = append(removed, name)
	}
	syscall.Sync()

	foreign := pkgSerial != "" && ownSerial != "" && !strings.EqualFold(pkgSerial, ownSerial)
	if foreign && active {
		// The ROM runs recovery.bin before Linux ever starts, so if this device
		// was already booted with that card inserted, the foreign identity may
		// have been flashed — operators must re-provision this node's EEPROM.
		logger.Warn("EEPROM guard: removed a FOREIGN armed recovery package; this device's EEPROM may already carry the other node's identity — re-run Provision EEPROM",
			"device", dev, "package_serial", pkgSerial, "own_serial", ownSerial, "removed", removed)
	} else {
		logger.Info("EEPROM guard: removed stale recovery package",
			"device", dev, "reason", reason, "package_serial", pkgSerial, "removed", removed)
	}
	return nil
}

// withWritableMount runs fn with dev's filesystem mounted read-write, reusing
// an existing mount (remounted rw and restored to ro afterwards if it was ro)
// or creating a temporary vfat mount otherwise.
func withWritableMount(dev string, fn func(dir string) error) error {
	if mp, ro := currentMount(dev); mp != "" {
		if ro {
			if err := syscall.Mount("", mp, "", syscall.MS_REMOUNT, ""); err != nil {
				return fmt.Errorf("remount rw failed: %w", err)
			}
			defer func() {
				syscall.Sync()
				_ = syscall.Mount("", mp, "", syscall.MS_REMOUNT|syscall.MS_RDONLY, "")
			}()
		}
		return fn(mp)
	}

	mp, err := os.MkdirTemp("", "bootpart-")
	if err != nil {
		return err
	}
	defer os.Remove(mp)
	if err := syscall.Mount(dev, mp, "vfat", 0, ""); err != nil {
		return err
	}
	defer func() {
		syscall.Sync()
		_ = syscall.Unmount(mp, 0)
	}()
	return fn(mp)
}

// currentMount returns the first mount point of dev from /proc/mounts and
// whether it is mounted read-only.
func currentMount(dev string) (mountPoint string, readOnly bool) {
	f, err := os.Open("/proc/mounts")
	if err != nil {
		return "", false
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 4 && fields[0] == dev {
			for _, opt := range strings.Split(fields[3], ",") {
				if opt == "ro" {
					return fields[1], true
				}
			}
			return fields[1], false
		}
	}
	return "", false
}
