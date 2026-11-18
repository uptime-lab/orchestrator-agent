//go:build linux

package handlers

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"

	"agent/pkg/infrastructure/hardware"
)

// deviceProbeReadBytes is how much of the device start the probe reads. 4096
// rather than 512 on purpose: a 4Kn device rejects a sub-sector read with
// EINVAL, and a healthy disk must never be reported as dead by the check that
// only exists to explain a dead one.
const deviceProbeReadBytes = 4096

// deviceProbeVerdict is what a read of the device start established.
type deviceProbeVerdict int

const (
	// deviceProbeOK — the device answered.
	deviceProbeOK deviceProbeVerdict = iota
	// deviceProbeNotResponding — the device node exists and the hardware is
	// answering nothing. This is the only verdict that refuses a command.
	deviceProbeNotResponding
	// deviceProbeInconclusive — the read failed for a reason that says nothing
	// about the device's health (permissions, O_EXCL contention, an unexpected
	// errno). Deliberately NOT a refusal: this probe is a diagnostic, and a
	// diagnostic that invents its own failure mode is worse than no diagnostic.
	deviceProbeInconclusive
)

// classifyDeviceProbeError maps a read error on a block device to a verdict.
// Pure, so the errno table is testable without wedged hardware.
//
// The errnos that mean "not answering" were taken from a measured failure:
// a USB disk behind a browned-out board returned ENXIO to
// `dd if=/dev/sda bs=512 count=1`, to blkid and to wipefs, after
// uas_eh_device_reset_handler cycles and "I/O error, dev sda, sector 0".
func classifyDeviceProbeError(err error) deviceProbeVerdict {
	if err == nil {
		return deviceProbeOK
	}
	switch {
	case errors.Is(err, syscall.ENXIO), // no such device or address — the UAS case
		errors.Is(err, syscall.ENODEV),    // device gone from under us
		errors.Is(err, syscall.EIO),       // transport reported an I/O error
		errors.Is(err, syscall.ENOMEDIUM), // slot present, no medium
		errors.Is(err, syscall.EREMOTEIO),
		errors.Is(err, io.ErrUnexpectedEOF): // answered, then stopped mid-sector
		return deviceProbeNotResponding
	}
	return deviceProbeInconclusive
}

// probeDeviceResponds reads the start of devicePath to establish that the
// hardware answers at all. os.Stat cannot substitute: the device node survives
// the transport dying, so every caller that only stats gets a "yes" from a disk
// that will fail the moment it is written.
func probeDeviceResponds(devicePath string) (deviceProbeVerdict, error) {
	f, err := os.OpenFile(devicePath, os.O_RDONLY, 0)
	if err != nil {
		return classifyDeviceProbeError(err), err
	}
	defer func() { _ = f.Close() }()

	buf := make([]byte, deviceProbeReadBytes)
	if _, err := io.ReadFull(f, buf); err != nil {
		return classifyDeviceProbeError(err), err
	}
	return deviceProbeOK, nil
}

// deviceTransportLabel names the bus devicePath hangs off, for an
// operator-facing message, or "" when it cannot tell. Best-effort: it only
// decorates text. The classification itself lives in the hardware package,
// because the storage reader needs the same answer to tell a USB stick from an
// internal disk — two copies of a sysfs-path rule would drift.
func deviceTransportLabel(devicePath string) string {
	name := strings.TrimPrefix(devicePath, "/dev/")
	return hardware.DeviceTransportLabel(hardware.DeviceTransport("/sys/block", name))
}

// checkDeviceResponds returns a descriptive error when devicePath is present but
// answering nothing, and nil otherwise (including when the probe is
// inconclusive).
//
// The message is the whole point of the check. `wipefs` on a wedged disk reports
// "probing initialization failed: No such device or address", which reads as a
// platform bug and sent an operator looking at the disk. Naming the transport
// and the power hypothesis moves the search to where the cause actually was —
// though only the firmware's throttling facts can confirm it, so this deliberately
// suggests rather than concludes.
func (h *CommandHandler) checkDeviceResponds(devicePath string) error {
	verdict, probeErr := probeDeviceResponds(devicePath)
	switch verdict {
	case deviceProbeOK:
		return nil
	case deviceProbeInconclusive:
		h.logger.Warn("device read probe was inconclusive; continuing",
			"device", devicePath, "error", probeErr)
		return nil
	}

	transport := ""
	if t := deviceTransportLabel(devicePath); t != "" {
		transport = fmt.Sprintf(" (%s transport)", t)
	}
	return fmt.Errorf("device %s is not responding%s: reading its first sector failed with %v. "+
		"The device node exists but the hardware answered nothing, so no erase or install can succeed. "+
		"On a Raspberry Pi the usual cause is power rather than the disk — an under-powered supply or a "+
		"computer's USB port browns the board out and resets the bus. Check the supply and cable, "+
		"power-cycle the node, and look at the node's power facts before replacing the disk",
		devicePath, transport, probeErr)
}
