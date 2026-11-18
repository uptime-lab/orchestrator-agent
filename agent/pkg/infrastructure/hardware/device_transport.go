//go:build linux

package hardware

import (
	"path/filepath"
	"strings"
)

// DeviceTransportFromSysPath names the bus a block device hangs off, given the
// RESOLVED /sys path of its /sys/block entry (e.g. the target of the
// /sys/block/sda symlink). Returns "" when it cannot tell.
//
// Pure and string-only so the classification is testable against real sysfs
// paths without the hardware.
//
// Prefer this over queue/rotational for deciding what a device IS. A UAS bridge
// is free to report rotational=1 for flash, and one does: the SanDisk USB stick
// on one node was labelled "57GB SanDisk 3.2Gen1 HDD" for exactly that
// reason.
func DeviceTransportFromSysPath(resolved string) string {
	switch {
	case strings.Contains(resolved, "/usb"):
		return "usb"
	case strings.Contains(resolved, "/nvme"):
		return "nvme"
	case strings.Contains(resolved, "/mmc_host/"):
		return "mmc"
	case strings.Contains(resolved, "/virtio"):
		return "virtio"
	default:
		return ""
	}
}

// DeviceTransport resolves a block device's sysfs entry and names its bus, or
// "" when it cannot tell. sysBlockDir is normally "/sys/block"; it is a
// parameter so tests can point at a tree they built.
func DeviceTransport(sysBlockDir, deviceName string) string {
	if deviceName == "" || strings.Contains(deviceName, "/") {
		return ""
	}
	resolved, err := filepath.EvalSymlinks(filepath.Join(sysBlockDir, deviceName))
	if err != nil {
		return ""
	}
	return DeviceTransportFromSysPath(resolved)
}

// DeviceTransportLabel renders a transport for an operator-facing message.
func DeviceTransportLabel(transport string) string {
	switch transport {
	case "usb":
		return "USB"
	case "nvme":
		return "NVMe"
	case "mmc":
		return "SD/eMMC"
	case "virtio":
		return "virtio"
	default:
		return ""
	}
}
