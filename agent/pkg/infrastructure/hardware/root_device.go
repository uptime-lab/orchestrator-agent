package hardware

import (
	"bufio"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// RootDevice returns the whole-disk device the running system booted from
// (e.g. "/dev/nvme0n1"), or "" when there is none to name.
//
// Why the platform needs it: the only signal it had was `current_boot_device`,
// a CLASS from the ROM's boot-mode byte (`sd`, `usb_msd`, `nvme`…). A class
// cannot pick between two devices of the same kind — eMMC plus an inserted SD
// card are both `mmcblk*` — which is exactly the ambiguity that makes an
// operator wipe the wrong medium, so the UI marks nothing there rather than
// guess. This makes the marker a fact.
//
// **"" is a correct and common answer.** In the recovery bootstrap the root is
// RAM, so no local device booted this node, and saying so is the point: marking
// the disk that merely holds an installed OS would mislead precisely the
// operator most likely to act on it.
//
// Deliberately NOT built with a `//go:build linux` tag even though /proc and
// /sys are Linux: everything here is pure path and string work over roots the
// caller supplies, so the parsing is testable on any machine. The agent's own
// tests are otherwise linux-tagged and cannot run on the development host at
// all, which is how untested parsing gets shipped.
func RootDevice() string {
	f, err := os.Open("/proc/mounts")
	if err != nil {
		return ""
	}
	defer func() { _ = f.Close() }()
	return resolveRootDevice(f, "/sys/class/block")
}

// resolveRootDevice finds the mount at "/" and reduces its source to the whole
// disk. mounts is /proc/mounts content; sysClassBlock is normally
// "/sys/class/block".
func resolveRootDevice(mounts io.Reader, sysClassBlock string) string {
	source := rootMountSource(mounts)
	if source == "" {
		return ""
	}
	name := strings.TrimPrefix(source, "/dev/")
	if name == source || name == "" || strings.Contains(name, "..") {
		// Not a /dev path at all: "rootfs", "tmpfs", "overlay", "/dev/root" from
		// some initramfs — none of which names a disk this platform can offer as
		// an install target.
		return ""
	}
	if disk := wholeDiskFromSysfs(sysClassBlock, name); disk != "" {
		return "/dev/" + disk
	}
	return "/dev/" + wholeDiskFromName(name)
}

// rootMountSource returns the device backing "/", or "" when the root is not a
// block device.
//
// Later mounts win: / can be mounted more than once (an initramfs pivot leaves
// the earlier one visible), and the last entry is what is actually in effect.
func rootMountSource(mounts io.Reader) string {
	source := ""
	scanner := bufio.NewScanner(mounts)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 3 || fields[1] != "/" {
			continue
		}
		switch fields[2] {
		case "rootfs", "ramfs", "tmpfs", "overlay", "aufs", "squashfs":
			// A RAM-backed or stacked root — the recovery bootstrap's case. No
			// local device booted this node.
			source = ""
		default:
			source = fields[0]
		}
	}
	return source
}

// wholeDiskFromSysfs reduces a partition name to its disk by asking sysfs,
// which knows the answer without any naming convention.
//
// /sys/class/block/<part> is a symlink into the device tree, where a partition
// sits INSIDE its disk's directory (…/block/nvme0n1/nvme0n1p2). So the parent
// directory's name is the disk — unless the entry is already a whole disk, in
// which case the parent is the controller and this returns "".
func wholeDiskFromSysfs(sysClassBlock, name string) string {
	resolved, err := filepath.EvalSymlinks(filepath.Join(sysClassBlock, name))
	if err != nil {
		return ""
	}
	// A partition carries a `partition` file; a whole disk does not. Checking
	// this rather than inferring from the parent's name is what keeps a disk
	// whose controller happens to be named like a device from being "reduced"
	// to the controller.
	if _, err := os.Stat(filepath.Join(resolved, "partition")); err != nil {
		return name
	}
	parent := filepath.Base(filepath.Dir(resolved))
	if parent == "" || parent == "." || parent == string(filepath.Separator) {
		return ""
	}
	return parent
}

// wholeDiskFromName strips a partition suffix by convention, for when sysfs
// cannot answer (a container, a test, an unusual initramfs).
//
// Two families, and they must not be collapsed — the first version of this
// collapsed them and the test caught it immediately. Devices whose DISK name
// ends in a digit separate the partition with "p" (nvme0n1p2 → nvme0n1,
// mmcblk0p1 → mmcblk0); devices whose disk name is letters only just append the
// number (sda2 → sda). Stripping trailing digits from the first family invents
// hardware: "mmcblk0" would become "mmcblk" and "nvme0n1" would become
// "nvme0n", neither of which exists.
//
// Anything unrecognised is returned unchanged. Naming a disk that does not exist
// is strictly worse than naming nothing, because the UI would mark a device the
// operator cannot find.
func wholeDiskFromName(name string) string {
	if i := strings.LastIndex(name, "p"); i > 0 && allDigits(name[i+1:]) && isDigit(name[i-1]) {
		return name[:i]
	}
	for _, prefix := range []string{"sd", "hd", "vd", "xvd"} {
		if !strings.HasPrefix(name, prefix) {
			continue
		}
		end := len(name)
		for end > 0 && isDigit(name[end-1]) {
			end--
		}
		if end > 0 {
			return name[:end]
		}
	}
	return name
}

func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !isDigit(s[i]) {
			return false
		}
	}
	return true
}

func isDigit(b byte) bool { return b >= '0' && b <= '9' }
