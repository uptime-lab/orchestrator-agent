package hardware

import (
	"bufio"
	"io"
	"os"
	"strings"
)

// RootPersistence reports how the root filesystem keeps writes:
//
//	"persistent" — a real block-device root; writes survive a reboot.
//	"overlay"    — an overlayfs/aufs root (overlayroot): writes land in the
//	               upper layer, which is tmpfs in every stock overlayroot
//	               setup, and evaporate at the next boot.
//	""           — /proc/mounts unreadable, or a RAM-backed recovery root
//	               (rootfs/tmpfs/ramfs/squashfs), which the recovery_bootstrap
//	               fact already covers — reporting "overlay" there would make
//	               the platform's overlay refusal fire inside recovery, where
//	               the managed-OS hold already governs.
//
// The platform refuses write-shaped dispatch on "overlay": an apply that
// evaporates while its recorded hash suppresses the re-apply is the failure
// mode this fact exists to prevent (a key revocation that reads as done is
// the worst member). Same testability rule as root_device.go: pure parsing
// over a supplied reader, no build tag.
func RootPersistence() string {
	f, err := os.Open("/proc/mounts")
	if err != nil {
		return ""
	}
	defer func() { _ = f.Close() }()
	return classifyRootPersistence(f)
}

// classifyRootPersistence reads /proc/mounts content. Later mounts win, same
// as rootMountSource: an initramfs pivot leaves the earlier "/" visible and
// the last entry is what is in effect.
func classifyRootPersistence(mounts io.Reader) string {
	fstype := ""
	scanner := bufio.NewScanner(mounts)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 3 || fields[1] != "/" {
			continue
		}
		fstype = fields[2]
	}
	switch fstype {
	case "":
		return ""
	case "overlay", "overlayfs", "aufs":
		return RootPersistenceOverlay
	case "rootfs", "ramfs", "tmpfs", "squashfs":
		// The recovery bootstrap's RAM root — recovery_bootstrap covers it.
		return ""
	default:
		return RootPersistencePersistent
	}
}

const (
	RootPersistencePersistent = "persistent"
	RootPersistenceOverlay    = "overlay"
)
