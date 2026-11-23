//go:build linux

package handlers

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"agent/pkg/infrastructure/hardware"
)

// releaseBootMediaMounts unmounts what the RECOVERY BOOTSTRAP holds on
// devicePath, so the device can be erased or written.
//
// Why this is needed at all: the bootstrap mounts the provisioning card at
// /mnt/sdcard to read (and, after the identity handoff, write) the adoption
// file, and it keeps that mount for the life of the session. Linux refuses an
// O_EXCL open of a whole-disk node while any of its partitions is mounted, so
// `wipefs -a /dev/mmcblk0` fails with "probing initialization failed: Device or
// resource busy" and install_os is refused by its own mounted-device guard.
// The result was that a Pi 4 or Pi 5 with no NVMe — where the SD card is both
// the provisioning medium and the only install target — could not be installed
// to at all, and the error named a busy device without saying what held it.
//
// Deliberately gated on the root filesystem being RAM-backed, i.e. on running
// inside the netboot bootstrap. On an installed OS a mounted partition on the
// target disk means something real is using it, and the right answer there is
// still to refuse; nothing about this path should make it easier to erase a
// disk out from under a running system.
//
// Returns the mount points released, for the caller to report, the subset
// that could only be detached lazily, and restore, which mounts what was
// released back as it was. A caller whose command is then refused before
// anything is written calls restore: the bootstrap reads and writes the
// adoption file through the card's mount, and with the mount gone an identity
// release would remove nothing from the card while reporting success.
func (h *CommandHandler) releaseBootMediaMounts(devicePath string) (released, lazy []string, restore func(), err error) {
	restore = func() {}
	if !hardware.RootIsEphemeral() {
		return nil, nil, restore, nil
	}

	f, err := os.Open("/proc/mounts")
	if err != nil {
		return nil, nil, restore, fmt.Errorf("cannot read /proc/mounts: %w", err)
	}
	mounts := mountsForDevice(f, devicePath)
	_ = f.Close()
	if len(mounts) == 0 {
		return nil, nil, restore, nil
	}

	var detached []deviceMount
	restore = func() {
		for _, m := range detached {
			if isMountPoint(m.MountPoint) {
				continue
			}
			if out, merr := exec.Command("mount", remountArgs(m)...).CombinedOutput(); merr != nil {
				h.logger.Warn("could not restore a recovery-bootstrap mount after a refused command",
					"device", devicePath, "mount_point", m.MountPoint, "source", m.Source,
					"error", merr, "output", strings.TrimSpace(string(out)))
				continue
			}
			h.logger.Info("restored a recovery-bootstrap mount after a refused command",
				"device", devicePath, "mount_point", m.MountPoint, "source", m.Source)
		}
	}

	var failures []string
	for _, m := range mounts {
		if out, uerr := exec.Command("umount", m.MountPoint).CombinedOutput(); uerr != nil {
			// Reached when something outside the agent still holds a file or a
			// working directory on the card (a recovery web-terminal shell cd'd
			// into the mount, for example). A lazy unmount detaches the tree
			// from /proc/mounts at once, but the filesystem — and its exclusive
			// claim on the partition — lives until that last reference closes,
			// so the O_EXCL probe that follows is still refused. That refusal
			// is right: writing an image under a live filesystem lets its final
			// flush corrupt the new image. The caller names the lazy detach,
			// because nothing in /proc/mounts shows it any more.
			if out2, lerr := exec.Command("umount", "-l", m.MountPoint).CombinedOutput(); lerr != nil {
				failures = append(failures, fmt.Sprintf("%s: %s", m.MountPoint,
					strings.TrimSpace(string(out2))))
				h.logger.Warn("could not release a mount on the target device",
					"device", devicePath, "mount_point", m.MountPoint,
					"error", lerr, "output", strings.TrimSpace(string(out)))
				continue
			}
			lazy = append(lazy, m.MountPoint)
		}
		released = append(released, m.MountPoint)
		detached = append(detached, m)
		h.logger.Info("released a recovery-bootstrap mount on the target device",
			"device", devicePath, "mount_point", m.MountPoint, "source", m.Source)
	}

	if len(failures) > 0 {
		return released, lazy, restore, fmt.Errorf("could not release %s", strings.Join(failures, "; "))
	}
	return released, lazy, restore, nil
}
