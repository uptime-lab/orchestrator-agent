//go:build linux

package handlers

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	proto "agent/pkg/infrastructure/grpc/proto"
	"agent/pkg/infrastructure/hardware"
)

// bootPrefix is the mount point the installed system uses for the FAT boot
// partition. A path under it lives on that partition, NOT on the root — which
// is the whole reason this command cannot simply mount the root and write.
const bootPrefix = "/boot/firmware/"

// offlinePatchMountPoint is deliberately distinct from the offline access
// apply's, so a stuck mount from one command cannot be mistaken for the other's.
const offlinePatchMountPoint = "/mnt/tmp-patch-offline"

// handlePatchFileOffline edits a file on the node's INSTALLED system while the
// node runs the recovery bootstrap.
//
// This exists because the state in which an operator most needs to edit
// /boot/firmware/config.txt — a node whose installed OS will not boot — is
// exactly the state in which the live patch_file cannot reach it: from the
// initramfs that path is the BOOTSTRAP's own boot partition, so a "successful"
// patch edits the wrong file and evaporates on the next boot.
func (h *CommandHandler) handlePatchFileOffline(commandID string, cmd *proto.PatchFileOfflineCommand) error {
	path := strings.TrimSpace(cmd.GetPath())
	if path == "" {
		path = "/boot/firmware/config.txt"
	}
	marker := cmd.GetMarker()
	if marker == "" {
		marker = DefaultPatchMarker
	}

	fail := func(format string, args ...interface{}) error {
		msg := fmt.Sprintf(format, args...)
		h.logger.Error("offline patch failed", "command_id", commandID, "path", path, "error", msg)
		h.reportCommandStatus(commandID, "failed", 0, msg)
		return fmt.Errorf("%s", msg)
	}

	h.logger.Info("offline patch file command received",
		"command_id", commandID, "path", path, "marker", marker,
		"target_device", cmd.GetTargetDevice())

	// Recovery-only, with the same polarity and for the same reason as the
	// offline access apply: on a live system the ordinary patch_file owns the
	// case, and "mount another disk and write into it" from a running root is
	// the shape of mistake that rewrites the machine you are standing on.
	if !hardware.RootIsEphemeral() {
		return fail("patch_file_offline must run from the netboot recovery bootstrap; use patch_file on an installed OS")
	}
	if !filepath.IsAbs(path) {
		return fail("path must be absolute, as the installed system sees it")
	}

	targetDevice := strings.TrimSpace(cmd.GetTargetDevice())
	if targetDevice == "" {
		return fail("target_device is required")
	}
	if _, err := os.Stat(targetDevice); err != nil {
		return fail("target device %s not found: %v", targetDevice, err)
	}

	// Which partition holds this path is DERIVED from the path, never asked
	// for: mounting the root for a /boot/firmware path would give an empty
	// directory and a write the firmware never reads.
	onBoot := strings.HasPrefix(path, bootPrefix)
	var partition string
	if onBoot {
		p, _, err := h.detectBootPartition(targetDevice)
		if err != nil {
			return fail("could not find the FAT boot partition on %s: %v", targetDevice, err)
		}
		partition = p
	} else if n := cmd.GetRootPartition(); n > 0 {
		partition = getPartitionPath(targetDevice, int(n))
	} else {
		p, err := h.captureDetectRootPartition(commandID, targetDevice)
		if err != nil {
			return fail("could not detect a Linux root partition on %s: %v", targetDevice, err)
		}
		partition = p.path
	}

	h.reportCommandStatus(commandID, "in_progress", 10, fmt.Sprintf("Mounting %s", partition))
	if err := os.MkdirAll(offlinePatchMountPoint, 0755); err != nil {
		return fail("failed to create mount point: %v", err)
	}
	mountCmd := exec.Command("mount", partition, offlinePatchMountPoint)
	var mountStderr bytes.Buffer
	mountCmd.Stderr = &mountStderr
	if err := mountCmd.Run(); err != nil {
		// A LUKS/encrypted root fails cleanly HERE; this command carries no
		// unlocking machinery, deliberately.
		return fail("failed to mount %s: %v (stderr: %s)", partition, err,
			strings.TrimSpace(mountStderr.String()))
	}
	defer func() {
		if err := exec.Command("umount", offlinePatchMountPoint).Run(); err != nil {
			h.logger.Warn("failed to unmount target after offline patch",
				"mount_point", offlinePatchMountPoint, "error", err)
		}
		if err := os.Remove(offlinePatchMountPoint); err != nil {
			h.logger.Warn("failed to remove mount point", "mount_point", offlinePatchMountPoint, "error", err)
		}
	}()

	// Never operate on the filesystem this agent is running from.
	if same, err := sameFilesystem(offlinePatchMountPoint, "/"); err == nil && same {
		return fail("refusing offline patch: the target partition IS the live root filesystem")
	}

	// Cheap proof we mounted what we think we mounted, so a data disk fails
	// here with a sentence rather than three steps later with a stat error.
	if onBoot {
		if _, err := os.Stat(filepath.Join(offlinePatchMountPoint, "config.txt")); err != nil {
			return fail("%s does not look like a Raspberry Pi boot partition (no config.txt)", partition)
		}
	} else if _, err := os.Stat(filepath.Join(offlinePatchMountPoint, "etc", "passwd")); err != nil {
		return fail("%s does not look like a Linux root filesystem (no etc/passwd)", partition)
	}

	targetPath, err := h.resolveOfflinePath(offlinePatchMountPoint, path, onBoot)
	if err != nil {
		return fail("%v", err)
	}

	h.reportCommandStatus(commandID, "in_progress", 30,
		fmt.Sprintf("Patching %s on the installed system (block '%s')", path, marker))
	perr := h.patchManagedBlockAtPath(commandID, targetPath, cmd.GetContent(), marker)
	// Push it to the disk before the deferred unmount: the entire point of this
	// command is what the NEXT boot finds there.
	syscall.Sync()
	return perr
}

// resolveOfflinePath maps a path as the INSTALLED system sees it onto the
// mounted partition, and refuses anything that leaves the mount.
//
// The containment check is not ceremony. The target filesystem is the one this
// command exists to repair, so it is exactly the filesystem that may be strange
// — and a symlink inside it (/etc/hosts -> ../../../etc/hosts) would otherwise
// have the root agent write into the RUNNING initramfs instead. Directories are
// resolved rather than the file itself, because the file may legitimately be a
// symlink WITHIN the target.
func (h *CommandHandler) resolveOfflinePath(mountPoint, path string, onBoot bool) (string, error) {
	rel := strings.TrimPrefix(path, "/")
	if onBoot {
		rel = strings.TrimPrefix(path, bootPrefix)
	}
	joined := filepath.Join(mountPoint, rel)

	dir, err := filepath.EvalSymlinks(filepath.Dir(joined))
	if err != nil {
		return "", fmt.Errorf("%s does not exist on the installed system: %v", path, err)
	}
	root, err := filepath.EvalSymlinks(mountPoint)
	if err != nil {
		return "", fmt.Errorf("failed to resolve the mount point: %v", err)
	}
	if dir != root && !strings.HasPrefix(dir, root+string(os.PathSeparator)) {
		return "", fmt.Errorf("refusing to follow %s outside the mounted target filesystem", path)
	}
	return filepath.Join(dir, filepath.Base(joined)), nil
}
