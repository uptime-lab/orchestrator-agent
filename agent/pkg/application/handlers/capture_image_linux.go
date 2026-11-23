//go:build linux

package handlers

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	proto "agent/pkg/infrastructure/grpc/proto"
	"agent/pkg/infrastructure/hardware"

	"github.com/klauspost/compress/zstd"
)

// captureMountPoint is where the target root is mounted for generalization.
const captureMountPoint = "/mnt/orchestrator-capture"

// identityBackupTar holds the source node's identity files while a generalized
// capture strips them from the mounted root; they are restored after capture.
const identityBackupTar = "/tmp/orchestrator-identity.tar"

// captureAlignment rounds the captured length up so the image ends on a tidy
// boundary past the shrunk filesystem.
const captureAlignment = 1 << 20 // 1 MiB

// captureUploadTimeout bounds the whole streamed PUT (a large disk over a slow
// link can take a while, but a black-holed connection must not wedge the agent
// command loop forever).
const captureUploadTimeout = 4 * time.Hour

// resize2fsBlocksRe parses "The filesystem ... is now 123456 (4k) blocks long."
var resize2fsBlocksRe = regexp.MustCompile(`is now (\d+) \((\d+)k\) blocks long`)

// partition is one partition of the target disk, read from sysfs (works on an
// unmounted disk, unlike the df-based storage reader).
type partition struct {
	path         string
	num          int
	startSectors int64
	sizeSectors  int64
}

// handleCaptureImage captures a disk image from the node and streams it,
// zstd-compressed, to the platform. It is the reverse of install_os and must
// run from the netboot recovery bootstrap (the target filesystem has to be
// unmounted to be checked and shrunk). generalize strips machine identity so
// the result is a reusable golden image, and the SOURCE node's identity is
// restored afterwards so it stays adopted; otherwise it is a byte-exact backup.
func (h *CommandHandler) handleCaptureImage(commandID string, cmd *proto.CaptureImageCommand) error {
	h.logger.Info("capture image command received",
		"command_id", commandID,
		"image_id", cmd.ImageId,
		"target_device", cmd.TargetDevice,
		"generalize", cmd.Generalize)

	h.reportCommandStatus(commandID, "in_progress", 0, "Starting image capture")

	if !hardware.RootIsEphemeral() {
		msg := "capture_image must run from the netboot recovery bootstrap (chain reboot-to-recovery → wait → capture); the target filesystem cannot be shrunk while it is the live root"
		h.reportCommandStatus(commandID, "failed", 0, msg)
		return fmt.Errorf("%s", msg)
	}

	targetDevice, err := captureTargetDevice(cmd.TargetDevice)
	if err != nil {
		h.reportCommandStatus(commandID, "failed", 0, err.Error())
		return err
	}
	if _, err := os.Stat(targetDevice); err != nil {
		return h.failCapture(commandID, fmt.Sprintf("target device %s not found: %v", targetDevice, err))
	}

	rootPart, err := h.captureDetectRootPartition(commandID, targetDevice)
	if err != nil {
		return h.failCapture(commandID, err.Error())
	}
	// The capture is [0, root_end); a partition starting after the root would be
	// silently dropped from the image while still listed in the captured table.
	if err := assertRootIsLastPartition(targetDevice, rootPart); err != nil {
		return h.failCapture(commandID, err.Error())
	}

	// A single ordered restore path for the SOURCE disk, run on every exit once
	// anything has been mutated. Order matters: restore the partition table
	// (partition back to full size) BEFORE growing the filesystem into it, then
	// restore the stripped identity into the full-size filesystem.
	fsShrunk := false
	tableShrunk := false
	generalized := false
	origTablePath := ""
	defer func() {
		if tableShrunk {
			if err := restorePartitionTable(targetDevice, origTablePath); err != nil {
				h.logger.Warn("failed to restore source partition table after capture", "device", targetDevice, "error", err)
			}
			_ = os.Remove(origTablePath)
		}
		if fsShrunk {
			if err := runCmd("resize2fs", rootPart.path); err != nil {
				h.logger.Warn("failed to restore filesystem size after capture", "partition", rootPart.path, "error", err)
			}
		}
		if generalized {
			if err := h.restoreIdentity(rootPart.path); err != nil {
				h.logger.Warn("failed to restore source node identity after capture", "error", err)
			} else if size := diskSizeBytes(targetDevice); size > 0 {
				// The identity is back where it belongs, so the on-disk copy has
				// done its job. Clearing it stops a later capture restoring an
				// identity that is already in place.
				if offset, ok := identityStashOffset(size, (rootPart.startSectors+rootPart.sizeSectors)*512); ok {
					clearIdentityStash(targetDevice, offset, h.logger)
				}
			}
			_ = os.Remove(identityBackupTar)
		}
	}()

	if cmd.Generalize {
		// Before stripping anything: if a PREVIOUS generalized capture died after
		// stripping, its identity is still stashed on this disk and the node is
		// running without one. Retrying the capture is the operator's natural
		// next move, so it is the natural moment to put it back.
		h.recoverStashedIdentity(targetDevice, rootPart.path, (rootPart.startSectors+rootPart.sizeSectors)*512)

		h.reportCommandStatus(commandID, "in_progress", 10, "Generalizing image (stripping machine identity)")
		if err := h.generalizeRoot(rootPart.path, targetDevice, (rootPart.startSectors+rootPart.sizeSectors)*512); err != nil {
			return h.failCapture(commandID, fmt.Sprintf("failed to generalize root filesystem: %v", err))
		}
		generalized = true
	}

	h.reportCommandStatus(commandID, "in_progress", 20, "Checking filesystem")
	if err := runE2fsck(rootPart.path); err != nil {
		return h.failCapture(commandID, err.Error())
	}
	h.reportCommandStatus(commandID, "in_progress", 25, "Shrinking filesystem to minimum size")
	shrunkBytes, err := shrinkFilesystem(rootPart.path)
	if err != nil {
		return h.failCapture(commandID, fmt.Sprintf("failed to shrink filesystem: %v", err))
	}
	fsShrunk = true

	// Shrink the ROOT PARTITION entry to just cover the shrunk filesystem so the
	// captured image's partition table is self-consistent and the image is
	// portable to a SMALLER disk. The original table is restored on the source
	// in the deferred cleanup; deploy (install_os) grows the partition + fs back
	// to fill whatever disk it lands on.
	h.reportCommandStatus(commandID, "in_progress", 28, "Shrinking partition table")
	partEndBytes := alignUp(rootPart.startSectors*512+shrunkBytes, captureAlignment)
	newSizeSectors := partEndBytes/512 - rootPart.startSectors
	origTablePath, err = shrinkPartitionTable(targetDevice, rootPart, newSizeSectors)
	if err != nil {
		return h.failCapture(commandID, fmt.Sprintf("failed to shrink partition table: %v", err))
	}
	tableShrunk = true

	captureLen := partEndBytes
	if total := diskSizeBytes(targetDevice); total > 0 && captureLen > total {
		captureLen = total
	}
	h.logger.Info("computed capture extent",
		"partition_start_bytes", rootPart.startSectors*512, "shrunk_fs_bytes", shrunkBytes, "capture_len", captureLen)

	// Retry the upload from scratch on a transient failure — each attempt
	// re-reads from offset 0; the filesystem stays shrunk (idempotent) and the
	// backend overwrites the not-yet-finalized record.
	const maxAttempts = 3
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		err = h.streamCaptureUpload(commandID, targetDevice, cmd.UploadUrl, captureLen)
		if err == nil {
			break
		}
		if attempt < maxAttempts && isTransientUploadError(err) {
			h.logger.Warn("capture upload interrupted, retrying", "attempt", attempt, "error", err)
			h.reportCommandStatus(commandID, "in_progress", 30,
				fmt.Sprintf("Upload interrupted, retrying (attempt %d/%d)", attempt+1, maxAttempts))
			time.Sleep(5 * time.Second)
			continue
		}
		break
	}
	if err != nil {
		return h.failCapture(commandID, fmt.Sprintf("capture upload failed: %v", err))
	}

	h.reportCommandResult(commandID, "success", "Image captured and uploaded", map[string]string{
		"image_id": cmd.ImageId,
	})
	h.logger.Info("capture image command completed", "command_id", commandID, "image_id", cmd.ImageId)
	return nil
}

// failCapture reports a terminal failure and returns the error.
func (h *CommandHandler) failCapture(commandID, msg string) error {
	h.reportCommandStatus(commandID, "failed", 0, msg)
	return fmt.Errorf("%s", msg)
}

// detectRootPartition finds the OS root partition on an UNMOUNTED disk. The
// df-based storage reader reports zero sizes for unmounted filesystems (the
// recovery precondition), so this reads partitions from sysfs and picks the
// largest one that is a genuine ext filesystem (dumpe2fs succeeds — which also
// avoids depending on a busybox blkid that may not report fs types). Falls back
// to partition 2, the RPi Ubuntu root, like the install-side expansion does.
func (h *CommandHandler) captureDetectRootPartition(commandID, targetDevice string) (partition, error) {
	parts, err := listPartitions(targetDevice)
	if err != nil || len(parts) == 0 {
		return partition{}, fmt.Errorf("failed to enumerate partitions on %s: %v", targetDevice, err)
	}
	sort.Slice(parts, func(i, j int) bool { return parts[i].sizeSectors > parts[j].sizeSectors })
	for _, p := range parts {
		if exec.Command("dumpe2fs", "-h", p.path).Run() == nil {
			h.logger.Info("detected root partition", "partition", p.path, "number", p.num)
			return p, nil
		}
	}
	// Fallback: partition 2.
	for _, p := range parts {
		if p.num == 2 {
			h.logger.Warn("no ext partition detected, falling back to partition 2", "partition", p.path)
			return p, nil
		}
	}
	return partition{}, fmt.Errorf("no ext filesystem found on %s", targetDevice)
}

// listPartitions reads the disk's partitions from sysfs (start + size in
// 512-byte sectors, always the sysfs unit regardless of physical sector size).
func listPartitions(targetDevice string) ([]partition, error) {
	base := filepath.Base(targetDevice)
	entries, err := os.ReadDir("/sys/class/block")
	if err != nil {
		return nil, err
	}
	var parts []partition
	for _, e := range entries {
		name := e.Name()
		if name == base || !strings.HasPrefix(name, base) {
			continue
		}
		dir := filepath.Join("/sys/class/block", name)
		if _, err := os.Stat(filepath.Join(dir, "partition")); err != nil {
			continue // not a partition of this disk
		}
		start, err1 := readSysfsInt(filepath.Join(dir, "start"))
		size, err2 := readSysfsInt(filepath.Join(dir, "size"))
		numRaw, _ := os.ReadFile(filepath.Join(dir, "partition"))
		num, _ := strconv.Atoi(strings.TrimSpace(string(numRaw)))
		if err1 != nil || err2 != nil {
			continue
		}
		parts = append(parts, partition{
			path:         "/dev/" + name,
			num:          num,
			startSectors: start,
			sizeSectors:  size,
		})
	}
	return parts, nil
}

// assertRootIsLastPartition fails if any partition starts at or after the root
// partition's end — capturing [0, root_end) would silently drop it.
func assertRootIsLastPartition(targetDevice string, root partition) error {
	parts, err := listPartitions(targetDevice)
	if err != nil {
		return err
	}
	rootEnd := root.startSectors + root.sizeSectors
	for _, p := range parts {
		if p.path == root.path {
			continue
		}
		if p.startSectors >= rootEnd {
			return fmt.Errorf("root partition %s is not the last partition (%s starts after it); capture would drop data — not supported", root.path, p.path)
		}
	}
	return nil
}

func readSysfsInt(path string) (int64, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	return strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
}

// streamCaptureUpload reads [0, captureLen) from the disk, zstd-compresses it,
// and PUTs it to the pre-signed upload URL, reporting progress 30→95%.
func (h *CommandHandler) streamCaptureUpload(commandID, device, uploadURL string, captureLen int64) error {
	src, err := os.OpenFile(device, os.O_RDONLY, 0)
	if err != nil {
		return fmt.Errorf("failed to open device %s: %w", device, err)
	}
	defer src.Close()

	pr, pw := io.Pipe()
	go func() {
		enc, encErr := zstd.NewWriter(pw, zstd.WithEncoderLevel(zstd.SpeedDefault), zstd.WithEncoderConcurrency(0))
		if encErr != nil {
			_ = pw.CloseWithError(encErr)
			return
		}
		progress := &captureProgressReader{
			reader: io.LimitReader(src, captureLen), total: captureLen, commandID: commandID, h: h, lastPct: 30,
		}
		if _, copyErr := io.Copy(enc, progress); copyErr != nil {
			_ = enc.Close()
			_ = pw.CloseWithError(fmt.Errorf("failed to read from device: %w", copyErr))
			return
		}
		if closeErr := enc.Close(); closeErr != nil {
			_ = pw.CloseWithError(closeErr)
			return
		}
		_ = pw.Close()
	}()

	req, err := http.NewRequest(http.MethodPut, uploadURL, pr)
	if err != nil {
		_ = pr.CloseWithError(err)
		return fmt.Errorf("failed to build upload request: %w", err)
	}
	req.Header.Set("Content-Type", "application/zstd")
	req.ContentLength = -1 // length unknown up front (compression) → chunked

	client := &http.Client{Timeout: captureUploadTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to upload image: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return fmt.Errorf("upload rejected: HTTP %d (%s)", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	h.reportCommandStatus(commandID, "in_progress", 95, "Upload complete")
	return nil
}

// captureProgressReader reports capture upload progress as the disk is read.
type captureProgressReader struct {
	reader    io.Reader
	total     int64
	read      int64
	commandID string
	h         *CommandHandler
	lastPct   int32
}

func (r *captureProgressReader) Read(p []byte) (int, error) {
	n, err := r.reader.Read(p)
	if n > 0 {
		r.read += int64(n)
		if r.total > 0 {
			pct := int32(30 + (r.read*65)/r.total)
			if pct > 95 {
				pct = 95
			}
			if pct >= r.lastPct+2 {
				r.lastPct = pct
				r.h.reportCommandStatus(r.commandID, "in_progress", pct, "Capturing and uploading image")
			}
		}
	}
	return n, err
}

// identityPaths are the machine-specific files stripped for a golden image.
// They are backed up before stripping and restored onto the source afterwards.
var identityPaths = []string{
	"etc/machine-id",
	"var/lib/dbus/machine-id",
	"etc/hostname",
	"etc/orchestrator",
	"var/lib/cloud",
	"var/lib/dhcp",
	"etc/udev/rules.d/70-persistent-net.rules",
	// Watchdog supervision is armed per node, never baked into an image: a
	// clone that boots armed with the SOURCE's ping targets and no breaker
	// state reboot-loops unrecoverably on hardware without netboot recovery.
	"etc/watchdog.conf",
	"etc/watchdog.conf.orchestrator.bak",
	"etc/systemd/system/watchdog.service.d",
	"etc/systemd/system/multi-user.target.wants/watchdog.service",
	"etc/systemd/system/multi-user.target.wants/wd_keepalive.service",
	"var/lib/orchestrator-agent/watchdog-armed",
}

// generalizeRoot mounts the target root, backs up its identity to a tar in the
// ramfs (so the source can be restored), then strips machine identity so the
// captured image deploys onto any device with a fresh identity. SSH host keys
// are matched by glob separately.
func (h *CommandHandler) generalizeRoot(rootPart, targetDevice string, rootEndBytes int64) error {
	if err := os.MkdirAll(captureMountPoint, 0o755); err != nil {
		return fmt.Errorf("mkdir mountpoint: %w", err)
	}
	if err := syscall.Mount(rootPart, captureMountPoint, "ext4", 0, ""); err != nil {
		return fmt.Errorf("mount %s: %w", rootPart, err)
	}
	unmounted := false
	unmount := func() {
		if unmounted {
			return
		}
		if err := syscall.Unmount(captureMountPoint, 0); err != nil {
			h.logger.Warn("failed to unmount capture root", "error", err)
		} else {
			unmounted = true
		}
	}
	defer unmount()

	// Collect the identity paths (and SSH host keys) that actually exist,
	// relative to the mount, and back them up BEFORE stripping. If the backup
	// cannot be made, abort without stripping — never leave the source without a
	// recoverable identity.
	var existing []string
	for _, rel := range identityPaths {
		if _, err := os.Lstat(filepath.Join(captureMountPoint, rel)); err == nil {
			existing = append(existing, rel)
		}
	}
	if keys, _ := filepath.Glob(filepath.Join(captureMountPoint, "etc/ssh/ssh_host_*")); keys != nil {
		for _, k := range keys {
			if rel, err := filepath.Rel(captureMountPoint, k); err == nil {
				existing = append(existing, rel)
			}
		}
	}
	if len(existing) > 0 {
		args := append([]string{"-C", captureMountPoint, "-cf", identityBackupTar}, existing...)
		if out, err := exec.Command("tar", args...).CombinedOutput(); err != nil {
			return fmt.Errorf("failed to back up source identity (aborting before strip): %v (%s)", err, strings.TrimSpace(string(out)))
		}
		// The tar above lives in the netboot initramfs TMPFS, and the strip
		// below is only undone by a deferred restore — so a crash or a power
		// cut anywhere in the next four hours takes the source node's adoption
		// file with it, permanently and unrecoverably from the platform's side.
		// Put a copy somewhere that survives losing the machine.
		h.stashIdentityOnDisk(targetDevice, rootEndBytes)
	}

	stripIdentityAt(captureMountPoint)

	syscall.Sync()
	unmount()
	return nil
}

// stripIdentityAt removes machine identity from a root filesystem mounted at
// mountPoint. Shared by golden captures (which back up the source's identity
// first and restore it afterwards) and by install_os with strip_identity set
// (deploying a backup image onto a node other than its source — there the
// strip is permanent by design).
func stripIdentityAt(mountPoint string) {
	// machine-id must exist but be EMPTY so systemd/cloud-init regenerate
	// it on first boot (a missing file makes some units fail).
	for _, mid := range []string{"etc/machine-id", "var/lib/dbus/machine-id"} {
		p := filepath.Join(mountPoint, mid)
		if _, err := os.Stat(p); err == nil {
			_ = os.WriteFile(p, []byte{}, 0o644)
		}
	}
	if keys, _ := filepath.Glob(filepath.Join(mountPoint, "etc/ssh/ssh_host_*")); keys != nil {
		for _, k := range keys {
			_ = os.Remove(k)
		}
	}
	// Orchestrator adoption identity: the deployed node must re-adopt as a fresh
	// node, not impersonate the source.
	_ = os.RemoveAll(filepath.Join(mountPoint, "etc/orchestrator"))
	// cloud-init re-runs from a clean state (regenerating host keys + hostname);
	// DHCP leases and persistent net rules pin the source's identity. Watchdog
	// supervision (conf, drop-in, enablement, breaker state) is per-node desired
	// state the platform re-applies — an image must never carry it (see
	// identityPaths).
	for _, tree := range []string{
		"var/lib/cloud", "var/lib/dhcp", "etc/udev/rules.d/70-persistent-net.rules",
		"etc/watchdog.conf", "etc/watchdog.conf.orchestrator.bak",
		"etc/systemd/system/watchdog.service.d",
		"etc/systemd/system/multi-user.target.wants/watchdog.service",
		"etc/systemd/system/multi-user.target.wants/wd_keepalive.service",
		"var/lib/orchestrator-agent/watchdog-armed",
	} {
		_ = os.RemoveAll(filepath.Join(mountPoint, tree))
	}
	// Hostname: empty so first boot assigns a fresh one.
	if _, err := os.Stat(filepath.Join(mountPoint, "etc/hostname")); err == nil {
		_ = os.WriteFile(filepath.Join(mountPoint, "etc/hostname"), []byte{}, 0o644)
	}
}

// restoreIdentity remounts the (grown-back) root and restores the source node's
// identity from the backup tar, so a generalized capture never leaves the
// source stripped and unadopted.
func (h *CommandHandler) restoreIdentity(rootPart string) error {
	if _, err := os.Stat(identityBackupTar); err != nil {
		return nil // nothing was backed up
	}
	if err := os.MkdirAll(captureMountPoint, 0o755); err != nil {
		return err
	}
	if err := syscall.Mount(rootPart, captureMountPoint, "ext4", 0, ""); err != nil {
		return fmt.Errorf("mount for restore: %w", err)
	}
	defer func() { _ = syscall.Unmount(captureMountPoint, 0) }()
	if out, err := exec.Command("tar", "-C", captureMountPoint, "-xf", identityBackupTar).CombinedOutput(); err != nil {
		return fmt.Errorf("restore untar: %v (%s)", err, strings.TrimSpace(string(out)))
	}
	syscall.Sync()
	return nil
}

// partitionTableSavePath holds the source disk's original partition table
// while a capture temporarily shrinks the root partition entry.
const partitionTableSavePath = "/tmp/orchestrator-ptable.sav"

// sfdiskSizeRe matches the "size=<sectors>" field of an sfdisk dump line.
var sfdiskSizeRe = regexp.MustCompile(`(size=\s*)\d+`)

// shrinkPartitionTable dumps the disk's partition table, rewrites the root
// partition's size to newSizeSectors, and applies it — making the captured
// image portable to a smaller disk. On any failure it leaves the ORIGINAL
// table intact (never applied, or restored) so the source is never corrupted.
// On success it returns the path of the saved original table for the caller to
// restore in its cleanup.
func shrinkPartitionTable(disk string, root partition, newSizeSectors int64) (string, error) {
	if newSizeSectors <= 0 {
		return "", fmt.Errorf("computed a non-positive partition size (%d sectors)", newSizeSectors)
	}
	dump, err := exec.Command("sfdisk", "-d", disk).Output()
	if err != nil {
		return "", fmt.Errorf("sfdisk dump: %w", err)
	}
	if err := os.WriteFile(partitionTableSavePath, dump, 0o600); err != nil {
		return "", fmt.Errorf("save partition table: %w", err)
	}
	modified, err := editSfdiskSize(string(dump), root.path, newSizeSectors)
	if err != nil {
		_ = os.Remove(partitionTableSavePath)
		return "", err
	}
	if err := applySfdisk(disk, modified); err != nil {
		// Apply may have partially written the table — restore the original.
		if rerr := applySfdisk(disk, string(dump)); rerr != nil {
			return "", fmt.Errorf("shrink failed (%v) AND original table restore failed (%v) — source disk table may be inconsistent", err, rerr)
		}
		_ = runCmd("partprobe", disk)
		_ = os.Remove(partitionTableSavePath)
		return "", fmt.Errorf("shrink partition apply failed, original table restored: %w", err)
	}
	_ = runCmd("partprobe", disk)
	return partitionTableSavePath, nil
}

// restorePartitionTable rewrites the disk's partition table from a saved dump.
func restorePartitionTable(disk, savePath string) error {
	data, err := os.ReadFile(savePath)
	if err != nil {
		return err
	}
	if err := applySfdisk(disk, string(data)); err != nil {
		return err
	}
	_ = runCmd("partprobe", disk)
	return nil
}

// applySfdisk writes a full partition table (sfdisk dump format) to the disk.
func applySfdisk(disk, table string) error {
	cmd := exec.Command("sfdisk", "--no-reread", "--force", disk)
	cmd.Stdin = strings.NewReader(table)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("sfdisk apply: %w (%s)", err, strings.TrimSpace(stderr.String()))
	}
	return nil
}

// editSfdiskSize rewrites the size= field of the root partition's line in an
// sfdisk dump, leaving start/type and every other line untouched.
func editSfdiskSize(dump, partPath string, newSizeSectors int64) (string, error) {
	lines := strings.Split(dump, "\n")
	found := false
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, partPath+" ") && !strings.HasPrefix(trimmed, partPath+":") {
			continue
		}
		if !sfdiskSizeRe.MatchString(line) {
			return "", fmt.Errorf("partition line for %s has no size= field", partPath)
		}
		lines[i] = sfdiskSizeRe.ReplaceAllString(line, fmt.Sprintf("${1}%d", newSizeSectors))
		found = true
		break
	}
	if !found {
		return "", fmt.Errorf("could not find partition %s in the table dump", partPath)
	}
	return strings.Join(lines, "\n"), nil
}

// runE2fsck runs e2fsck -p -f, tolerating exit 1 (errors corrected) but failing
// on exit > 1 (uncorrected/serious) so latent corruption is never baked into a
// fleet-wide image.
func runE2fsck(part string) error {
	cmd := exec.Command("e2fsck", "-p", "-f", part)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			if status, ok := exitErr.Sys().(syscall.WaitStatus); ok && status.ExitStatus() == 1 {
				return nil
			}
		}
		return fmt.Errorf("e2fsck failed on %s: %v (%s)", part, err, strings.TrimSpace(stderr.String()))
	}
	return nil
}

// shrinkFilesystem runs resize2fs -M and returns the resulting size in bytes.
func shrinkFilesystem(part string) (int64, error) {
	out, err := exec.Command("resize2fs", "-M", part).CombinedOutput()
	text := string(out)
	if err != nil {
		return 0, fmt.Errorf("resize2fs -M failed: %w (%s)", err, strings.TrimSpace(text))
	}
	m := resize2fsBlocksRe.FindStringSubmatch(text)
	if m == nil {
		// Already minimal ("Nothing to do!"): read the current size instead.
		return filesystemSizeBytes(part)
	}
	blocks, _ := strconv.ParseInt(m[1], 10, 64)
	blockKiB, _ := strconv.ParseInt(m[2], 10, 64)
	return blocks * blockKiB * 1024, nil
}

// filesystemSizeBytes reads block count × block size from dumpe2fs.
func filesystemSizeBytes(part string) (int64, error) {
	out, err := exec.Command("dumpe2fs", "-h", part).CombinedOutput()
	if err != nil {
		return 0, fmt.Errorf("dumpe2fs failed: %w", err)
	}
	var blockCount, blockSize int64
	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(line, "Block count:") {
			blockCount, _ = strconv.ParseInt(strings.TrimSpace(strings.TrimPrefix(line, "Block count:")), 10, 64)
		}
		if strings.HasPrefix(line, "Block size:") {
			blockSize, _ = strconv.ParseInt(strings.TrimSpace(strings.TrimPrefix(line, "Block size:")), 10, 64)
		}
	}
	if blockCount == 0 || blockSize == 0 {
		return 0, fmt.Errorf("could not parse filesystem size from dumpe2fs")
	}
	return blockCount * blockSize, nil
}

// diskSizeBytes returns the whole-disk size, or 0 when it cannot be read.
func diskSizeBytes(device string) int64 {
	out, err := exec.Command("blockdev", "--getsize64", device).CombinedOutput()
	if err != nil {
		return 0
	}
	n, _ := strconv.ParseInt(strings.TrimSpace(string(out)), 10, 64)
	return n
}

func alignUp(n, align int64) int64 {
	if align <= 0 {
		return n
	}
	if rem := n % align; rem != 0 {
		return n + (align - rem)
	}
	return n
}

// runCmd runs a command and returns a wrapped error on failure.
func runCmd(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s failed: %w (%s)", name, err, strings.TrimSpace(stderr.String()))
	}
	return nil
}

// isTransientUploadError reports whether a capture upload failure is worth
// retrying from scratch (network/gateway blip) rather than a persistent local
// or server error.
func isTransientUploadError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	for _, marker := range []string{
		"broken pipe",
		"connection reset",
		"connection refused",
		"unexpected eof",
		"eof",
		"i/o timeout",
		"timeout",
		"upload rejected: http 5",
	} {
		if strings.Contains(msg, marker) {
			return true
		}
	}
	return false
}
