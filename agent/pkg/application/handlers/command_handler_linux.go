//go:build linux

package handlers

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
	"unicode/utf8"

	"agent/pkg/domain/board"
	"agent/pkg/domain/refusal"
	"agent/pkg/pkgver"
	"agent/pkg/signing"

	proto "agent/pkg/infrastructure/grpc/proto"
	"agent/pkg/infrastructure/hardware"
)

// rebootNow reboots the machine, preferring `shutdown -r now` (present on a
// full sysvinit/systemd OS) but falling back to `reboot` on minimal images such
// as the bootstrap RAM rootfs (busybox), which has no `shutdown` binary.
func rebootNow() error {
	if _, err := exec.LookPath("shutdown"); err == nil {
		if err := exec.Command("shutdown", "-r", "now").Run(); err == nil {
			return nil
		}
	}
	// On the minimal bootstrap, plain `reboot` only signals an init that does
	// not act on it, so force an immediate reboot. Sync first since -f skips the
	// clean shutdown.
	syscall.Sync()
	if err := exec.Command("reboot", "-f").Run(); err == nil {
		return nil
	}
	return exec.Command("reboot").Run()
}

// poweroffNow halts the machine with the same `shutdown`-then-busybox fallback.
func poweroffNow() error {
	if _, err := exec.LookPath("shutdown"); err == nil {
		if err := exec.Command("shutdown", "-h", "now").Run(); err == nil {
			return nil
		}
	}
	return exec.Command("poweroff").Run()
}

// ensureURLScheme prepends http:// when a URL has no scheme. The adoption file's
// platform URL is sometimes a bare host/IP, which Go's net/http rejects.
func ensureURLScheme(u string) string {
	if u == "" {
		return u
	}
	if !strings.HasPrefix(u, "http://") && !strings.HasPrefix(u, "https://") {
		return "http://" + u
	}
	return u
}

// handleShutdown handles shutdown commands
func (h *CommandHandler) handleShutdown(commandID string, cmd *proto.ShutdownCommand) error {
	h.logger.Info("shutdown command received", "command_id", commandID, "delay_seconds", cmd.DelaySeconds)

	// Report command status: in_progress
	delaySeconds, bound := clampCommandDelaySeconds(cmd.DelaySeconds)
	if bound {
		h.logger.Warn("shutdown delay clamped", "command_id", commandID,
			"requested_seconds", cmd.DelaySeconds, "delay_seconds", delaySeconds)
	}
	h.reportCommandStatus(commandID, "in_progress", 0, fmt.Sprintf("System will shutdown in %d seconds", delaySeconds))

	// Delay before powering off, then halt (busybox-compatible).
	if delaySeconds > 0 {
		time.Sleep(time.Duration(delaySeconds) * time.Second)
	}
	if err := poweroffNow(); err != nil {
		errMsg := fmt.Sprintf("Shutdown command failed: %v", err)
		h.logger.Error("shutdown command failed", "command_id", commandID, "error", err)
		h.reportCommandStatus(commandID, "failed", 0, errMsg)
		return fmt.Errorf("shutdown command failed: %w", err)
	}

	// Report command success (system will shutdown, so this may not be received)
	h.reportCommandStatus(commandID, "success", 100, fmt.Sprintf("Shutdown scheduled for %d seconds", delaySeconds))

	h.logger.Info("shutdown command executed successfully", "command_id", commandID)
	return nil
}

// handleRestart handles restart commands
func (h *CommandHandler) handleRestart(commandID string, cmd *proto.RestartCommand) error {
	h.logger.Info("restart command received", "command_id", commandID, "delay_seconds", cmd.DelaySeconds)

	delaySeconds, bound := clampCommandDelaySeconds(cmd.DelaySeconds)
	if bound {
		h.logger.Warn("restart delay clamped", "command_id", commandID,
			"requested_seconds", cmd.DelaySeconds, "delay_seconds", delaySeconds)
	}
	// Report command status: in_progress
	progressDetail := "Restart initiated"
	if delaySeconds > 0 {
		progressDetail = fmt.Sprintf("Restart initiated (in %ds)", delaySeconds)
	}
	h.reportCommandStatus(commandID, "in_progress", 0, progressDetail)

	// Delay before rebooting, then reboot (busybox-compatible: falls back to
	// `reboot` when `shutdown` is absent, as on the bootstrap RAM image).
	if delaySeconds > 0 {
		h.logger.Info("scheduling reboot", "delay_seconds", delaySeconds)
		time.Sleep(time.Duration(delaySeconds) * time.Second)
	} else {
		h.logger.Info("executing immediate reboot")
	}

	if err := rebootNow(); err != nil {
		errMsg := fmt.Sprintf("Restart command failed: %v", err)
		h.logger.Error("restart command failed", "command_id", commandID, "error", err)
		h.reportCommandStatus(commandID, "failed", 0, errMsg)
		return fmt.Errorf("restart command failed: %w", err)
	}

	// Report command success (system will restart, so this may not be received)
	detail := "Restart initiated"
	if delaySeconds > 0 {
		detail = fmt.Sprintf("Restart initiated (in %ds)", delaySeconds)
	}
	h.reportCommandStatus(commandID, "success", 100, detail)

	h.logger.Info("restart command executed successfully", "command_id", commandID)
	return nil
}

// handleStatusCheck handles status check commands
func (h *CommandHandler) handleStatusCheck(commandID string, cmd *proto.StatusCheckCommand) error {
	h.logger.Info("status check command received", "command_id", commandID)

	// Check system status using systemctl if available, otherwise just report online
	var statusMessage string
	statusCmd := exec.Command("systemctl", "is-system-running")
	output, err := statusCmd.Output()

	if err != nil {
		// If systemctl is not available or fails, assume system is online
		statusMessage = "System status: online"
		h.logger.Info("status check: systemctl not available, assuming online", "command_id", commandID)
	} else {
		statusMessage = fmt.Sprintf("System status: %s", string(output))
	}

	// Report command success
	h.reportCommandStatus(commandID, "success", 100, statusMessage)

	// Send status update with the output
	h.logger.Info("status update: online", "message", statusMessage)
	h.logger.Info("status check command executed successfully", "command_id", commandID, "output", statusMessage)
	return nil
}

// validateTargetDevice validates that the target device is safe to install onto:
// never mounted, and (unless allowPartitioned) free of existing partitions.
func (h *CommandHandler) validateTargetDevice(devicePath string, allowPartitioned bool) error {
	if h.storageReader == nil {
		return fmt.Errorf("storage reader not available")
	}

	devices, err := h.storageReader.DetectDevices()
	if err != nil {
		return fmt.Errorf("failed to detect devices: %w", err)
	}

	device, exists := devices[devicePath]
	if !exists {
		return fmt.Errorf("device %s not found", devicePath)
	}

	// A device with existing partitions is refused UNLESS the caller explicitly
	// opts in (restore / re-image with wipe=true). The mount checks below still
	// run either way — a mounted disk is never overwritten.
	if len(device.Partitions) > 0 && !allowPartitioned {
		return fmt.Errorf("device %s has partitions and cannot be used for OS installation (set wipe to overwrite a used disk from recovery)", devicePath)
	}

	// Check if device is mounted (check if any partition is mounted)
	for _, partition := range device.Partitions {
		if partition.MountPoint != "" {
			return fmt.Errorf("device %s has mounted partitions and cannot be used for OS installation", devicePath)
		}
	}

	// Check if device itself is mounted by checking /proc/mounts
	mountCmd := exec.Command("grep", "-q", "^"+devicePath+" ", "/proc/mounts")
	if err := mountCmd.Run(); err == nil {
		return fmt.Errorf("device %s is mounted and cannot be used for OS installation", devicePath)
	}

	// In use without a mount of its own: LUKS/LVM, md or swap. Named first, so
	// the refusal says what holds the disk; then the kernel's own answer, an
	// exclusive open, which it refuses while anything claims the disk or one of
	// its partitions.
	if held := targetDeviceHolders("/sys/class/block", "/proc/swaps", devicePath); len(held) > 0 {
		return fmt.Errorf("device %s is in use and cannot be used for OS installation: %s",
			devicePath, strings.Join(held, "; "))
	}
	if f, err := os.OpenFile(devicePath, os.O_RDONLY|syscall.O_EXCL, 0); err != nil {
		if errors.Is(err, syscall.EBUSY) {
			return fmt.Errorf("device %s cannot be used for OS installation: %w (a mounted, device-mapper, md or swap partition holds it, or a filesystem detached lazily is still held open)", devicePath, errTargetDeviceBusy)
		}
	} else {
		_ = f.Close()
	}

	// Verify device exists and is accessible
	if _, err := os.Stat(devicePath); err != nil {
		return fmt.Errorf("device %s is not accessible: %w", devicePath, err)
	}

	// Stat is not enough: the device node outlives the transport, so a wedged
	// disk passes every check above and then fails deep inside the write with an
	// error that names a tool rather than the hardware. Read its first sector.
	if err := h.checkDeviceResponds(devicePath); err != nil {
		return err
	}

	return nil
}

// downloadAndWriteImageChunked downloads image in chunks and writes to device using dd
// Progress is reported from 5% to 95% (90% range for download, 5% reserved for resize)
//
// With wipe, the old partition and filesystem signatures are cleared too, so a
// stale table or filesystem beyond the written image cannot confuse blkid or
// the bootloader. Both that and the disarm run only once the image stream has
// delivered its first bytes (prepareOnFirstRead).
func (h *CommandHandler) downloadAndWriteImageChunked(commandID, imageURL, targetDevice, expectedChecksum string, wipe bool) (err error) {
	h.logger.Info("starting image download and write", "image_url", redactURL(imageURL), "target_device", targetDevice)

	// A stall watchdog rather than an overall deadline: progress is sampled from
	// the write loop, so a download that stops delivering bytes cancels the
	// request instead of hanging with the target device open.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var progress atomic.Int64
	go func() {
		ticker := time.NewTicker(15 * time.Second)
		defer ticker.Stop()
		last := int64(-1)
		stalledFor := time.Duration(0)
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				now := progress.Load()
				if now != last {
					last, stalledFor = now, 0
					continue
				}
				stalledFor += 15 * time.Second
				if stalledFor >= downloadStallTimeout {
					h.logger.Error("image download stalled; aborting",
						"stalled_for", stalledFor.String(), "bytes", now)
					cancel()
					return
				}
			}
		}
	}()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, imageURL, nil)
	if err != nil {
		return fmt.Errorf("failed to build image request: %w", err)
	}
	resp, err := imageDownloadClient().Do(req)
	if err != nil {
		return fmt.Errorf("failed to download image: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to download image: HTTP %d", resp.StatusCode)
	}

	// Get content length if available
	contentLength := resp.ContentLength
	if contentLength > 0 {
		h.logger.Info("image download started", "content_length", contentLength, "content_length_mb", contentLength/(1024*1024))
	} else {
		h.logger.Info("image download started", "content_length", "unknown")
	}

	// The platform checksum is computed over the stored file, so hash the raw
	// download stream; compressed images are decompressed on the fly and
	// only the decompressed bytes reach the device.
	compression, err := imageURLCompression(imageURL)
	if err != nil {
		return err
	}
	if compression != compressionNone {
		h.logger.Info("image is compressed, decompressing while writing", "compression", compression)
	}

	hash := sha256.New()
	source := &countingHashReader{reader: resp.Body, hash: hash}
	imageReader, err := newImageStreamReader(compression, source, h.logger)
	if err != nil {
		return err
	}
	defer imageReader.Close()

	// Define chunk size (4MB)
	const chunkSize = 4 * 1024 * 1024
	buffer := make([]byte, chunkSize)

	// Open target device for buffered writing. O_SYNC would force a full
	// flush per chunk and caps throughput at ~28 MB/s on Pi NVMe; instead
	// dirty pages are bounded by a periodic sync and a final Sync() before
	// the command is reported complete.
	deviceFile, err := os.OpenFile(targetDevice, os.O_WRONLY, 0)
	if err != nil {
		return fmt.Errorf("failed to open device %s: %w", targetDevice, err)
	}
	defer deviceFile.Close()

	// The previous install stops being bootable before anything of this one is
	// written, and durably — a reset mid-stream never reaches a defer. Not
	// before the stream has started, though: until then nothing obliges the
	// disk to lose the system it holds.
	stream := newPrepareOnFirstRead(imageReader, func() error {
		if wipe {
			h.reportCommandStatus(commandID, "in_progress", 5, "Wiping existing disk signatures")
			if out, werr := exec.Command("wipefs", "-a", targetDevice).CombinedOutput(); werr != nil {
				h.logger.Warn("wipefs reported an issue (continuing; the image write overwrites the table)",
					"device", targetDevice, "error", werr, "output", strings.TrimSpace(string(out)))
			}
		}
		if err := disarmTargetBeforeWrite(deviceFile); err != nil {
			return fmt.Errorf("failed to prepare %s: %w", targetDevice, err)
		}
		return nil
	})

	// Sync every 256MB to keep memory pressure bounded on the netboot
	// bootstrap while letting the kernel batch writes efficiently.
	const syncInterval = 256 * 1024 * 1024
	var lastSyncedAt int64

	h.logger.Info("target device opened for writing", "device", targetDevice)

	chunkNum := 0
	writtenBytes := int64(0)         // decompressed bytes consumed (= logical offset in the image)
	lastReportedProgress := int32(5) // Track last reported integer percentage (start at 5%)

	// ANY failure from here on leaves the disk in the state invalidateTargetDevice
	// exists to prevent, so it runs from a defer rather than from one branch.
	//
	// The head is deliberately withheld until the digest matches, so a failure
	// mid-stream leaves the PREVIOUS install's partition table pointing at a
	// filesystem that is now half-old and half-new: the disk looks bootable, the
	// board hangs in initramfs, and somebody drives to the rack. That was
	// reachable from every error return in this function — a stalled download, a
	// read error, a short write, a failed sync — while the invalidation was wired
	// to the checksum-mismatch branch alone, which is the one case that had
	// already been thought about.
	//
	// `committed` turns it off the moment the head lands: from then on the disk
	// carries a valid table for the image that is actually on it, and a later
	// failure (a resize, a partprobe) must not destroy a good install.
	committed := false
	defer func() {
		// Untouched — the stream failed before its first bytes — means the
		// previous system is intact, and there is nothing to invalidate.
		if err == nil || committed || !stream.Prepared() {
			return
		}
		h.invalidateTargetDevice(deviceFile, targetDevice, writtenBytes)
	}()

	// The image head is held in RAM until the digest matches. Costs 4 MiB on a
	// bootstrap whose working set is already ~350 MB (dirty pages alone are
	// bounded at 256 MB by syncInterval), so under half a percent even on a
	// 1 GB CM4.
	head := make([]byte, 0, imageHeadSize)

	writeAt := func(data []byte, offset int64) error {
		bytesWritten, writeErr := deviceFile.WriteAt(data, offset)
		if writeErr != nil {
			h.logger.Error("failed to write chunk to device",
				"chunk", chunkNum+1, "error", writeErr,
				"chunk_size", len(data), "offset_bytes", offset)
			return fmt.Errorf("failed to write chunk to device: %w", writeErr)
		}
		if bytesWritten != len(data) {
			h.logger.Error("partial write to device",
				"chunk", chunkNum+1, "expected_bytes", len(data),
				"bytes_written", bytesWritten, "offset_bytes", offset)
			return fmt.Errorf("partial write to device: expected %d bytes, wrote %d bytes", len(data), bytesWritten)
		}
		return nil
	}

	// Chunked loop - write sequentially to device
	for {
		// Read chunk of raw image bytes (decompressed if the source is .xz)
		n, err := stream.Read(buffer)

		// Process data if we read any bytes
		if n > 0 {
			chunkData := buffer[:n]

			h.logger.Debug("writing chunk to device",
				"chunk", chunkNum+1,
				"chunk_size", n,
				"offset_bytes", writtenBytes)

			// Hold back the head; write only what falls beyond it. Offsets are
			// unchanged from the write-everything version, so progress, the
			// sync interval and the post-write steps all see the same numbers.
			held := int64(0)
			if writtenBytes < imageHeadSize {
				held = imageHeadSize - writtenBytes
				if held > int64(n) {
					held = int64(n)
				}
				head = append(head, chunkData[:held]...)
			}
			if int64(n) > held {
				if err := writeAt(chunkData[held:], writtenBytes+held); err != nil {
					return err
				}
			}

			h.logger.Debug("chunk written to device", "chunk", chunkNum+1, "bytes", n)

			chunkNum++
			writtenBytes += int64(n)
			progress.Store(writtenBytes)

			if writtenBytes-lastSyncedAt >= syncInterval {
				if err := deviceFile.Sync(); err != nil {
					return fmt.Errorf("failed to sync device: %w", err)
				}
				lastSyncedAt = writtenBytes
			}

			// Progress tracks the download (compressed bytes vs Content-Length),
			// not the decompressed output, so it stays accurate for .xz images.
			downloadedBytes := source.BytesRead()

			// Report progress only when integer percentage changes (5% to 95% range, 90% for download)
			if contentLength > 0 {
				// Calculate download progress (0.0 to 1.0)
				downloadProgress := float64(downloadedBytes) / float64(contentLength)
				// Map to 5% to 95% range (90% for download)
				currentProgress := int32(5 + downloadProgress*90)

				// Only report if progress increased by at least 1%
				if currentProgress > lastReportedProgress {
					progressMB := float64(downloadedBytes) / (1024 * 1024)
					// Report command status with calculated progress
					h.reportCommandStatus(commandID, "in_progress", currentProgress,
						fmt.Sprintf("Downloading OS image: %d%% (%.2f MB)", currentProgress, progressMB))

					h.logger.Info("download progress",
						"chunks", chunkNum,
						"downloaded_bytes", downloadedBytes,
						"written_bytes", writtenBytes,
						"mb", fmt.Sprintf("%.2f", progressMB),
						"overall_progress", currentProgress)

					lastReportedProgress = currentProgress
				}
			} else {
				// If content length is unknown, report progress based on chunks (less frequently)
				// Estimate progress (assume ~100MB chunks for estimation)
				estimatedProgress := int32(5 + (chunkNum*90)/100) // Rough estimate
				if estimatedProgress > 95 {
					estimatedProgress = 95
				}
				// Only report if progress increased by at least 1%
				if estimatedProgress > lastReportedProgress {
					progressMB := float64(downloadedBytes) / (1024 * 1024)
					h.reportCommandStatus(commandID, "in_progress", estimatedProgress,
						fmt.Sprintf("Downloading OS image: %d%% (%.2f MB)", estimatedProgress, progressMB))

					h.logger.Info("download progress",
						"chunks", chunkNum,
						"downloaded_bytes", downloadedBytes,
						"written_bytes", writtenBytes,
						"mb", fmt.Sprintf("%.2f", progressMB),
						"overall_progress", estimatedProgress)

					lastReportedProgress = estimatedProgress
				}
			}
		}

		// Check for errors after processing any data we read
		if err != nil {
			if err == io.EOF {
				// EOF reached. The decoder must also have COMPLETED: for
				// system xz that is the process exit status, judged here and
				// not only by the deferred cleanup.
				if ferr := imageReader.Finish(); ferr != nil {
					return fmt.Errorf("failed to read chunk: image stream did not complete cleanly: %w", ferr)
				}
				h.logger.Info("reached end of file", "downloaded_bytes", source.BytesRead(), "written_bytes", writtenBytes)
				break
			}
			// Real error occurred
			return fmt.Errorf("failed to read chunk: %w", err)
		}
	}

	h.logger.Info("download completed",
		"total_chunks", chunkNum,
		"downloaded_bytes", source.BytesRead(),
		"written_bytes", writtenBytes,
		"written_mb", fmt.Sprintf("%.2f", float64(writtenBytes)/(1024*1024)),
		"compression", compression)

	// After all chunks are written, verify checksum
	h.logger.Info("starting checksum verification", "expected_checksum", expectedChecksum)
	calculatedHash := hex.EncodeToString(hash.Sum(nil))
	expectedHashLower := strings.ToLower(strings.TrimSpace(expectedChecksum))
	calculatedHashLower := strings.ToLower(calculatedHash)

	h.logger.Info("checksum calculated", "calculated_checksum", calculatedHash)

	if calculatedHashLower != expectedHashLower {
		h.logger.Error("checksum verification failed",
			"expected", expectedHashLower,
			"calculated", calculatedHashLower)
		// The head was never written, so there is no valid partition table for
		// what is on the disk — but a PREVIOUS install's table may still be
		// there, and it would make this image look bootable. The deferred
		// invalidation above destroys it; this branch no longer calls it
		// directly, so there is exactly one place that decides.
		//
		// This exact string is load-bearing: handleInstallOS matches on it to
		// produce the operator-facing message, and isTransientDownloadError
		// deliberately does NOT list it, so a mismatch is never retried.
		return fmt.Errorf("checksum verification failed: expected %s, got %s (data corruption detected)", expectedHashLower, calculatedHashLower)
	}

	h.logger.Info("checksum verification passed")

	// Only now does the image become bootable. Everything downstream —
	// sfdisk --relocate, parted resizepart, partprobe, the partition
	// verification and strip_identity — reads the primary GPT, so the head must
	// land before any of them and after the digest is known.
	if err := writeAt(head, 0); err != nil {
		return fmt.Errorf("failed to write image head: %w", err)
	}
	if err := deviceFile.Sync(); err != nil {
		return fmt.Errorf("failed to sync image head: %w", err)
	}
	committed = true
	h.logger.Info("image head committed after digest match", "head_bytes", len(head))

	// Report 95% - download and write complete, starting resize
	h.reportCommandStatus(commandID, "in_progress", 95, "Download complete, expanding filesystem")

	// Sync device file
	h.logger.Info("syncing device to ensure all data is written to disk")
	if err := deviceFile.Sync(); err != nil {
		return fmt.Errorf("failed to sync device: %w", err)
	}

	// Expand root partition (typically partition 2) to use full disk space
	h.logger.Info("expanding root partition after OS installation", "device", targetDevice)
	if err := h.expandRootPartition(targetDevice); err != nil {
		h.logger.Error("failed to expand root partition after OS installation", "device", targetDevice, "error", err)
		return fmt.Errorf("failed to expand root partition: %w", err)
	}

	// Refresh partition table so kernel recognizes new partitions
	h.logger.Info("refreshing partition table", "device", targetDevice)
	partprobeCmd := exec.Command("partprobe", targetDevice)
	var partprobeStderr bytes.Buffer
	partprobeCmd.Stderr = &partprobeStderr
	if err := partprobeCmd.Run(); err != nil {
		stderrStr := partprobeStderr.String()
		h.logger.Warn("partprobe failed",
			"error", err,
			"device", targetDevice,
			"stderr", stderrStr)
		// Don't fail installation, but log warning - partitions might still be readable
	} else {
		h.logger.Info("partition table refreshed successfully", "device", targetDevice)
	}

	// Verify partitions were created
	h.logger.Info("verifying partitions after installation", "device", targetDevice)
	if h.storageReader != nil {
		devices, err := h.storageReader.DetectDevices()
		if err != nil {
			h.logger.Warn("failed to detect devices for partition verification", "error", err)
		} else {
			if device, exists := devices[targetDevice]; exists {
				if len(device.Partitions) > 0 {
					h.logger.Info("partitions detected after installation",
						"device", targetDevice,
						"partition_count", len(device.Partitions))
					for i, part := range device.Partitions {
						totalSize := part.UsedSpace + part.AvailableSpace
						h.logger.Info("partition detected",
							"device", targetDevice,
							"partition_index", i,
							"partition_id", part.PartitionId,
							"filesystem", part.Filesystem,
							"total_size_bytes", totalSize,
							"mount_point", part.MountPoint)
					}
				} else {
					h.logger.Warn("no partitions detected after installation",
						"device", targetDevice,
						"total_bytes_written", writtenBytes)
					// This is a warning, not an error - the image might be valid but kernel needs time
				}
			} else {
				h.logger.Warn("device not found in storage reader after installation",
					"device", targetDevice)
			}
		}
	} else {
		h.logger.Warn("storage reader not available for partition verification")
	}

	h.logger.Info("image downloaded and written successfully",
		"chunks", chunkNum,
		"total_bytes", writtenBytes,
		"total_mb", fmt.Sprintf("%.2f", float64(writtenBytes)/(1024*1024)),
		"checksum", calculatedHash)
	return nil
}

// stripIdentityOnDevice mounts the root partition of a freshly installed
// device and removes the machine identity baked into a backup image (see
// stripIdentityAt). Refuses to touch the live root filesystem.
func (h *CommandHandler) stripIdentityOnDevice(targetDevice string) error {
	rootPart, rootPartNum, err := h.detectRootPartition(targetDevice)
	if err != nil {
		h.logger.Warn("failed to auto-detect root partition for identity strip, defaulting to partition 2",
			"error", err, "device", targetDevice)
		rootPartNum = 2
		rootPart = getPartitionPath(targetDevice, rootPartNum)
	}

	mountPoint := "/mnt/tmp-strip-identity"
	if err := os.MkdirAll(mountPoint, 0o755); err != nil {
		return fmt.Errorf("failed to create mount point %s: %w", mountPoint, err)
	}
	mountCmd := exec.Command("mount", rootPart, mountPoint)
	var mountStderr bytes.Buffer
	mountCmd.Stderr = &mountStderr
	if err := mountCmd.Run(); err != nil {
		return fmt.Errorf("failed to mount root partition %s: %w (stderr: %s)", rootPart, err, mountStderr.String())
	}
	defer func() {
		if err := exec.Command("umount", mountPoint).Run(); err != nil {
			h.logger.Warn("failed to unmount after identity strip", "mount_point", mountPoint, "error", err)
		}
		_ = os.Remove(mountPoint)
	}()

	// Never strip the LIVE root (a re-mount of an in-use device shares the
	// superblock, so both mounts report the same st_dev).
	if sameFS, err := sameFilesystem(mountPoint, "/"); err != nil {
		return fmt.Errorf("cannot verify the target is not the live root filesystem: %w", err)
	} else if sameFS {
		return fmt.Errorf("target volume is the live root filesystem, refusing identity strip")
	}

	stripIdentityAt(mountPoint)
	syscall.Sync()
	return nil
}

// expandRootPartition grows the root filesystem partition to use all available space on the target device.
// It auto-detects the root partition (largest ext4 partition) or falls back to partition 2.
func (h *CommandHandler) expandRootPartition(targetDevice string) error {
	// Auto-detect root partition
	var rootPart string
	var rootPartNum int
	detectedPart, detectedNum, err := h.detectRootPartition(targetDevice)
	if err != nil {
		h.logger.Warn("failed to auto-detect root partition for expansion, defaulting to partition 2",
			"error", err,
			"device", targetDevice)
		rootPartNum = 2
		rootPart = getPartitionPath(targetDevice, rootPartNum)
	} else {
		rootPart = detectedPart
		rootPartNum = detectedNum
		h.logger.Info("auto-detected root partition for expansion",
			"partition_number", rootPartNum,
			"partition_path", rootPart)
	}

	h.logger.Info("starting root partition expansion",
		"device", targetDevice,
		"root_partition", rootPart,
		"partition_number", rootPartNum)

	// Captured images carry a GPT sized for the SOURCE disk: on a target of a
	// different size the backup header location / alternate-LBA no longer
	// match the device, and parted refuses to resize. Relocate the backup GPT
	// to the real end of this disk first. Best-effort: a no-op for MBR disks,
	// and an sfdisk too old for --relocate leaves same-size deployments
	// working exactly as before.
	if out, relErr := exec.Command("sfdisk", "--relocate", "gpt-bak-std", targetDevice).CombinedOutput(); relErr != nil {
		h.logger.Warn("GPT backup relocation failed (continuing; only needed when the target disk size differs from the image's source)",
			"device", targetDevice, "error", relErr, "output", strings.TrimSpace(string(out)))
	}

	// Step 1: Resize root partition to 100% of the device using parted
	h.logger.Info("resizing partition with parted", "device", targetDevice, "partition", rootPartNum)
	partedCmd := exec.Command("parted", "-s", targetDevice, "resizepart", strconv.Itoa(rootPartNum), "100%")
	var partedStderr bytes.Buffer
	partedCmd.Stderr = &partedStderr

	if err := partedCmd.Run(); err != nil {
		stderrStr := partedStderr.String()
		h.logger.Error("parted resizepart failed",
			"device", targetDevice,
			"partition", "2",
			"error", err,
			"stderr", stderrStr)
		return fmt.Errorf("failed to resize partition 2 on %s: %w (stderr: %s)", targetDevice, err, stderrStr)
	}

	if stderrStr := partedStderr.String(); stderrStr != "" {
		h.logger.Debug("parted resizepart output", "stderr", stderrStr)
	}
	h.logger.Info("partition resized successfully with parted", "device", targetDevice, "partition", "2")

	// Step 2: Run e2fsck on the root partition to ensure filesystem consistency
	// Use -p (preen) and -f:
	//   -p: automatically fix problems that can be safely fixed, no interactive prompts
	//   -f: force a full check even if filesystem seems clean
	h.logger.Info("running e2fsck before filesystem resize", "partition", rootPart)
	checkCmd := exec.Command("e2fsck", "-p", "-f", rootPart)
	var checkStdout, checkStderr bytes.Buffer
	checkCmd.Stdout = &checkStdout
	checkCmd.Stderr = &checkStderr

	err = checkCmd.Run()
	exitCode := 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			if status, ok := exitErr.Sys().(syscall.WaitStatus); ok {
				exitCode = status.ExitStatus()
			}
		}
	}

	// e2fsck exit codes:
	// 0: no errors, 1: errors corrected, 2/4/8: more serious issues
	if err != nil && exitCode != 1 {
		h.logger.Error("e2fsck failed",
			"partition", rootPart,
			"exit_code", exitCode,
			"error", err,
			"stdout", checkStdout.String(),
			"stderr", checkStderr.String())
		return fmt.Errorf("e2fsck failed on %s: exit code %d (stderr: %s)", rootPart, exitCode, checkStderr.String())
	}

	if exitCode == 1 {
		h.logger.Info("e2fsck completed with corrections",
			"partition", rootPart,
			"stdout", checkStdout.String(),
			"stderr", checkStderr.String())
	} else {
		h.logger.Info("e2fsck completed without critical errors",
			"partition", rootPart,
			"exit_code", exitCode)
	}

	// Step 3: Grow filesystem to fill the expanded partition
	h.logger.Info("resizing filesystem to fill partition", "partition", rootPart)
	resizeCmd := exec.Command("resize2fs", rootPart)
	var resizeStdout, resizeStderr bytes.Buffer
	resizeCmd.Stdout = &resizeStdout
	resizeCmd.Stderr = &resizeStderr

	if err := resizeCmd.Run(); err != nil {
		h.logger.Error("resize2fs failed",
			"partition", rootPart,
			"error", err,
			"stdout", resizeStdout.String(),
			"stderr", resizeStderr.String())
		return fmt.Errorf("resize2fs failed on %s: %w (stderr: %s)", rootPart, err, resizeStderr.String())
	}

	h.logger.Info("filesystem resized successfully",
		"partition", rootPart,
		"stdout", resizeStdout.String())

	return nil
}

// detectRootPartition automatically detects the root partition on a target device.
// It looks for the largest ext4 partition, which is typically the root filesystem.
// Returns the partition path and partition number, or an error if detection fails.
func (h *CommandHandler) detectRootPartition(targetDevice string) (partitionPath string, partitionNum int, err error) {
	if h.storageReader == nil {
		return "", 0, fmt.Errorf("storage reader not available")
	}

	// Get all devices and their partitions
	devices, err := h.storageReader.DetectDevices()
	if err != nil {
		return "", 0, fmt.Errorf("failed to detect devices: %w", err)
	}

	// Find the target device
	device, exists := devices[targetDevice]
	if !exists {
		return "", 0, fmt.Errorf("target device %s not found in detected devices", targetDevice)
	}

	// Find the largest ext4 partition
	var largestPartition *proto.StoragePartition
	var largestSize uint64 = 0

	for _, partition := range device.Partitions {
		// Look for ext4 filesystem
		if strings.ToLower(partition.Filesystem) == "ext4" {
			totalSize := partition.UsedSpace + partition.AvailableSpace
			if totalSize > largestSize {
				largestSize = totalSize
				largestPartition = partition
			}
		}
	}

	if largestPartition == nil {
		return "", 0, fmt.Errorf("no ext4 partition found on device %s", targetDevice)
	}

	// Extract partition number from partition path
	// Examples: /dev/nvme0n1p2 -> 2, /dev/sda2 -> 2, /dev/mmcblk0p2 -> 2
	partPath := largestPartition.PartitionId
	baseName := filepath.Base(partPath)

	// Try to extract number from end of partition name
	// For nvme/mmc: nvme0n1p2 -> extract "2"
	// For sda: sda2 -> extract "2"
	var partNum int
	if strings.Contains(baseName, "p") {
		// Format like nvme0n1p2 or mmcblk0p2
		parts := strings.Split(baseName, "p")
		if len(parts) > 1 {
			if num, err := strconv.Atoi(parts[len(parts)-1]); err == nil {
				partNum = num
			}
		}
	} else {
		// Format like sda2 - extract trailing digits
		for i := len(baseName) - 1; i >= 0; i-- {
			if baseName[i] >= '0' && baseName[i] <= '9' {
				// Found a digit, extract all trailing digits
				start := i
				for start > 0 && baseName[start-1] >= '0' && baseName[start-1] <= '9' {
					start--
				}
				if num, err := strconv.Atoi(baseName[start:]); err == nil {
					partNum = num
					break
				}
			}
		}
	}

	if partNum == 0 {
		return "", 0, fmt.Errorf("failed to extract partition number from %s", partPath)
	}

	h.logger.Info("detected root partition",
		"partition_path", partPath,
		"partition_number", partNum,
		"filesystem", largestPartition.Filesystem,
		"size_bytes", largestSize)

	return partPath, partNum, nil
}

// getPartitionPath computes the partition device path for a given base device and partition number.
// Examples:
//
//	/dev/sda + 2       -> /dev/sda2
//	/dev/nvme0n1 + 2   -> /dev/nvme0n1p2
//	/dev/mmcblk0 + 2   -> /dev/mmcblk0p2
func getPartitionPath(device string, partNum int) string {
	if device == "" {
		return ""
	}

	// Extract base name (after last '/')
	base := device
	if idx := strings.LastIndex(device, "/"); idx != -1 && idx < len(device)-1 {
		base = device[idx+1:]
	}

	// If base ends with a digit, use 'p' separator (nvme0n1p2, mmcblk0p2)
	suffix := strconv.Itoa(partNum)
	if len(base) > 0 {
		lastChar := base[len(base)-1]
		if lastChar >= '0' && lastChar <= '9' {
			return device + "p" + suffix
		}
	}

	// Otherwise append partition number directly (sda2)
	return device + suffix
}

// handleInstallAgentOnVolume handles commands to install the agent onto a newly installed OS volume.
// It mounts the root partition of the target device, detects the OS, downloads the appropriate agent
// package from the backend CDN, installs it into the target filesystem, copies the adoption file,
// and installs the systemd service file.
func (h *CommandHandler) handleInstallAgentOnVolume(commandID string, cmd *proto.InstallAgentOnVolumeCommand) error {
	h.logger.Info("install agent on volume command received",
		"command_id", commandID,
		"target_device", cmd.TargetDevice,
		"root_partition", cmd.RootPartition,
		"agent_version", cmd.AgentVersion)

	// Report command status: in_progress
	h.reportCommandStatus(commandID, "in_progress", 0, "Starting agent installation on volume")

	if cmd.TargetDevice == "" {
		errMsg := "target_device is required for install_agent_on_volume command"
		h.reportCommandStatus(commandID, "failed", 0, errMsg)
		h.sendStatusUpdate("agent_installation_failed", errMsg)
		return errors.New(errMsg)
	}

	if h.adoptionConfig == nil {
		errMsg := "adoption config not available for install_agent_on_volume"
		h.reportCommandStatus(commandID, "failed", 0, errMsg)
		h.sendStatusUpdate("agent_installation_failed", errMsg)
		return errors.New(errMsg)
	}

	// Determine root partition
	var rootPart string
	var rootPartNum int
	if cmd.RootPartition != 0 {
		// Use explicitly specified partition
		rootPartNum = int(cmd.RootPartition)
		rootPart = getPartitionPath(cmd.TargetDevice, rootPartNum)
		h.logger.Info("using explicitly specified root partition",
			"partition_number", rootPartNum,
			"partition_path", rootPart)
	} else {
		// Auto-detect root partition
		h.logger.Info("auto-detecting root partition for target device", "device", cmd.TargetDevice)
		detectedPart, detectedNum, err := h.detectRootPartition(cmd.TargetDevice)
		if err != nil {
			h.logger.Warn("failed to auto-detect root partition, defaulting to partition 2",
				"error", err,
				"device", cmd.TargetDevice)
			rootPartNum = 2
			rootPart = getPartitionPath(cmd.TargetDevice, rootPartNum)
		} else {
			rootPart = detectedPart
			rootPartNum = detectedNum
			h.logger.Info("auto-detected root partition",
				"partition_number", rootPartNum,
				"partition_path", rootPart)
		}
	}

	// Report progress: mounting partition
	h.reportCommandStatus(commandID, "in_progress", 10, "Mounting root partition")

	// Create temporary mount point
	mountPoint := "/mnt/tmp-agent-install"
	if err := os.MkdirAll(mountPoint, 0755); err != nil {
		errMsg := fmt.Sprintf("Failed to create mount point: %v", err)
		h.logger.Error("failed to create mount point", "command_id", commandID, "error", err)
		h.reportCommandStatus(commandID, "failed", 0, errMsg)
		h.sendStatusUpdate("agent_installation_failed", errMsg)
		return fmt.Errorf("failed to create mount point %s: %w", mountPoint, err)
	}

	// Mount the root partition
	h.logger.Info("mounting root partition for agent installation",
		"partition", rootPart,
		"mount_point", mountPoint)
	mountCmd := exec.Command("mount", rootPart, mountPoint)
	var mountStderr bytes.Buffer
	mountCmd.Stderr = &mountStderr
	if err := mountCmd.Run(); err != nil {
		errMsg := fmt.Sprintf("Failed to mount root partition: %v", err)
		h.logger.Error("failed to mount root partition", "command_id", commandID, "error", err)
		h.reportCommandStatus(commandID, "failed", 0, errMsg)
		h.sendStatusUpdate("agent_installation_failed", errMsg)
		return fmt.Errorf("failed to mount root partition %s: %w (stderr: %s)", rootPart, err, mountStderr.String())
	}
	defer func() {
		umountCmd := exec.Command("umount", mountPoint)
		var umountStderr bytes.Buffer
		umountCmd.Stderr = &umountStderr
		if err := umountCmd.Run(); err != nil {
			h.logger.Warn("failed to unmount root partition after agent install",
				"mount_point", mountPoint,
				"error", err,
				"stderr", umountStderr.String())
		} else {
			h.logger.Info("unmounted root partition after agent install", "mount_point", mountPoint)
		}
	}()

	// Refuse to operate on the LIVE root filesystem. install_on_volume is for
	// baking the agent into a freshly installed OS; aimed at the running root
	// it becomes an update_agent that sidesteps the anti-rollback floor (an
	// old-but-signed package would overwrite the running agent). Mounting an
	// in-use device again shares the superblock, so both mounts report the
	// same st_dev.
	if sameFS, err := sameFilesystem(mountPoint, "/"); err != nil {
		errMsg := fmt.Sprintf("Cannot verify the target volume is not the live root filesystem: %v", err)
		h.reportCommandStatus(commandID, "failed", 0, errMsg)
		h.sendStatusUpdate("agent_installation_failed", errMsg)
		return errors.New(errMsg)
	} else if sameFS {
		errMsg := "Target volume is the live root filesystem, refusing agent install (use update_agent instead)"
		h.reportCommandStatus(commandID, "failed", 0, errMsg)
		h.sendStatusUpdate("agent_installation_failed", errMsg)
		return errors.New(errMsg)
	}

	// Detect OS type from /etc/os-release
	osReleasePath := filepath.Join(mountPoint, "etc", "os-release")
	osID, osLike, err := readOSRelease(osReleasePath)
	if err != nil {
		h.logger.Warn("failed to read os-release on target volume, falling back to tar.gz package",
			"path", osReleasePath, "error", err)
	}

	pkgType := selectPackageType(osID, osLike)
	h.logger.Info("selected agent package type based on target OS",
		"os_id", osID,
		"os_like", osLike,
		"pkg_type", pkgType)

	// Determine architecture based on current agent
	arch := mapArch(runtime.GOARCH)
	h.logger.Info("determined agent architecture for CDN download", "arch", arch)

	// Determine version (default to latest)
	version := strings.TrimSpace(cmd.AgentVersion)
	if version == "" {
		version = "latest"
	}

	// Which agent lands on the disk: the full managing agent (default) or the
	// telemetry-only watcher/Watcher. Unknown values are refused
	// rather than defaulted — a platform newer than this agent may know
	// variants this code does not, and installing the WRONG agent silently is
	// exactly the failure the conditional dispatch floor exists to prevent.
	variant := strings.TrimSpace(cmd.GetVariant())
	cdnPathSeg := "agent"
	switch variant {
	case "", "full":
		variant = "full"
	case "watcher":
		cdnPathSeg = "watcher"
	default:
		errMsg := fmt.Sprintf("unknown agent variant %q", variant)
		h.reportCommandStatus(commandID, "failed", 0, errMsg)
		h.sendStatusUpdate("agent_installation_failed", errMsg)
		return errors.New(errMsg)
	}

	// Build CDN URL from adoption config platform URL
	baseURL := strings.TrimRight(h.adoptionConfig.PlatformURL, "/")

	// Ensure URL has a scheme (default to http:// if missing)
	if !strings.HasPrefix(baseURL, "http://") && !strings.HasPrefix(baseURL, "https://") {
		baseURL = "http://" + baseURL
	}

	agentURL := fmt.Sprintf("%s/cdn/%s/%s/%s/%s", baseURL, cdnPathSeg, version, arch, pkgType)
	h.logger.Info("downloading agent package from CDN",
		"url", agentURL,
		"version", version,
		"arch", arch,
		"variant", variant,
		"pkg_type", pkgType)

	// Report progress: downloading agent package
	h.reportCommandStatus(commandID, "in_progress", 30, "Downloading agent package")

	// Download agent package to temporary file
	tmpFile, err := os.CreateTemp("", "orchestrator-agent-*."+strings.ReplaceAll(pkgType, ".", "_"))
	if err != nil {
		return fmt.Errorf("failed to create temporary file for agent package: %w", err)
	}
	defer func() {
		tmpFile.Close()
		os.Remove(tmpFile.Name())
	}()

	resp, err := boundedHTTPClient(agentDownloadTimeout).Get(agentURL)
	if err != nil {
		errMsg := fmt.Sprintf("Failed to download agent package: %v", err)
		h.logger.Error("failed to download agent package", "command_id", commandID, "error", err)
		h.reportCommandStatus(commandID, "failed", 0, errMsg)
		h.sendStatusUpdate("agent_installation_failed", errMsg)
		return fmt.Errorf("failed to download agent package from %s: %w", agentURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		errMsg := fmt.Sprintf("Failed to download agent package: HTTP %d", resp.StatusCode)
		h.logger.Error("failed to download agent package", "command_id", commandID, "status_code", resp.StatusCode)
		h.reportCommandStatus(commandID, "failed", 0, errMsg)
		h.sendStatusUpdate("agent_installation_failed", errMsg)
		return fmt.Errorf("failed to download agent package: HTTP %d (%s)", resp.StatusCode, string(body))
	}

	if err := copyBoundedPackage(tmpFile, resp.Body); err != nil {
		errMsg := fmt.Sprintf("Failed to save downloaded agent package: %v", err)
		h.logger.Error("failed to save downloaded agent package", "command_id", commandID, "error", err)
		h.reportCommandStatus(commandID, "failed", 0, errMsg)
		h.sendStatusUpdate("agent_installation_failed", errMsg)
		return fmt.Errorf("failed to save downloaded agent package: %w", err)
	}

	if _, err := tmpFile.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("failed to rewind temporary agent package file: %w", err)
	}

	// Verify the detached signature before writing the agent into the target OS
	// (fail-closed): a missing/invalid signature aborts the install.
	h.reportCommandStatus(commandID, "in_progress", 50, "Verifying agent package signature")
	pkgBytes, err := os.ReadFile(tmpFile.Name())
	if err != nil {
		errMsg := fmt.Sprintf("Failed to read agent package for verification: %v", err)
		h.reportCommandStatus(commandID, "failed", 0, errMsg)
		h.sendStatusUpdate("agent_installation_failed", errMsg)
		return fmt.Errorf("failed to read agent package: %w", err)
	}
	sigBytes, err := downloadSignature(agentURL + ".sig")
	if err != nil {
		errMsg := fmt.Sprintf("Agent package signature unavailable, refusing install: %v", err)
		h.reportCommandStatus(commandID, "failed", 0, errMsg)
		h.sendStatusUpdate("agent_installation_failed", errMsg)
		return errors.New(errMsg)
	}
	if err := signing.VerifyDetached(pkgBytes, sigBytes); err != nil {
		errMsg := fmt.Sprintf("Agent package signature invalid, refusing install: %v", err)
		h.reportCommandStatus(commandID, "failed", 0, errMsg)
		h.sendStatusUpdate("agent_installation_failed", errMsg)
		return errors.New(errMsg)
	}
	h.logger.Info("install_on_volume: agent package signature verified", "command_id", commandID)

	// Version binding: the requested version is mandatory here — make
	// sure the (signed) package actually declares it, so a CDN cannot serve
	// an older signed artifact under a newer name. No downgrade floor: a
	// fresh OS install has no running-agent version to protect.
	if pkgType == "deb" {
		declared, err := pkgver.DebControlVersion(pkgBytes)
		if err != nil {
			errMsg := fmt.Sprintf("Cannot read the package's declared version, refusing install: %v", err)
			h.reportCommandStatus(commandID, "failed", 0, errMsg)
			h.sendStatusUpdate("agent_installation_failed", errMsg)
			return errors.New(errMsg)
		}
		if version != "latest" && !pkgver.Equal(declared, version) {
			errMsg := fmt.Sprintf("Package declares version %s but %s was requested, refusing install", declared, version)
			h.reportCommandStatus(commandID, "failed", 0, errMsg)
			h.sendStatusUpdate("agent_installation_failed", errMsg)
			return errors.New(errMsg)
		}
	}

	// Install exactly the verified bytes (see handleUpdateAgent).
	if err := os.WriteFile(tmpFile.Name(), pkgBytes, 0o600); err != nil {
		errMsg := fmt.Sprintf("Failed to persist verified package: %v", err)
		h.reportCommandStatus(commandID, "failed", 0, errMsg)
		h.sendStatusUpdate("agent_installation_failed", errMsg)
		return fmt.Errorf("failed to persist verified package: %w", err)
	}

	// Report progress: installing agent package
	h.reportCommandStatus(commandID, "in_progress", 60, "Installing agent package")

	// Install agent into target filesystem
	if err := h.installAgentPackageOnTarget(mountPoint, tmpFile.Name(), pkgType, variant); err != nil {
		errMsg := fmt.Sprintf("Failed to install agent package: %v", err)
		h.logger.Error("failed to install agent package", "command_id", commandID, "error", err)
		h.reportCommandStatus(commandID, "failed", 0, errMsg)
		h.sendStatusUpdate("agent_installation_failed", errMsg)
		return fmt.Errorf("failed to install agent package on target volume: %w", err)
	}

	// Report progress: configuring boot partition for EEPROM
	h.reportCommandStatus(commandID, "in_progress", 70, "Configuring boot partition for EEPROM")

	// Configure boot partition (mount and write config.txt with EEPROM settings)
	if err := h.configureBootPartitionEEPROM(cmd.TargetDevice); err != nil {
		// Log warning but don't fail - EEPROM config is optional for non-Raspberry Pi systems
		h.logger.Warn("failed to configure boot partition for EEPROM", "command_id", commandID, "error", err)
	}

	// Report progress: configuring adoption (EEPROM on Raspberry Pi, file on others)
	h.reportCommandStatus(commandID, "in_progress", 80, "Configuring adoption")

	// Configure adoption (write to EEPROM on Raspberry Pi, copy file on others)
	if err := h.copyAdoptionFileToTarget(mountPoint, variant); err != nil {
		errMsg := fmt.Sprintf("Failed to configure adoption: %v", err)
		h.logger.Error("failed to configure adoption", "command_id", commandID, "error", err)
		h.reportCommandStatus(commandID, "failed", 0, errMsg)
		h.sendStatusUpdate("agent_installation_failed", errMsg)
		return fmt.Errorf("failed to configure adoption: %w", err)
	}

	// Report progress: enabling service
	h.reportCommandStatus(commandID, "in_progress", 90, "Enabling orchestrator-agent service")

	// Enable orchestrator-agent service to start on boot
	if err := h.enableAgentServiceOnTarget(mountPoint, variant); err != nil {
		errMsg := fmt.Sprintf("Failed to enable orchestrator-agent service: %v", err)
		h.logger.Error("failed to enable orchestrator-agent service", "command_id", commandID, "error", err)
		h.reportCommandStatus(commandID, "failed", 0, errMsg)
		h.sendStatusUpdate("agent_installation_failed", errMsg)
		return fmt.Errorf("failed to enable orchestrator-agent service: %w", err)
	}

	// Make sure the installed OS will actually bring up its network. Both of these
	// used to run only from provision_connection, which is an OPTIONAL command — a
	// plain install_os + install_agent flow (what the UI buttons do) got
	// neither, so the target booted with an empty
	// /etc/netplan and no persistent networkd enablement. See
	// ensureNetworkdEnabledOnRoot for the boot race that then strands the node.
	//
	// Best-effort on purpose: a freshly written agent is worth keeping even if the
	// network belt-and-braces could not be applied, and both are no-ops on an image
	// that manages its network some other way.
	if err := h.ensureNetworkConfigOnRoot(mountPoint); err != nil {
		h.logger.Warn("failed to write default network config on target OS", "error", err)
	}
	if err := h.ensureNetworkdEnabledOnRoot(mountPoint); err != nil {
		h.logger.Warn("failed to enable systemd-networkd on target OS", "error", err)
	}

	// Report command success
	h.reportCommandStatus(commandID, "success", 100, "Agent installation completed successfully")

	// Final status update
	h.sendStatusUpdate("online", "Agent installation completed successfully")

	h.logger.Info("install agent on volume command completed successfully",
		"command_id", commandID,
		"target_device", cmd.TargetDevice,
		"root_partition", rootPart)
	return nil
}

// readOSRelease parses /etc/os-release and returns ID and ID_LIKE values (lowercased).
func readOSRelease(path string) (osID string, osLike []string, err error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", nil, err
	}
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "ID=") {
			osID = strings.Trim(strings.TrimPrefix(line, "ID="), `"'`)
			osID = strings.ToLower(osID)
		}
		if strings.HasPrefix(line, "ID_LIKE=") {
			val := strings.Trim(strings.TrimPrefix(line, "ID_LIKE="), `"'`)
			for _, part := range strings.Fields(val) {
				osLike = append(osLike, strings.ToLower(part))
			}
		}
	}
	return osID, osLike, nil
}

// selectPackageType chooses deb/rpm/tar.gz based on OS ID and ID_LIKE values.
func selectPackageType(osID string, osLike []string) string {
	all := append([]string{}, osLike...)
	if osID != "" {
		all = append(all, osID)
	}
	for _, v := range all {
		if v == "ubuntu" || v == "debian" {
			return "deb"
		}
		if v == "rhel" || v == "centos" || v == "fedora" {
			return "rpm"
		}
	}
	// Fallback
	return "tar.gz"
}

// mapArch maps runtime.GOARCH to CDN arch string.
func mapArch(goarch string) string {
	switch goarch {
	case "amd64":
		return "amd64"
	case "arm64":
		return "arm64"
	default:
		return "arm64"
	}
}

// handleUpdateAgent self-updates the running managed agent: download the given
// version from the platform CDN, install it over the live OS (no chroot),
// report success, then restart the agent service so the new binary takes over.
// downloadSignature fetches a small detached-signature file into memory. Used to
// verify an agent package before installing it as root.
// sameFilesystem reports whether two paths live on the same filesystem
// (identical st_dev). A block device mounted a second time shares its
// superblock, so a second mount of the live root is detected too.
func sameFilesystem(a, b string) (bool, error) {
	var sa, sb syscall.Stat_t
	if err := syscall.Stat(a, &sa); err != nil {
		return false, fmt.Errorf("stat %s: %w", a, err)
	}
	if err := syscall.Stat(b, &sb); err != nil {
		return false, fmt.Errorf("stat %s: %w", b, err)
	}
	return sa.Dev == sb.Dev, nil
}

// --- bounded HTTP for the synchronous command loop ------------------------
//
// Four downloads on this file used a bare http.Get, which uses
// Go's default client — and that client has NO timeout of any kind. A stalled
// CDN or a black-holed connection blocked the handler forever.
//
// That is worse than a failed command, because ListenForCommands calls handlers
// INLINE and the same select arm dispatches web-terminal frames. A blocked
// handler leaves the node ONLINE and HEARTBEATING while accepting nothing —
// including the terminal you would use to diagnose it. install_os and
// download_file are hardened against exactly this; the agent's own update path
// needs it most, because it is the path that breaks the ability to ship a fix.
//
// An overall Timeout is right for these four, unlike the OS image: they are the
// agent package (~10 MB), its signature (~100 bytes) and an EEPROM blob (a few
// MB). None has a legitimate reason to take minutes, so "slow" and "hung" are
// the same thing here and a single deadline says so.
const (
	agentDownloadTimeout = 5 * time.Minute
	signatureTimeout     = 30 * time.Second
)

// maxAgentPackageBytes bounds a downloaded agent/EEPROM package before it is read
// into memory and signature-checked. A real agent .deb is a few MiB and an EEPROM
// package smaller still; this leaves generous headroom while stopping a
// compromised or plaintext-HTTP CDN from OOMing the agent — most sharply in the
// RAM-rooted recovery initramfs, where the copy plus os.ReadFile share the same
// tmpfs — with an unbounded stream that is never even signature-checked.
// Every other agent fetch is already capped.
const maxAgentPackageBytes = 128 << 20 // 128 MiB

// copyBoundedPackage copies src into dst, refusing more than maxAgentPackageBytes.
// LimitReader(+1) lets a stream exactly at the cap through and only the one that
// EXCEEDS it fails, fail-closed.
func copyBoundedPackage(dst io.Writer, src io.Reader) error {
	n, err := io.Copy(dst, io.LimitReader(src, maxAgentPackageBytes+1))
	if err != nil {
		return err
	}
	if n > maxAgentPackageBytes {
		return fmt.Errorf("downloaded package exceeds the %d-byte cap", int64(maxAgentPackageBytes))
	}
	return nil
}

// boundedHTTPClient returns a client with deadlines on every phase that can
// hang, plus an overall ceiling. One-shot: its connection is closed with the
// response body (newOneShotTransport).
func boundedHTTPClient(overall time.Duration) *http.Client {
	return &http.Client{
		Timeout:   overall,
		Transport: newOneShotTransport(),
	}
}

func downloadSignature(url string) ([]byte, error) {
	resp, err := boundedHTTPClient(signatureTimeout).Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	// Signatures are tiny (ECDSA-P384 ASN.1 DER ~100 bytes); cap the read.
	return io.ReadAll(io.LimitReader(resp.Body, 4096))
}

func (h *CommandHandler) handleUpdateAgent(commandID string, cmd *proto.UpdateAgentCommand) error {
	h.logger.Info("update agent command received", "command_id", commandID, "agent_version", cmd.AgentVersion)
	h.reportCommandStatus(commandID, "in_progress", 0, "Starting agent self-update")

	if h.adoptionConfig == nil {
		errMsg := "adoption config not available for update_agent"
		h.reportCommandStatus(commandID, "failed", 0, errMsg)
		return errors.New(errMsg)
	}

	// Detect package type from the RUNNING OS.
	osID, osLike, err := readOSRelease("/etc/os-release")
	if err != nil {
		h.logger.Warn("failed to read /etc/os-release, assuming deb", "error", err)
	}
	pkgType := selectPackageType(osID, osLike)
	if pkgType != "deb" && pkgType != "rpm" {
		errMsg := "agent self-update supports deb/rpm systems only"
		h.reportCommandStatus(commandID, "failed", 0, errMsg)
		return errors.New(errMsg)
	}
	arch := mapArch(runtime.GOARCH)
	version := strings.TrimSpace(cmd.AgentVersion)
	if version == "" {
		version = "latest"
	}

	if alreadyRunning(h.agentVersion, version, cmd.AllowDowngrade) {
		h.reportCommandStatus(commandID, "success", 100,
			fmt.Sprintf("Agent is already on %s; nothing to install", h.agentVersion))
		return nil
	}

	baseURL := strings.TrimRight(h.adoptionConfig.PlatformURL, "/")
	if !strings.HasPrefix(baseURL, "http://") && !strings.HasPrefix(baseURL, "https://") {
		baseURL = "http://" + baseURL
	}
	agentURL := fmt.Sprintf("%s/cdn/agent/%s/%s/%s", baseURL, version, arch, pkgType)
	h.logger.Info("self-update: downloading agent package", "url", agentURL, "version", version, "arch", arch, "pkg_type", pkgType)
	h.reportCommandStatus(commandID, "in_progress", 30, "Downloading agent package")

	tmpFile, err := os.CreateTemp("", "orchestrator-agent-update-*."+strings.ReplaceAll(pkgType, ".", "_"))
	if err != nil {
		h.reportCommandStatus(commandID, "failed", 0, "failed to create temp file")
		return fmt.Errorf("failed to create temp file: %w", err)
	}
	defer func() {
		tmpFile.Close()
		os.Remove(tmpFile.Name())
	}()

	resp, err := boundedHTTPClient(agentDownloadTimeout).Get(agentURL)
	if err != nil {
		errMsg := fmt.Sprintf("Failed to download agent package: %v", err)
		h.reportCommandStatus(commandID, "failed", 0, errMsg)
		return fmt.Errorf("failed to download agent package from %s: %w", agentURL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		errMsg := fmt.Sprintf("Failed to download agent package: HTTP %d", resp.StatusCode)
		h.reportCommandStatus(commandID, "failed", 0, errMsg)
		return fmt.Errorf("failed to download agent package: HTTP %d", resp.StatusCode)
	}
	if err := copyBoundedPackage(tmpFile, resp.Body); err != nil {
		h.reportCommandStatus(commandID, "failed", 0, "failed to save package")
		return fmt.Errorf("failed to save downloaded package: %w", err)
	}
	tmpFile.Close()

	// Verify the detached signature BEFORE installing as root. Fail-closed: a
	// missing or invalid signature aborts the update. The signing key is not on the
	// server, so a compromised server/CDN (or a MITM on a plaintext-HTTP install) cannot
	// produce a valid signature for a malicious package.
	h.reportCommandStatus(commandID, "in_progress", 50, "Verifying agent package signature")
	pkgBytes, err := os.ReadFile(tmpFile.Name())
	if err != nil {
		h.reportCommandStatus(commandID, "failed", 0, "failed to read downloaded package")
		return fmt.Errorf("failed to read downloaded package: %w", err)
	}
	sigBytes, err := downloadSignature(agentURL + ".sig")
	if err != nil {
		errMsg := fmt.Sprintf("agent package signature unavailable, refusing update: %v", err)
		h.reportCommandStatus(commandID, "failed", 0, errMsg)
		return errors.New(errMsg)
	}
	if err := signing.VerifyDetached(pkgBytes, sigBytes); err != nil {
		errMsg := fmt.Sprintf("agent package signature invalid, refusing update: %v", err)
		h.reportCommandStatus(commandID, "failed", 0, errMsg)
		return errors.New(errMsg)
	}
	h.logger.Info("self-update: agent package signature verified")

	// Anti-rollback: the signature proves who BUILT the package, not
	// which version was served — read the version declared inside the signed
	// bytes and refuse a mismatched artifact or a downgrade without the
	// explicit override.
	declared := ""
	if pkgType == "deb" {
		declared, err = pkgver.DebControlVersion(pkgBytes)
		if err != nil {
			errMsg := fmt.Sprintf("cannot read the package's declared version, refusing update: %v", err)
			h.reportCommandStatus(commandID, "failed", 0, errMsg)
			return errors.New(errMsg)
		}
	}
	if err := checkUpdatePolicy(h.agentVersion, version, declared, cmd.AllowDowngrade); err != nil {
		h.reportCommandStatus(commandID, "failed", 0, err.Error())
		return err
	}
	// "latest" is known only now: the same check against the signed bytes.
	if declared != "" && alreadyRunning(h.agentVersion, declared, cmd.AllowDowngrade) {
		h.reportCommandStatus(commandID, "success", 100,
			fmt.Sprintf("Agent is already on %s; nothing to install", h.agentVersion))
		return nil
	}
	if declared != "" {
		version = declared // the authoritative version, for the success report
	}

	// Install exactly the bytes that were verified: dpkg re-reads the path,
	// so rewrite the temp file from the in-memory verified buffer (closes the
	// verify-path-vs-install-path TOCTOU).
	if err := os.WriteFile(tmpFile.Name(), pkgBytes, 0o600); err != nil {
		h.reportCommandStatus(commandID, "failed", 0, "failed to persist verified package")
		return fmt.Errorf("failed to persist verified package: %w", err)
	}

	// Install over the running OS. dpkg replaces /usr/bin/orchestrator-agent;
	// the running process keeps the old inode until it restarts. The nfpm deb
	// ships no postinst, so this does NOT restart the service by itself.
	//
	// dpkg is retried while another process holds its lock: a freshly booted
	// Ubuntu runs unattended-upgrades for minutes, and a bare `dpkg -i` fails
	// INSTANTLY on the frontend lock (measured live: three failed
	// updates in a row against a ~50-package run). dpkg has no equivalent of
	// apt's DPkg::Lock::Timeout, and going through apt-get would put a
	// dependency resolver between the verified bytes and the install, so the
	// wait is a bounded retry loop (packageLockWait: the bound, the progress
	// reports and the final message naming the holder).
	h.reportCommandStatus(commandID, "in_progress", 60, "Installing agent package")
	var stderr bytes.Buffer
	installOnce := func() (bool, error) {
		stderr.Reset()
		var install *exec.Cmd
		if pkgType == "deb" {
			install = exec.Command("dpkg", "-i", tmpFile.Name())
		} else {
			install = exec.Command("rpm", "-U", "--force", tmpFile.Name())
		}
		install.Stderr = &stderr
		if err := install.Run(); err != nil {
			return pkgType == "deb" && strings.Contains(stderr.String(), "lock"),
				fmt.Errorf("%v (%s)", err, strings.TrimSpace(stderr.String()))
		}
		return false, nil
	}
	var installErr error
	if pkgType == "deb" {
		lockWait := h.packageLockWaitFor(commandID)
		lockWait.progress = 60
		installErr = lockWait.run(installOnce)
	} else {
		// rpm has no dpkg lock to probe or wait for.
		_, installErr = installOnce()
	}
	if installErr != nil {
		errMsg := fmt.Sprintf("package install failed: %v", installErr)
		h.reportCommandStatus(commandID, "failed", 0, errMsg)
		return errors.New(errMsg)
	}

	// Report success BEFORE restarting — the restart tears down this process
	// and its stream, so the command must already be marked done.
	h.reportCommandStatus(commandID, "success", 100, fmt.Sprintf("Agent updated to %s, restarting", version))
	h.sendStatusUpdate("online", "agent updated, restarting")

	// Restart after a short flush delay. systemd (Restart=always) re-execs the
	// new binary; if systemctl is missing, exit so systemd respawns us.
	go func() {
		time.Sleep(1500 * time.Millisecond)
		h.logger.Info("self-update: restarting agent service")
		if err := exec.Command("systemctl", "restart", "orchestrator-agent").Start(); err != nil {
			h.logger.Warn("systemctl restart failed, exiting for systemd respawn", "error", err)
			os.Exit(0)
		}
	}()
	return nil
}

// installAgentPackageOnTarget installs the agent package into the mounted target filesystem.
func (h *CommandHandler) installAgentPackageOnTarget(mountPoint, tmpFilePath, pkgType, variant string) error {
	h.logger.Info("installing agent package on target filesystem",
		"mount_point", mountPoint,
		"package_path", tmpFilePath,
		"pkg_type", pkgType,
		"variant", variant)

	// The two agent packages Conflict by design (both would authenticate the
	// same node identity), so installing one over a rootfs that carries the
	// other must remove the counterpart first or dpkg refuses. Best-effort: on
	// a fresh install neither is present and dpkg -r exits nonzero, which is
	// the common case, not an error.
	if pkgType == "deb" {
		counterpart := "orchestrator-watcher"
		if variant == "watcher" {
			counterpart = "orchestrator-agent"
		}
		rmCmd := exec.Command("chroot", mountPoint, "dpkg", "-r", counterpart)
		var rmStderr bytes.Buffer
		rmCmd.Stderr = &rmStderr
		if err := rmCmd.Run(); err != nil {
			h.logger.Debug("counterpart package removal skipped (usually: not installed)",
				"package", counterpart, "error", err, "stderr", strings.TrimSpace(rmStderr.String()))
		} else {
			h.logger.Info("removed the counterpart agent package from the target", "package", counterpart)
		}
	}

	switch pkgType {
	case "deb":
		// Copy .deb into target /tmp
		targetTmpDir := filepath.Join(mountPoint, "tmp")
		if err := os.MkdirAll(targetTmpDir, 0755); err != nil {
			return fmt.Errorf("failed to create target tmp dir: %w", err)
		}
		targetDebPath := filepath.Join(targetTmpDir, "orchestrator-agent.deb")
		if err := copyFile(tmpFilePath, targetDebPath); err != nil {
			return fmt.Errorf("failed to copy deb to target: %w", err)
		}
		// Run dpkg -i inside target root
		cmd := exec.Command("chroot", mountPoint, "dpkg", "-i", "/tmp/orchestrator-agent.deb")
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("dpkg -i failed in chroot: %w (stderr: %s)", err, stderr.String())
		}
	case "rpm":
		// Copy .rpm into target /tmp
		targetTmpDir := filepath.Join(mountPoint, "tmp")
		if err := os.MkdirAll(targetTmpDir, 0755); err != nil {
			return fmt.Errorf("failed to create target tmp dir: %w", err)
		}
		targetRpmPath := filepath.Join(targetTmpDir, "orchestrator-agent.rpm")
		if err := copyFile(tmpFilePath, targetRpmPath); err != nil {
			return fmt.Errorf("failed to copy rpm to target: %w", err)
		}
		// Run rpm -i inside target root
		cmd := exec.Command("chroot", mountPoint, "rpm", "-i", "/tmp/orchestrator-agent.rpm")
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("rpm -i failed in chroot: %w (stderr: %s)", err, stderr.String())
		}
	case "tar.gz":
		// Extract tar.gz directly into /usr/local in target root
		targetDir := filepath.Join(mountPoint, "usr", "local")
		if err := os.MkdirAll(targetDir, 0755); err != nil {
			return fmt.Errorf("failed to create target usr/local dir: %w", err)
		}
		cmd := exec.Command("tar", "-xzf", tmpFilePath, "-C", targetDir)
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("tar extraction failed on target: %w (stderr: %s)", err, stderr.String())
		}
	default:
		return fmt.Errorf("unsupported package type: %s", pkgType)
	}

	return nil
}

// copyAdoptionFileToTarget writes the adoption config to the target filesystem or EEPROM
// On Raspberry Pi: writes to EEPROM (checks if value exists, sets if missing)
// On non-Raspberry Pi: copies adoption file to target filesystem
func (h *CommandHandler) copyAdoptionFileToTarget(mountPoint, variant string) error {
	if h.adoptionConfig == nil {
		return fmt.Errorf("adoption config not available")
	}

	// Recreate adoption file line: base64(JSON(AdoptionConfig))
	adoptJSON, err := json.Marshal(h.adoptionConfig)
	if err != nil {
		return fmt.Errorf("failed to marshal adoption config: %w", err)
	}
	encoded := base64.StdEncoding.EncodeToString(adoptJSON)

	// This is the adoption config for the OS being installed on the TARGET disk,
	// not for the bootstrap's own EEPROM. Always write it as a file into the
	// target filesystem at the path the installed agent reads (the systemd unit
	// runs with --adoption-file=/etc/orchestrator/node-adoption.txt).
	//
	// A file rather than the RPi EEPROM, for a reason that has nothing to do with
	// tooling: the EEPROM belongs to the BOARD and this identity belongs to the OS
	// on the target disk, so baking it into the EEPROM would follow the board to
	// whatever is installed next. (This comment used to justify it with "the
	// bootstrap image ships no vcgencmd/rpi-eeprom tooling". The vcgencmd half is
	// false — measured: the bootstrap ships /usr/bin/vcgencmd and it
	// works. Whether `rpi-eeprom-config` and the sudo it is invoked through exist
	// there has never been tested, so treat that half as unverified rather than
	// as a fact.)
	// The watcher/Watcher runs unprivileged and reads its OWN adoption path —
	// the full agent's /etc/orchestrator copy is root-owned 0600 on purpose.
	// The directory and its owner user exist after the package postinst ran in
	// the chroot; ownership is applied below via the target's own chown, which
	// resolves the name against the TARGET's passwd, not the bootstrap's.
	adoptionDirName := "orchestrator"
	if variant == "watcher" {
		adoptionDirName = "orchestrator-watcher"
	}
	targetDir := filepath.Join(mountPoint, "etc", adoptionDirName)
	if err := os.MkdirAll(targetDir, 0755); err != nil {
		return fmt.Errorf("failed to create target adoption directory: %w", err)
	}

	targetPath := filepath.Join(targetDir, "node-adoption.txt")
	// 0600, matching the other two adoption-write paths. This one wrote 0644
	// into the rootfs it had just installed, so the credential that
	// authenticates a gRPC stream for this node was readable by every
	// unprivileged account on the device — including the non-sudo login an
	// access entry is meant to hand a contractor. The platform then sends that
	// "node" the whole account access config.
	if err := os.WriteFile(targetPath, []byte(encoded), 0o600); err != nil {
		return fmt.Errorf("failed to write adoption file to target: %w", err)
	}

	if variant == "watcher" {
		// Resolve ownership inside the TARGET (its passwd has the user; the
		// bootstrap's does not). Fail closed: an adoption file the watcher
		// cannot read means a node that never calls home, and the operator is
		// better served by a failed install naming the cause.
		chownCmd := exec.Command("chroot", mountPoint, "chown",
			"orchestrator-watcher:orchestrator-watcher", "/etc/"+adoptionDirName+"/node-adoption.txt")
		var chownStderr bytes.Buffer
		chownCmd.Stderr = &chownStderr
		if err := chownCmd.Run(); err != nil {
			return fmt.Errorf("failed to chown the watcher adoption file (did the package postinst create the user?): %w (stderr: %s)",
				err, strings.TrimSpace(chownStderr.String()))
		}
	}

	h.logger.Info("adoption file copied to target volume", "path", targetPath, "variant", variant)
	return nil
}

// detectBootPartition automatically detects the boot partition on a target device.
// It looks for a FAT32 partition, typically partition 1 on Raspberry Pi systems.
// Returns the partition path and partition number, or an error if detection fails.
func (h *CommandHandler) detectBootPartition(targetDevice string) (partitionPath string, partitionNum int, err error) {
	if h.storageReader == nil {
		return "", 0, fmt.Errorf("storage reader not available")
	}

	// Get all devices and their partitions
	devices, err := h.storageReader.DetectDevices()
	if err != nil {
		return "", 0, fmt.Errorf("failed to detect devices: %w", err)
	}

	// Find the target device
	device, exists := devices[targetDevice]
	if !exists {
		return "", 0, fmt.Errorf("target device %s not found in detected devices", targetDevice)
	}

	// Look for FAT32 partition (typically boot partition)
	// Also check for vfat, msdos, fat32 filesystem types
	var bootPartition *proto.StoragePartition
	var bootPartNum int

	for _, partition := range device.Partitions {
		fsType := strings.ToLower(partition.Filesystem)
		// Check for FAT filesystem types
		if fsType == "vfat" || fsType == "fat32" || fsType == "fat16" || fsType == "msdos" {
			// Extract partition number from partition path
			partPath := partition.PartitionId
			baseName := filepath.Base(partPath)

			var partNum int
			if strings.Contains(baseName, "p") {
				// Format like nvme0n1p1 or mmcblk0p1
				parts := strings.Split(baseName, "p")
				if len(parts) > 1 {
					if num, err := strconv.Atoi(parts[len(parts)-1]); err == nil {
						partNum = num
					}
				}
			} else {
				// Format like sda1 - extract trailing digits
				for i := len(baseName) - 1; i >= 0; i-- {
					if baseName[i] >= '0' && baseName[i] <= '9' {
						start := i
						for start > 0 && baseName[start-1] >= '0' && baseName[start-1] <= '9' {
							start--
						}
						if num, err := strconv.Atoi(baseName[start:]); err == nil {
							partNum = num
							break
						}
					}
				}
			}

			// Prefer partition 1 if found, otherwise use first FAT partition
			if partNum == 1 {
				bootPartition = partition
				bootPartNum = partNum
				break
			} else if bootPartition == nil {
				bootPartition = partition
				bootPartNum = partNum
			}
		}
	}

	if bootPartition == nil {
		return "", 0, fmt.Errorf("no FAT32/vfat partition found on device %s", targetDevice)
	}

	h.logger.Info("detected boot partition",
		"partition_path", bootPartition.PartitionId,
		"partition_number", bootPartNum,
		"filesystem", bootPartition.Filesystem)

	return bootPartition.PartitionId, bootPartNum, nil
}

// configureBootPartitionEEPROM mounts the boot partition and writes EEPROM configuration to config.txt
// This enables EEPROM updates on Raspberry Pi CM4 systems by adding SPI settings to config.txt
func (h *CommandHandler) configureBootPartitionEEPROM(targetDevice string) error {
	// Check if this is a Raspberry Pi system
	systemInfoReader := hardware.NewSystemInfoReader(h.logger)
	isRPi, err := systemInfoReader.IsRaspberryPi()
	if err != nil {
		h.logger.Warn("failed to check if Raspberry Pi, skipping boot partition EEPROM config", "error", err)
		return nil // Not an error, just skip for non-RPi systems
	}
	if !isRPi {
		h.logger.Debug("not a Raspberry Pi, skipping boot partition EEPROM config")
		return nil
	}

	// Detect boot partition
	bootPart, bootPartNum, err := h.detectBootPartition(targetDevice)
	if err != nil {
		return fmt.Errorf("failed to detect boot partition: %w", err)
	}

	h.logger.Info("configuring boot partition for EEPROM",
		"boot_partition", bootPart,
		"partition_number", bootPartNum)

	// Create temporary mount point for boot partition
	bootMountPoint := "/mnt/tmp-boot-partition"
	if err := os.MkdirAll(bootMountPoint, 0755); err != nil {
		return fmt.Errorf("failed to create boot mount point: %w", err)
	}
	defer func() {
		// Unmount boot partition
		umountCmd := exec.Command("umount", bootMountPoint)
		var umountStderr bytes.Buffer
		umountCmd.Stderr = &umountStderr
		if err := umountCmd.Run(); err != nil {
			h.logger.Warn("failed to unmount boot partition",
				"mount_point", bootMountPoint,
				"error", err,
				"stderr", umountStderr.String())
		} else {
			h.logger.Info("unmounted boot partition", "mount_point", bootMountPoint)
		}
		// Remove mount point directory
		os.Remove(bootMountPoint)
	}()

	// Mount boot partition
	h.logger.Info("mounting boot partition", "partition", bootPart, "mount_point", bootMountPoint)
	mountCmd := exec.Command("mount", bootPart, bootMountPoint)
	var mountStderr bytes.Buffer
	mountCmd.Stderr = &mountStderr
	if err := mountCmd.Run(); err != nil {
		return fmt.Errorf("failed to mount boot partition %s: %w (stderr: %s)", bootPart, err, mountStderr.String())
	}

	// Find config.txt in boot partition (try both possible paths)
	configTxtPaths := []string{
		filepath.Join(bootMountPoint, "config.txt"),
		filepath.Join(bootMountPoint, "firmware", "config.txt"),
	}

	var configPath string
	var configContent string
	for _, path := range configTxtPaths {
		if _, err := os.Stat(path); err == nil {
			content, err := os.ReadFile(path)
			if err == nil {
				configPath = path
				configContent = string(content)
				break
			}
		}
	}

	if configPath == "" {
		h.logger.Warn("config.txt not found in boot partition, skipping EEPROM config")
		return nil // Not an error, just skip if config.txt doesn't exist
	}

	h.logger.Info("found config.txt in boot partition", "path", configPath)

	// Update config.txt with CM4 EEPROM settings
	// We'll manually update config.txt since FixCM4EEPROMConfig also tries to update
	// /etc/default/rpi-eeprom-update which is in the root filesystem, not boot partition
	if err := h.updateConfigTxtForCM4(configPath, configContent); err != nil {
		h.logger.Warn("failed to update config.txt with EEPROM settings", "error", err)
		return fmt.Errorf("failed to update config.txt: %w", err)
	}

	if err := h.updateNetworkConfig(bootMountPoint); err != nil {
		h.logger.Warn("failed to update network-config", "error", err)
		return fmt.Errorf("failed to update network-config: %w", err)
	}

	h.logger.Info("boot partition configured successfully with EEPROM settings")
	return nil
}

// networkConfigYAML pins the DHCP client identifier of the installed OS to
// the plain MAC address. systemd-networkd's default RFC4361 DUID identifier
// is handled unreliably by some DHCP servers (observed: the same
// device leases instantly as a MAC-identified client — bootloader, netboot
// bootstrap — but intermittently gets no lease for many minutes as a
// DUID-identified one). cloud-init applies this file on first boot.
const networkConfigYAML = `# Written by orchestrator-agent during OS installation.
# dhcp-identifier: mac makes the OS request DHCP leases exactly like the
# netboot environment does; DUID-identified requests are flaky with some
# DHCP servers.
version: 2
ethernets:
  eth0:
    dhcp4: true
    optional: true
    dhcp-identifier: mac
`

// updateNetworkConfig replaces the cloud-init network-config on the boot
// partition. Only images that already ship one (Ubuntu preinstalled layout)
// are touched, so non-cloud-init images stay as-is.
func (h *CommandHandler) updateNetworkConfig(bootMountPoint string) error {
	path := filepath.Join(bootMountPoint, "network-config")
	if _, err := os.Stat(path); err != nil {
		h.logger.Info("no network-config on boot partition, skipping DHCP identifier pin")
		return nil
	}
	if err := os.WriteFile(path, []byte(networkConfigYAML), 0644); err != nil {
		return fmt.Errorf("failed to write %s: %w", path, err)
	}
	h.logger.Info("pinned DHCP client identifier to MAC in network-config")
	return nil
}

// updateConfigTxtForCM5 enables PCIe Gen 3 on CM5 variants in the installed
// OS. The parameter lives strictly inside the [cm5]/[cm5l] model filters, so
// a CM4 (PCIe Gen 2 silicon) booting the same config.txt is never affected.
//
// NOT WIRED IN on purpose: Gen 3 is not certified on the Pi 5 family, and a
// live test on a CM5 carrier hung the first NVMe boot after
// the link was switched to Gen 3 — the device required a power cycle. Keep
// this behind an explicit per-node opt-in policy if it is ever enabled.
//
//nolint:unused
func (h *CommandHandler) updateConfigTxtForCM5(configPath string) error {
	content, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("failed to read %s: %w", configPath, err)
	}

	updated := string(content)
	changedAny := false
	for _, section := range []string{"cm5", "cm5l"} {
		var changed bool
		updated, changed = ensureConfigTxtSetting(updated, section, "dtparam=pciex1_gen=3")
		if changed {
			h.logger.Info("enabled PCIe Gen 3 in config.txt", "section", section)
			changedAny = true
		}
	}
	if !changedAny {
		return nil
	}

	if err := os.WriteFile(configPath, []byte(updated), 0644); err != nil {
		return fmt.Errorf("failed to write %s: %w", configPath, err)
	}
	return nil
}

// updateConfigTxtForCM4 updates config.txt with CM4-specific EEPROM settings
// This is a simplified version that only updates config.txt (not /etc/default/rpi-eeprom-update)
func (h *CommandHandler) updateConfigTxtForCM4(configPath, content string) error {
	h.logger.Info("updating config.txt for CM4", "path", configPath)

	// Parse the file to check what exists in the [cm4] section
	lines := strings.Split(content, "\n")
	var newLines []string
	inCM4Section := false
	hasCM4Section := false
	hasSPIInCM4 := false
	hasAudremapInCM4 := false
	hasSPIGPIOInCM4 := false

	// First pass: check what exists in [cm4] section
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		if trimmed == "[cm4]" {
			hasCM4Section = true
			inCM4Section = true
			continue
		}

		// If we're in the [cm4] section and hit another section, exit it
		if inCM4Section && strings.HasPrefix(trimmed, "[") && trimmed != "[cm4]" {
			inCM4Section = false
		}

		// Check for settings within [cm4] section
		if inCM4Section {
			if trimmed == "dtparam=spi=on" {
				hasSPIInCM4 = true
			} else if trimmed == "dtoverlay=audremap" {
				hasAudremapInCM4 = true
			} else if trimmed == "dtoverlay=spi-gpio40-45" {
				hasSPIGPIOInCM4 = true
			}
		}
	}

	// If all settings already exist in [cm4] section, no update needed
	if hasCM4Section && hasSPIInCM4 && hasAudremapInCM4 && hasSPIGPIOInCM4 {
		h.logger.Info("config.txt already has all CM4 settings in [cm4] section, no update needed")
		return nil
	}

	// Second pass: build the updated file
	inCM4Section = false
	cm4SettingsAdded := false

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		if trimmed == "[cm4]" {
			inCM4Section = true
			hasCM4Section = true
			newLines = append(newLines, line)
			// Add missing settings right after [cm4]
			if !hasSPIInCM4 {
				newLines = append(newLines, "dtparam=spi=on")
				h.logger.Info("added dtparam=spi=on to [cm4] section")
			}
			if !hasAudremapInCM4 {
				newLines = append(newLines, "dtoverlay=audremap")
				h.logger.Info("added dtoverlay=audremap to [cm4] section")
			}
			if !hasSPIGPIOInCM4 {
				newLines = append(newLines, "dtoverlay=spi-gpio40-45")
				h.logger.Info("added dtoverlay=spi-gpio40-45 to [cm4] section")
			}
			cm4SettingsAdded = true
			continue
		}

		// If we're in the [cm4] section and hit another section, exit it
		if inCM4Section && strings.HasPrefix(trimmed, "[") && trimmed != "[cm4]" {
			inCM4Section = false
		}

		// Skip duplicate CM4 settings that are already in the section (we added them above)
		if inCM4Section && cm4SettingsAdded {
			if trimmed == "dtparam=spi=on" || trimmed == "dtoverlay=audremap" || trimmed == "dtoverlay=spi-gpio40-45" {
				continue // Skip duplicate
			}
		}

		newLines = append(newLines, line)
	}

	// If [cm4] section doesn't exist, add it at the end
	if !hasCM4Section {
		// Ensure content ends with newline
		contentEnd := strings.TrimRight(strings.Join(newLines, "\n"), "\n")
		newLines = []string{contentEnd, "", "[cm4]", "dtparam=spi=on", "dtoverlay=audremap", "dtoverlay=spi-gpio40-45"}
		h.logger.Info("added [cm4] section with all required settings")
	}

	updatedContent := strings.Join(newLines, "\n")
	if !strings.HasSuffix(updatedContent, "\n") && len(newLines) > 0 {
		updatedContent += "\n"
	}

	// Write the updated content
	if err := os.WriteFile(configPath, []byte(updatedContent), 0644); err != nil {
		return fmt.Errorf("failed to write %s: %w", configPath, err)
	}

	h.logger.Info("config.txt updated successfully with CM4 settings")
	return nil
}

// copyFile copies a file from src to dst paths.
func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer func() {
		_ = out.Close()
	}()

	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	return out.Sync()
}

// handleInstallOS handles OS installation commands
func (h *CommandHandler) handleInstallOS(commandID string, cmd *proto.InstallOSCommand) error {
	h.logger.Info("install OS command received",
		"command_id", commandID,
		"image_id", cmd.ImageId,
		"target_device", cmd.TargetDevice,
		"reboot", cmd.Reboot)

	// Report command status: in_progress
	h.reportCommandStatus(commandID, "in_progress", 0, "Starting OS installation")

	// Release the bootstrap's own hold on the target BEFORE validating it.
	// Installing onto the SD card the device was provisioned from is the normal
	// flow for a board with no NVMe, and the bootstrap keeps that card mounted
	// for its adoption file — which the validation below would then refuse as a
	// mounted device. No-op on an installed OS.
	released, lazilyDetached, restoreMounts, rerr := h.releaseBootMediaMounts(cmd.TargetDevice)
	if rerr != nil {
		h.logger.Warn("could not fully release the target device before install",
			"command_id", commandID, "target_device", cmd.TargetDevice, "error", rerr)
	} else if len(released) > 0 {
		h.reportCommandStatus(commandID, "in_progress", 1,
			fmt.Sprintf("Released recovery mounts on %s (%s)", cmd.TargetDevice, strings.Join(released, ", ")))
	}

	// Initial validation
	if err := h.validateTargetDevice(cmd.TargetDevice, cmd.Wipe); err != nil {
		// Refused with nothing written: put the card's mount back.
		restoreMounts()
		err = explainBusyAfterLazyUnmount(err, lazilyDetached)
		errMsg := fmt.Sprintf("device validation failed: %v", err)
		h.logger.Error("device validation failed", "command_id", commandID, "target_device", cmd.TargetDevice, "error", err)
		// Report command failure
		h.reportCommandStatus(commandID, "failed", 0, errMsg)
		// Report failure status to backend
		h.sendStatusUpdate("os_installation_failed", errMsg)
		return fmt.Errorf("device validation failed: %w", err)
	}

	// Report 5% - validation complete, starting download
	h.reportCommandStatus(commandID, "in_progress", 5, "Validation complete, starting download")

	// Download and write image (chunked) - progress reported from 5% to 95% inside function.
	// A download interrupted mid-stream (network blip, platform restart) is
	// retried from scratch: the write restarts at offset 0, so a partial
	// previous attempt is simply overwritten.
	const maxDownloadAttempts = 3
	var err error
	for attempt := 1; attempt <= maxDownloadAttempts; attempt++ {
		err = h.downloadAndWriteImageChunked(commandID, cmd.ImageUrl, cmd.TargetDevice, cmd.Checksum, cmd.Wipe)
		if err == nil {
			break
		}
		if attempt < maxDownloadAttempts && isTransientDownloadError(err) {
			h.logger.Warn("image download interrupted, retrying",
				"command_id", commandID,
				"attempt", attempt,
				"max_attempts", maxDownloadAttempts,
				"error", err)
			h.reportCommandStatus(commandID, "in_progress", 5,
				fmt.Sprintf("Download interrupted, retrying (attempt %d/%d)", attempt+1, maxDownloadAttempts))
			time.Sleep(5 * time.Second)
			continue
		}
		break
	}
	if err != nil {
		errMsg := fmt.Sprintf("OS installation failed: %v", err)
		h.logger.Error("OS installation failed", "command_id", commandID, "error", err)
		if strings.Contains(err.Error(), "checksum verification failed") {
			errMsg = "OS installation failed: checksum verification failed - data corruption detected"
		}
		// Report command failure
		h.reportCommandStatus(commandID, "failed", 0, errMsg)
		// Report failure status to backend
		h.sendStatusUpdate("os_installation_failed", errMsg)
		if strings.Contains(err.Error(), "checksum verification failed") {
			return fmt.Errorf("OS installation failed: checksum verification failed - data corruption detected")
		}
		return fmt.Errorf("OS installation failed: %w", err)
	}

	// A backup image deployed onto a node other than its source carries the
	// source's machine identity; the platform sets strip_identity so this
	// install generalizes the freshly written system (machine-id, SSH host
	// keys, adoption file) and the device adopts as ITSELF instead of
	// impersonating the source. Failing to strip must fail the install —
	// booting an identity clone is worse than not booting.
	if cmd.StripIdentity {
		h.reportCommandStatus(commandID, "in_progress", 97, "Stripping source machine identity")
		if stripErr := h.stripIdentityOnDevice(cmd.TargetDevice); stripErr != nil {
			// Failing the COMMAND is not failing the DISK, and here the two are
			// not the same thing. The image was written, expanded and
			// partprobe'd before this ran, so the disk now holds a BOOTABLE copy
			// of the source node — its machine-id, its host keys, its adoption
			// file. The one-shot recovery revert restores boot_to_os on the next
			// reconnect, the board boots that copy, and it authenticates to the
			// platform AS THE SOURCE NODE, displacing the real one's stream.
			//
			// So make the disk refuse to boot. The comment above already said
			// "booting an identity clone is worse than not booting"; this is
			// what makes that true.
			h.invalidateTargetDeviceByPath(cmd.TargetDevice)
			errMsg := fmt.Sprintf("OS installation failed: identity strip failed: %v", stripErr)
			h.logger.Error("identity strip failed; target device invalidated so it cannot boot as the source node",
				"command_id", commandID, "device", cmd.TargetDevice, "error", stripErr)
			h.reportCommandStatus(commandID, "failed", 0, errMsg)
			h.sendStatusUpdate("os_installation_failed", errMsg)
			return fmt.Errorf("identity strip failed: %w", stripErr)
		}
	}

	// Agent install and connectivity provision are separate commands issued
	// after OS installation; resize already completed (reported at 95% in
	// downloadAndWriteImageChunked).
	h.reportCommandStatus(commandID, "success", 100, "OS installation completed successfully")

	// Final status update
	if cmd.Reboot {
		h.sendStatusUpdate("restarting", "OS installation complete, rebooting...")
		// Wait a short delay before rebooting
		time.Sleep(2 * time.Second)
		if err := rebootNow(); err != nil {
			h.logger.Error("reboot command failed", "command_id", commandID, "error", err)
			return fmt.Errorf("reboot command failed: %w", err)
		}
	} else {
		h.sendStatusUpdate("online", "OS installation complete")
	}

	// Trigger hardware info refresh after OS installation
	if h.hardwareInfoReporter != nil {
		if err := h.hardwareInfoReporter(); err != nil {
			h.logger.Warn("failed to trigger hardware info refresh after OS installation", "error", err)
		} else {
			h.logger.Info("hardware info refresh triggered after OS installation")
		}
	}

	h.logger.Info("install OS command executed successfully", "command_id", commandID)
	return nil
}

// sendStatusUpdate sends a status update to the platform
// platformClient is guaranteed to be non-nil and implement the interface (set in constructor)
func (h *CommandHandler) sendStatusUpdate(status, message string) {
	if err := h.platformClient.SendStatusUpdate(h.nodeID, h.accountID, h.uniqueToken, status, message); err != nil {
		h.logger.Warn("failed to send status update", "error", err, "status", status, "message", message)
	}
}

// handleUpdateFile handles file update commands
func (h *CommandHandler) handleUpdateFile(commandID string, cmd *proto.UpdateFileCommand) error {
	h.logger.Info("update file command received",
		"command_id", commandID,
		"path", cmd.Path,
		"version", cmd.Version)

	// Report command status: in_progress
	h.reportCommandStatus(commandID, "in_progress", 0, fmt.Sprintf("Updating file: %s", cmd.Path))

	if h.fileReader == nil {
		errMsg := "file reader not available"
		h.logger.Error(errMsg)
		h.reportCommandStatus(commandID, "failed", 0, errMsg)
		h.reportFileStatus(cmd.Path, cmd.Version, "failed", errMsg)
		return fmt.Errorf("file reader not available")
	}

	// Report status "applying"
	h.reportFileStatus(cmd.Path, cmd.Version, "applying", "")
	h.reportCommandStatus(commandID, "in_progress", 50, "Writing file content")

	// Write file content
	if err := h.fileReader.WriteFile(cmd.Path, cmd.Content); err != nil {
		errMsg := fmt.Sprintf("failed to write file: %v", err)
		h.logger.Error("failed to write file", "command_id", commandID, "path", cmd.Path, "error", err)
		h.reportCommandStatus(commandID, "failed", 0, errMsg)
		h.reportFileStatus(cmd.Path, cmd.Version, "failed", errMsg)
		return fmt.Errorf("failed to write file: %w", err)
	}

	// Verify hash after write
	h.reportCommandStatus(commandID, "in_progress", 75, "Verifying file hash")
	hashMatches, err := h.fileReader.VerifyFileHash(cmd.Path, cmd.Hash)
	if err != nil {
		errMsg := fmt.Sprintf("failed to verify file hash: %v", err)
		h.logger.Error("failed to verify file hash", "command_id", commandID, "path", cmd.Path, "error", err)
		h.reportCommandStatus(commandID, "failed", 0, errMsg)
		h.reportFileStatus(cmd.Path, cmd.Version, "failed", errMsg)
		return fmt.Errorf("failed to verify file hash: %w", err)
	}

	if !hashMatches {
		errMsg := "file hash verification failed after write"
		h.logger.Error(errMsg, "command_id", commandID, "path", cmd.Path)
		h.reportCommandStatus(commandID, "failed", 0, errMsg)
		h.reportFileStatus(cmd.Path, cmd.Version, "failed", errMsg)
		return fmt.Errorf("file hash verification failed after write")
	}

	// Report status "applied"
	h.reportFileStatus(cmd.Path, cmd.Version, "applied", "")
	h.reportCommandStatus(commandID, "success", 100, fmt.Sprintf("File updated successfully: %s", cmd.Path))

	h.logger.Info("update file command executed successfully", "command_id", commandID, "path", cmd.Path, "version", cmd.Version)
	return nil
}

// handleUpdateBootOrder handles boot order update commands
func (h *CommandHandler) handleUpdateBootOrder(commandID string, cmd *proto.UpdateBootOrderCommand) error {
	h.logger.Info("update boot order command received",
		"command_id", commandID,
		"boot_order", cmd.BootOrder)

	// The per-device EEPROM package download is gated by a short-lived HMAC
	// capability minted by the platform (its adoption token would otherwise be
	// world-readable). Present it on the by-serial requests.
	sigQuery := ""
	if cmd.PkgExp != "" && cmd.PkgSig != "" {
		sigQuery = "?exp=" + cmd.PkgExp + "&sig=" + cmd.PkgSig
	}

	// Report command status: in_progress
	h.reportCommandStatus(commandID, "in_progress", 0, "Validating boot order")

	// Validate boot order array - accept all valid boot options
	// The validation will happen in bootOrderArrayToHex which has the complete list
	// We just check that devices are not empty
	for _, device := range cmd.BootOrder {
		device = strings.ToLower(strings.TrimSpace(device))
		if device == "" {
			errMsg := "boot order contains empty device"
			h.logger.Error("empty boot device", "command_id", commandID)
			h.reportCommandStatus(commandID, "failed", 0, errMsg)
			h.sendStatusUpdate("busy", errMsg)
			return fmt.Errorf("boot order contains empty device")
		}
	}

	// Report progress: applying boot order
	h.reportCommandStatus(commandID, "in_progress", 50, "Applying boot order")

	// Every EEPROM change flashes a server-signed package from the eeprom-signer;
	// the agent never rebuilds the config on-device. rpi-eeprom-config --apply
	// regenerates the EEPROM from the stock base image and silently drops our
	// embedded public key, breaking signed network boot (see docs/NETWORK-FIRST.md).
	// The two environments differ only in how the signed image is flashed:
	//   - Managed OS (e.g. Ubuntu on NVMe): rpi-eeprom-update is installed and
	//     provision pre-enables flashrom → write the exact signed image directly.
	//   - Minimal bootstrap (RAM image): no rpi-eeprom tooling → stage the package
	//     on the SD/USB boot partition and reboot so the ROM's recovery.bin flashes it.
	if _, err := exec.LookPath("rpi-eeprom-update"); err == nil {
		if err := h.applyBootOrderViaEepromUpdate(commandID, cmd.BootOrder, sigQuery); err != nil {
			errMsg := fmt.Sprintf("failed to flash signed EEPROM package: %v", err)
			h.logger.Error("failed to flash signed EEPROM package", "command_id", commandID, "error", err)
			h.reportCommandStatus(commandID, "failed", 0, errMsg)
			h.sendStatusUpdate("busy", errMsg)
			return fmt.Errorf("failed to flash signed EEPROM package: %w", err)
		}

		h.logger.Info("boot order updated successfully", "command_id", commandID, "boot_order", cmd.BootOrder)

		successMsg := "Signed EEPROM image flashed successfully. Reboot required for the new boot order to take effect."
		// Say explicitly that this path does NOT reboot. The platform pins a
		// reboot-class command's node to "restarting" at dispatch, because it
		// cannot trust an agent about a reboot it has not performed yet, and
		// only an explicit "false" releases the pin — absence means unknown.
		// Without this the node reads "restarting" for the seconds between the
		// flash and the next status report, telling the operator the machine is
		// going down when this branch never takes it down. The recovery branch
		// below says "true" for the same reason, from the other side.
		h.reportCommandResult(commandID, "success", successMsg,
			map[string]string{"rebooting": "false"})
		h.sendStatusUpdate("online", successMsg)

		// Trigger hardware info refresh to report new boot order
		if h.hardwareInfoReporter != nil {
			if err := h.hardwareInfoReporter(); err != nil {
				h.logger.Warn("failed to trigger hardware info refresh", "error", err)
			} else {
				h.logger.Info("hardware info refresh triggered after boot order update")
			}
		}

		return nil
	}

	h.logger.Info("rpi-eeprom-update not present, applying boot order via recovery package", "command_id", commandID)
	if err := h.applyBootOrderViaRecovery(commandID, cmd.BootOrder, sigQuery); err != nil {
		errMsg := fmt.Sprintf("failed to update boot order via recovery package: %v", err)
		h.logger.Error("failed to update boot order via recovery", "command_id", commandID, "error", err)
		h.reportCommandStatus(commandID, "failed", 0, errMsg)
		h.sendStatusUpdate("busy", errMsg)
		return fmt.Errorf("failed to update boot order via recovery package: %w", err)
	}
	// applyBootOrderViaRecovery reboots on success and does not return.
	return nil
}

// eepromPackageFiles moved to manifest_verify.go, next to the check that
// requires the manifest to cover every one of them.

// fetchSignedEEPROMPackage downloads and integrity-checks the server-signed
// EEPROM package (recovery.bin + pieeprom.upd + pieeprom.sig) for this device
// and target boot order into a temp dir. It prefers the per-device (by-serial)
// package the eeprom-signer bakes for network-first devices (this device's real
// serial in HTTP_PATH + its node-specific adoption token, see
// docs/NETWORK-FIRST.md) and falls back to the shared <soc>/<boot_order>
// package. The returned cleanup removes the temp dir.
func (h *CommandHandler) fetchSignedEEPROMPackage(commandID string, order []string, sigQuery string) (pkgDir, hexOrder string, cleanup func(), err error) {
	if h.adoptionConfig == nil || h.adoptionConfig.PlatformURL == "" {
		return "", "", nil, fmt.Errorf("no platform URL available to fetch EEPROM package")
	}

	hexOrder, err = hardware.BootOrderArrayToHex(order)
	if err != nil {
		return "", "", nil, fmt.Errorf("failed to convert boot order to hex: %w", err)
	}
	soc, err := detectRPiSoC()
	if err != nil {
		return "", "", nil, fmt.Errorf("failed to detect SoC: %w", err)
	}

	// The adoption file may carry a scheme-less platform URL (e.g. "1.2.3.4");
	// Go's http.Get requires an explicit scheme, so default to http.
	platformURL := strings.TrimRight(ensureURLScheme(h.adoptionConfig.PlatformURL), "/")

	tmpDir, err := os.MkdirTemp("", "eeprom-pkg-")
	if err != nil {
		return "", "", nil, fmt.Errorf("failed to create temp dir: %w", err)
	}
	removeTmp := func() { os.RemoveAll(tmpDir) }
	cleanup = removeTmp
	// Call removeTmp, not the named result: every failure below returns a nil
	// cleanup, and a deferred call through the named result would dereference it.
	defer func() {
		if err != nil {
			removeTmp()
		}
	}()

	// The per-device (by-serial) package embeds this node's adoption token and
	// is served behind a short-lived HMAC capability (sigQuery). The generic
	// shared package carries no secret and needs none.
	downloadPkg := func(base, query string) error {
		for _, f := range append([]string{"SHA256SUMS"}, eepromPackageFiles...) {
			if err := downloadFile(base+"/"+f+query, filepath.Join(tmpDir, f)); err != nil {
				return fmt.Errorf("failed to download %s: %w", f, err)
			}
		}
		if err := verifySHA256SUMS(tmpDir, "SHA256SUMS", eepromPackageFiles); err != nil {
			return fmt.Errorf("EEPROM package integrity check failed: %w", err)
		}
		return nil
	}

	generic := fmt.Sprintf("%s/net_install/eeprom/%s/%s", platformURL, soc, hexOrder)
	base := generic
	baseQuery := ""
	serial := detectHardwareSerial()
	if serial == "" {
		if refusal := refusePerDeviceEEPROMFallback(sigQuery,
			"this device's hardware serial could not be read, so no per-device package could be requested", nil); refusal != nil {
			return "", "", nil, refusal
		}
	} else {
		bySerial := fmt.Sprintf("%s/net_install/eeprom/by-serial/%s", platformURL, serial)
		if probeErr := downloadFile(bySerial+"/SHA256SUMS"+sigQuery, filepath.Join(tmpDir, "SHA256SUMS")); probeErr != nil {
			if refusal := refusePerDeviceEEPROMFallback(sigQuery,
				fmt.Sprintf("the per-device package for serial %s could not be fetched", serial), probeErr); refusal != nil {
				return "", "", nil, refusal
			}
			h.logger.Warn("no per-device EEPROM package available, using the shared package",
				"command_id", commandID, "serial", serial, "error", probeErr)
		} else {
			base = bySerial
			baseQuery = sigQuery
			h.logger.Info("using per-device EEPROM package", "command_id", commandID, "serial", serial)
		}
	}
	h.logger.Info("fetching EEPROM package", "command_id", commandID, "soc", soc, "boot_order", hexOrder, "url", base)

	if err := downloadPkg(base, baseQuery); err != nil {
		return "", "", nil, err
	}

	// The by-serial package is whatever the signer last baked for this device —
	// it does not automatically carry the order THIS command asked for. Flashing
	// a mismatched package would silently apply a stale boot order.
	if base != generic {
		data, err := os.ReadFile(filepath.Join(tmpDir, "pieeprom.upd"))
		if err != nil {
			return "", "", nil, fmt.Errorf("failed to read downloaded pieeprom.upd: %w", err)
		}
		if baked := hardware.ExtractEEPROMBootOrder(data); baked != "" && !strings.EqualFold(baked, hexOrder) {
			if refusal := refusePerDeviceEEPROMFallback(sigQuery,
				fmt.Sprintf("the per-device package for serial %s is baked with BOOT_ORDER=%s but %s was requested", serial, baked, hexOrder), nil); refusal != nil {
				return "", "", nil, refusal
			}
			h.logger.Warn("per-device EEPROM package carries a different boot order; falling back to shared package",
				"command_id", commandID, "baked", baked, "requested", hexOrder)
			if err := downloadPkg(generic, ""); err != nil {
				return "", "", nil, fmt.Errorf(
					"per-device EEPROM package is baked with BOOT_ORDER=%s but %s was requested, and no shared %s package is available — re-run provision-eeprom with the desired boot order (%v)",
					baked, hexOrder, hexOrder, err)
			}
		}
	}
	h.logger.Info("EEPROM package verified", "command_id", commandID)

	return tmpDir, hexOrder, cleanup, nil
}

// applyBootOrderViaEepromUpdate flashes the signed per-device EEPROM package on
// a managed OS where rpi-eeprom-update is installed. It writes the exact
// server-signed image: `-f` flashes the given pieeprom.upd verbatim (via
// flashrom, which provision pre-enables with RPI_EEPROM_USE_FLASHROM=1) and
// `-d` uses the configuration embedded in that image instead of merging the
// currently-booted config back in — a merge would lose the signer-baked
// settings (embedded pubkey, per-serial HTTP_PATH, adoption token).
func (h *CommandHandler) applyBootOrderViaEepromUpdate(commandID string, order []string, sigQuery string) error {
	pkgDir, hexOrder, cleanup, err := h.fetchSignedEEPROMPackage(commandID, order, sigQuery)
	if err != nil {
		return err
	}
	defer cleanup()

	// Ensure OS-side EEPROM flashing is enabled on the LIVE rootfs before the
	// flash, not only at install_os time — a node adopted onto a pre-existing OS
	// (SSH adopt / curl|install.sh) may lack the record, which would force
	// rpi-eeprom-update onto the slow staged path (extra reboot). Best-effort:
	// on failure we still try the flash and fall back to the CM4 retry below.
	if err := h.enableEEPROMUpdatesOnRoot("/"); err != nil {
		h.logger.Warn("could not pre-enable OS-side EEPROM updates; proceeding", "command_id", commandID, "error", err)
	}

	h.logger.Info("flashing signed EEPROM image", "command_id", commandID, "boot_order", hexOrder)
	stderr, err := runEepromUpdateFlash(pkgDir)
	if err != nil && hardware.IsCM4EEPROMError(stderr) {
		// CM4 ships with OS-side EEPROM updates disabled; enable them and retry once.
		h.logger.Info("CM4 OS-side EEPROM updates disabled, enabling and retrying", "command_id", commandID)
		if fixErr := hardware.NewBootOrderWriter(h.logger).FixCM4EEPROMConfig(); fixErr != nil {
			return fmt.Errorf("flash failed (%v) and CM4 enable fix failed: %w", err, fixErr)
		}
		stderr, err = runEepromUpdateFlash(pkgDir)
	}
	if err != nil {
		if stderr != "" {
			return fmt.Errorf("rpi-eeprom-update failed: %w (stderr: %s)", err, stderr)
		}
		return fmt.Errorf("rpi-eeprom-update failed: %w", err)
	}

	h.logger.Info("signed EEPROM image flashed", "command_id", commandID, "boot_order", hexOrder)
	return nil
}

// runEepromUpdateFlash runs `rpi-eeprom-update -d -f pieeprom.upd` from pkgDir
// (so the matching pieeprom.sig sits next to the image) and returns its stderr
// for error classification.
func runEepromUpdateFlash(pkgDir string) (string, error) {
	cmd := exec.Command("sudo", "rpi-eeprom-update", "-d", "-f", filepath.Join(pkgDir, "pieeprom.upd"))
	cmd.Dir = pkgDir
	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	return stderr.String(), err
}

// applyBootOrderViaRecovery changes the EEPROM BOOT_ORDER from the minimal
// bootstrap, where no rpi-eeprom tooling exists. It downloads the signed EEPROM
// package, drops it onto the SD/USB boot partition, and reboots. On the next
// boot the Raspberry Pi ROM finds recovery.bin, flashes the EEPROM itself, and
// reboots again into the new order. On success this reboots and does not return.
func (h *CommandHandler) applyBootOrderViaRecovery(commandID string, order []string, sigQuery string) error {
	tmpDir, hexOrder, cleanup, err := h.fetchSignedEEPROMPackage(commandID, order, sigQuery)
	if err != nil {
		return err
	}
	defer cleanup()

	// Mount the boot partition read-write and drop the package files at its root,
	// where the ROM looks for recovery.bin.
	mountPoint, cleanup, err := mountBootPartitionRW(h.logger)
	if err != nil {
		return fmt.Errorf("failed to mount boot partition: %w", err)
	}
	defer cleanup()

	// ORDER MATTERS, and this is the one failure in the product that needs a
	// physical visit.
	//
	// The ROM loads recovery.bin unconditionally on the next boot. Writing it
	// first — which is what a plain loop over the package does — leaves a window
	// in which a power cut has produced a TRUNCATED recovery.bin that the ROM
	// will still try to run, on a machine nobody can reach. So the payload goes
	// down first, the trigger is staged under a temporary name, everything is
	// re-hashed WHERE IT WILL BE READ, and only then is the trigger renamed into
	// place. A rename within one directory is a directory-entry update, so the
	// file the ROM finds is either absent or complete.
	//
	// Re-verifying on the boot partition rather than trusting the temp dir is the
	// other half: the manifest was checked where the package was DOWNLOADED, and
	// a copy onto a small FAT partition is exactly where a short write or a full
	// filesystem turns a verified package into a broken one.
	const stagedTrigger = "recovery.bin.staged"
	payload := make([]string, 0, len(eepromPackageFiles))
	for _, f := range eepromPackageFiles {
		if f != eepromTriggerFile {
			payload = append(payload, f)
		}
	}
	for _, f := range payload {
		if err := copyFile(filepath.Join(tmpDir, f), filepath.Join(mountPoint, f)); err != nil {
			return fmt.Errorf("failed to place %s on boot partition: %w", f, err)
		}
	}
	if err := copyFile(filepath.Join(tmpDir, eepromTriggerFile), filepath.Join(mountPoint, stagedTrigger)); err != nil {
		return fmt.Errorf("failed to stage %s on boot partition: %w", eepromTriggerFile, err)
	}
	syscall.Sync()

	if err := verifySHA256SUMSAcross(tmpDir, mountPoint, "SHA256SUMS", eepromPackageFiles,
		map[string]string{eepromTriggerFile: stagedTrigger}); err != nil {
		// Remove the staged trigger before giving up: leaving it behind is
		// harmless to the ROM (it is not called recovery.bin) but it would
		// confuse the next attempt.
		_ = os.Remove(filepath.Join(mountPoint, stagedTrigger))
		return fmt.Errorf("the EEPROM package did not survive the copy to the boot partition, so nothing was armed: %w", err)
	}

	// Arm it. Everything the ROM needs is already on disk and verified; this
	// single rename is what makes it look.
	if err := os.Rename(filepath.Join(mountPoint, stagedTrigger), filepath.Join(mountPoint, eepromTriggerFile)); err != nil {
		_ = os.Remove(filepath.Join(mountPoint, stagedTrigger))
		return fmt.Errorf("failed to arm %s on boot partition: %w", eepromTriggerFile, err)
	}
	syscall.Sync()
	h.logger.Info("EEPROM recovery package written to boot partition and verified in place",
		"command_id", commandID, "mount", mountPoint)

	// This branch really does reboot: the ROM applies the staged package on the
	// next boot. Stated positively so the platform's dispatch-time pin is
	// confirmed rather than merely un-contradicted.
	h.reportCommandResult(commandID, "success",
		fmt.Sprintf("EEPROM update staged (BOOT_ORDER=%s); rebooting to apply", hexOrder),
		map[string]string{"rebooting": "true"})
	h.sendStatusUpdate("restarting", "Rebooting to flash EEPROM boot order")

	// Give the status update a moment to flush, then reboot so the ROM applies it.
	time.Sleep(2 * time.Second)
	if err := rebootNow(); err != nil {
		return fmt.Errorf("reboot failed: %w", err)
	}
	return nil
}

// detectBoardRevision decodes this device's board revision code from
// /proc/cpuinfo. Returns ok=false when there is no usable code, and callers
// must then refuse to act rather than assume a board — see MatchesCM4Filter's
// caller, where the wrong assumption costs a pointless reboot, and the EEPROM
// package path, where it would cost a trip to the rack.
//
// The revision comes from OTP via the firmware, so it stays correct in the
// recovery bootstrap, where a forced device_tree= makes every BCM2712 board
// describe itself as a Compute Module 5.
func detectBoardRevision() (board.Revision, bool) {
	data, err := os.ReadFile("/proc/cpuinfo")
	if err != nil {
		return board.Revision{}, false
	}
	m := regexp.MustCompile(`(?m)^Revision\s*:\s*([0-9a-fA-F]+)\s*$`).FindSubmatch(data)
	if len(m) < 2 {
		return board.Revision{}, false
	}
	return board.ParseRevision(string(m[1]))
}

// detectRPiSoC returns "cm4" or "cm5" — the EEPROM FIRMWARE FAMILY, i.e. the
// silicon, not the form factor. A Pi 4 B answering "cm4" here is correct: it is
// BCM2711 and takes the same bootloader image as a Compute Module 4. Do not
// reuse this to decide which config.txt filter applies — that is
// board.Revision.MatchesCM4Filter, and the two answers differ on a Pi 4 B and a
// CM4S.
//
// The revision code is preferred because it reads the processor nibble and so
// needs no table of board names, but the device-tree model stays as an
// unconditional fallback: the platform still runs agents that predate the
// revision reporting, and an empty answer here fails the whole command.
func detectRPiSoC() (string, error) {
	if rev, ok := detectBoardRevision(); ok {
		if soc := rev.SoCFamily(); soc != "" {
			return soc, nil
		}
	}
	return detectRPiSoCFromModel()
}

// detectRPiSoCFromModel is the pre-revision-code path, kept as the fallback.
func detectRPiSoCFromModel() (string, error) {
	data, err := os.ReadFile("/proc/device-tree/model")
	if err != nil {
		return "", fmt.Errorf("failed to read device-tree model: %w", err)
	}
	model := string(bytes.Trim(data, "\x00"))
	switch {
	case strings.Contains(model, "Compute Module 5"), strings.Contains(model, "Pi 5"):
		return "cm5", nil
	case strings.Contains(model, "Compute Module 4"), strings.Contains(model, "Pi 4"):
		return "cm4", nil
	default:
		return "", fmt.Errorf("unsupported SoC model: %q", model)
	}
}

// detectHardwareSerial returns the Raspberry Pi hardware serial from /proc/cpuinfo
// (lowercase 16-hex). It uses the same pattern as the fingerprint reader so the
// per-device EEPROM path (by-serial/<serial>) matches the serial the platform
// stored for this node. Returns "" if unavailable.
func detectHardwareSerial() string {
	data, err := os.ReadFile("/proc/cpuinfo")
	if err != nil {
		return ""
	}
	m := regexp.MustCompile(`Serial\t*: ([a-z0-9]{16})`).FindSubmatch(data)
	if m == nil {
		return ""
	}
	return string(m[1])
}

// downloadFile fetches url into dst.
func downloadFile(url, dst string) error {
	resp, err := boundedHTTPClient(agentDownloadTimeout).Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status %d for %s", resp.StatusCode, url)
	}
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()
	if err := copyBoundedPackage(out, resp.Body); err != nil {
		return err
	}
	return nil
}

// verifySHA256SUMS lives in manifest_verify.go — deliberately untagged, so its
// tests run on a developer's machine and not only in the Linux CI container.

// mountBootPartitionRW mounts the SD/USB FAT boot partition read-write and
// returns its mount point and a cleanup function. If the bootstrap already
// mounted it read-only at /mnt/sdcard, it is remounted read-write in place.
func mountBootPartitionRW(logger *slog.Logger) (string, func(), error) {
	const existing = "/mnt/sdcard"
	// If /mnt/sdcard is already the boot partition (bootstrap mounted it ro),
	// remount it read-write rather than mounting a second time.
	if isMountPoint(existing) {
		if err := syscall.Mount("", existing, "", syscall.MS_REMOUNT, ""); err == nil {
			return existing, func() {
				syscall.Sync()
				_ = syscall.Mount("", existing, "", syscall.MS_REMOUNT|syscall.MS_RDONLY, "")
			}, nil
		}
		logger.Warn("remount rw of /mnt/sdcard failed, trying a fresh mount")
	}

	mp, err := os.MkdirTemp("", "bootpart-")
	if err != nil {
		return "", nil, err
	}
	// SD/eMMC and USB only: the ROM runs recovery.bin exclusively from those
	// media. NVMe boot partitions are deliberately excluded — staging there
	// looks successful but is never applied (the package just rots on disk).
	candidates := []string{"/dev/mmcblk1p1", "/dev/mmcblk0p1", "/dev/sda1", "/dev/mmcblk1", "/dev/mmcblk0"}
	for _, dev := range candidates {
		if _, statErr := os.Stat(dev); statErr != nil {
			continue
		}
		if err := syscall.Mount(dev, mp, "vfat", 0, ""); err == nil {
			logger.Info("mounted boot partition read-write", "device", dev, "mount", mp)
			return mp, func() {
				syscall.Sync()
				_ = syscall.Unmount(mp, 0)
				_ = os.Remove(mp)
			}, nil
		}
	}
	_ = os.Remove(mp)
	return "", nil, fmt.Errorf("no SD/USB boot media found (checked %v): the ROM only applies recovery.bin from SD/USB, so a netbooted device without a card cannot reflash its own EEPROM — insert the provisioning SD card or flash via usbboot", candidates)
}

// isMountPoint reports whether path is a mount point (its device differs from its parent).
func isMountPoint(path string) bool {
	var st, parent syscall.Stat_t
	if err := syscall.Stat(path, &st); err != nil {
		return false
	}
	if err := syscall.Stat(filepath.Dir(path), &parent); err != nil {
		return false
	}
	return st.Dev != parent.Dev
}

// reportFileStatus reports file status to the platform
// platformClient is guaranteed to be non-nil and implement the interface (set in constructor)
func (h *CommandHandler) reportFileStatus(path string, version int32, status, errorMessage string) {
	// Read current file content and hash for the report
	var content, hash string
	if h.fileReader != nil {
		if filePath, fileContent, err := h.fileReader.ReadFile(); err == nil && filePath == path {
			content = fileContent
			hash = h.fileReader.GetFileHash(content)
		}
	}

	if err := h.platformClient.SendFileChangedEvent(h.nodeID, h.accountID, h.uniqueToken, path, content, hash, version, status, errorMessage); err != nil {
		h.logger.Warn("failed to send file changed event", "error", err)
	}
}

// handleProvisionConnection handles manual provision connection commands.
// If target_device is provided, it mounts the device and provisions on that volume.
// If target_device is empty, it provisions on the currently running OS.
func (h *CommandHandler) handleProvisionConnection(commandID string, cmd *proto.ProvisionConnectionCommand) error {
	h.logger.Info("provision connection command received",
		"command_id", commandID,
		"username", cmd.Username,
		"target_device", cmd.TargetDevice,
		"root_partition", cmd.RootPartition)

	// Report command status: in_progress
	h.reportCommandStatus(commandID, "in_progress", 0, "Starting connection provisioning")

	if cmd.Username == "" {
		errMsg := "username is required for provision_connection command"
		h.reportCommandStatus(commandID, "failed", 0, errMsg)
		h.sendStatusUpdate("provision_connection_failed", errMsg)
		return errors.New(errMsg)
	}

	// Steps skipped without failing the provision, for the success report.
	var warnings []string

	// If target_device is provided, mount it and provision on that volume
	if cmd.TargetDevice != "" {
		// Determine root partition
		var rootPart string
		var rootPartNum int
		if cmd.RootPartition > 0 {
			// Use specified partition
			rootPartNum = int(cmd.RootPartition)
			rootPart = getPartitionPath(cmd.TargetDevice, rootPartNum)
			h.logger.Info("using specified root partition for provisioning",
				"partition_number", rootPartNum,
				"partition_path", rootPart)
		} else {
			// Auto-detect root partition
			detectedPart, detectedNum, err := h.detectRootPartition(cmd.TargetDevice)
			if err != nil {
				h.logger.Warn("failed to auto-detect root partition for provisioning, defaulting to partition 2",
					"error", err,
					"device", cmd.TargetDevice)
				rootPartNum = 2
				rootPart = getPartitionPath(cmd.TargetDevice, rootPartNum)
			} else {
				rootPart = detectedPart
				rootPartNum = detectedNum
				h.logger.Info("auto-detected root partition for provisioning",
					"partition_number", rootPartNum,
					"partition_path", rootPart)
			}
		}

		// Report progress: mounting partition
		h.reportCommandStatus(commandID, "in_progress", 20, "Mounting root partition")

		// Create temporary mount point
		mountPoint := "/mnt/tmp-provision-connection"
		if err := os.MkdirAll(mountPoint, 0755); err != nil {
			errMsg := fmt.Sprintf("failed to create mount point: %v", err)
			h.reportCommandStatus(commandID, "failed", 0, errMsg)
			h.sendStatusUpdate("provision_connection_failed", errMsg)
			return fmt.Errorf("failed to create mount point %s: %w", mountPoint, err)
		}

		// Mount the root partition
		h.logger.Info("mounting root partition for connection provisioning",
			"partition", rootPart,
			"mount_point", mountPoint)
		mountCmd := exec.Command("mount", rootPart, mountPoint)
		var mountStderr bytes.Buffer
		mountCmd.Stderr = &mountStderr
		if err := mountCmd.Run(); err != nil {
			errMsg := fmt.Sprintf("failed to mount root partition: %v", err)
			h.reportCommandStatus(commandID, "failed", 0, errMsg)
			h.sendStatusUpdate("provision_connection_failed", errMsg)
			return fmt.Errorf("failed to mount root partition %s: %w (stderr: %s)", rootPart, err, mountStderr.String())
		}
		defer func() {
			umountCmd := exec.Command("umount", mountPoint)
			var umountStderr bytes.Buffer
			umountCmd.Stderr = &umountStderr
			if err := umountCmd.Run(); err != nil {
				h.logger.Warn("failed to unmount root partition after connection provisioning",
					"mount_point", mountPoint,
					"error", err,
					"stderr", umountStderr.String())
			} else {
				h.logger.Info("unmounted root partition after connection provisioning", "mount_point", mountPoint)
			}
			// Clean up mount point
			if err := os.Remove(mountPoint); err != nil {
				h.logger.Warn("failed to remove mount point", "mount_point", mountPoint, "error", err)
			}
		}()

		// Report progress: provisioning connection
		h.reportCommandStatus(commandID, "in_progress", 50, "Provisioning connection on mounted volume")

		// Provision on mounted volume
		w, err := h.provisionConnectionOnRoot(mountPoint, cmd.Username, cmd.PasswordHash, cmd.SshKey, cmd.SshKeyType, cmd.Env)
		warnings = w
		if err != nil {
			errMsg := fmt.Sprintf("Provision connection failed: %v", err)
			h.logger.Error("provision connection failed", "command_id", commandID, "error", err)
			h.reportCommandStatus(commandID, "failed", 0, errMsg)
			h.sendStatusUpdate("provision_connection_failed", errMsg)
			return fmt.Errorf("provision connection failed: %w", err)
		}
	} else {
		// Report progress: provisioning connection
		h.reportCommandStatus(commandID, "in_progress", 50, "Provisioning connection on current filesystem")

		// Provision on current root filesystem (backward compatibility)
		w, err := h.provisionConnectionOnRoot("/", cmd.Username, cmd.PasswordHash, cmd.SshKey, cmd.SshKeyType, cmd.Env)
		warnings = w
		if err != nil {
			errMsg := fmt.Sprintf("Provision connection failed: %v", err)
			h.logger.Error("provision connection failed", "command_id", commandID, "error", err)
			h.reportCommandStatus(commandID, "failed", 0, errMsg)
			h.sendStatusUpdate("provision_connection_failed", errMsg)
			return fmt.Errorf("provision connection failed: %w", err)
		}
	}

	// Report command success. A step skipped without failing is named here, so
	// the operator reads it on the command and not only in the device journal.
	done := "Connection provisioning completed successfully"
	if len(warnings) > 0 {
		done = "Connection provisioning completed with a warning: " + strings.Join(warnings, "; ")
	}
	h.reportCommandStatus(commandID, "success", 100, done)

	// Final status update
	h.sendStatusUpdate("online", "Connection provisioning completed successfully")

	h.logger.Info("provision connection command executed successfully", "command_id", commandID)
	return nil
}

// provisionConnectionOnRoot provisions user credentials and SSH key on a root filesystem.
// rootPath can be "/" for current system or a mount point for a new OS volume.
// sshKeyType can be "ssh" (authorized_keys) or "ca" (certificate authority).
//
// passwordHash is a crypt(3) `$6$` hash, not a password: the platform hashes
// server-side so the fleet-wide provisioning default never travels in the clear.
// Empty means "no password" — a key-only user.
//
// The returned warnings name steps that were skipped without failing the
// provision; the caller puts them in the command's result.
func (h *CommandHandler) provisionConnectionOnRoot(rootPath, username, passwordHash, sshKey, sshKeyType string, env map[string]string) (warnings []string, err error) {
	// Validate credentials before they reach useradd/usermod/chpasswd. This is
	// the single chokepoint for all root-filesystem provisioning, so rejecting
	// hostile values here blocks option injection (a username starting with "-")
	// and chpasswd line injection (a newline in the username or the hash — which
	// with `user:value` input would address a DIFFERENT account, not merely set a
	// bad password).
	if err := validateProvisionConnectionUsername(username); err != nil {
		return nil, err
	}
	if passwordHash != "" && !shadowHashPattern.MatchString(passwordHash) {
		return nil, fmt.Errorf("the provisioning password hash for %q is not a crypt(3) SHA-512 hash", username)
	}
	// The key material is checked here too, front-loaded with the rest: a second
	// line in it would smuggle an extra authorized key, or an extra trusted CA
	// into /etc/ssh/ca_key.pub, past everything the operator actually granted.
	if sshKey != "" {
		if err := validateProvisionSSHKey(sshKey, sshKeyType); err != nil {
			return nil, err
		}
	}

	// Check if target username already exists
	targetUserExists, err := h.userExists(rootPath, username)
	if err != nil {
		return nil, fmt.Errorf("failed to check if user exists: %w", err)
	}

	if targetUserExists {
		// Target user already exists, update it
		h.logger.Info("target user already exists, will update existing user", "username", username)
		// Ensure the user has a valid login shell (may have been set to nologin/false)
		if err := h.ensureUserHasLoginShell(rootPath, username); err != nil {
			h.logger.Warn("failed to ensure user has login shell", "username", username, "error", err)
			// Continue anyway - user might still be able to login
		}
		// Add user to sudo group (in case they weren't already)
		if err := h.addUserToSudoers(rootPath, username); err != nil {
			h.logger.Warn("failed to add user to sudoers", "username", username, "error", err)
			// Continue anyway - sudo is optional
		}
	} else {
		// Target user doesn't exist, create new user
		h.logger.Info("target user does not exist, will create new user", "username", username)
		if err := h.createUserOnRoot(rootPath, username, passwordHash); err != nil {
			return nil, fmt.Errorf("failed to create user: %w", err)
		}
	}

	// 2. Set password if provided
	if passwordHash != "" {
		if err := h.setPasswordHashOnRoot(rootPath, username, passwordHash); err != nil {
			return nil, fmt.Errorf("failed to set password: %w", err)
		}
	}

	// 3. Provision SSH key if provided
	if sshKey != "" {
		// Default to "ssh" type if not specified
		if sshKeyType == "" {
			sshKeyType = "ssh"
		}

		if sshKeyType == "ca" {
			// CA key: configure in sshd_config for certificate-based auth
			if err := h.provisionCAKeyOnRoot(rootPath, sshKey); err != nil {
				return nil, fmt.Errorf("failed to provision CA key: %w", err)
			}
		} else {
			// Regular SSH key: write to user's authorized_keys
			if err := h.provisionSSHKeyOnRoot(rootPath, username, sshKey); err != nil {
				return nil, fmt.Errorf("failed to provision SSH key: %w", err)
			}
		}
	}

	// 4. Enable SSH service and configure password authentication
	if err := h.configureSSHServiceOnRoot(rootPath); err != nil {
		return nil, fmt.Errorf("failed to configure SSH service: %w", err)
	}

	// 5. Reconcile environment secrets into the target OS (/etc/orchestrator/env,
	// root only). Called unconditionally: an EMPTY set must still run so that
	// detaching the last env secret removes it from the device — gating on
	// len(env) > 0 would make a detached secret immortal there.
	envWarning, err := h.writeEnvironmentOnRoot(rootPath, env)
	if err != nil {
		return nil, fmt.Errorf("failed to write environment secrets: %w", err)
	}
	if envWarning != "" {
		warnings = append(warnings, envWarning)
	}

	// 6. Pre-enable OS-side EEPROM updates so the managed OS can reflash the EEPROM
	// remotely (boot-order changes / re-provision) with no separate enable_eeprom
	// step. Best-effort: never fail provisioning if the target OS lacks the file.
	if err := h.enableEEPROMUpdatesOnRoot(rootPath); err != nil {
		h.logger.Warn("failed to pre-enable EEPROM updates on target OS", "error", err)
	}

	// 6b. Mask the OS's automatic EEPROM updater: applying the distro's stock
	// firmware would drop our embedded pubkey, per-serial HTTP_PATH and adoption
	// token and break signed network boot. Only the platform-signed images may
	// touch the EEPROM. Best-effort.
	if err := h.maskEEPROMAutoUpdateOnRoot(rootPath); err != nil {
		h.logger.Warn("failed to mask OS EEPROM auto-update on target OS", "error", err)
	}

	// 7. Ensure the managed OS brings up ethernet via DHCP. Some OS images ship no
	// netplan config, leaving eth0 unmanaged with no IPv4, so the agent can never
	// reach the platform. Write a default DHCP netplan. Best-effort.
	//
	// Do not go looking for one error string here: the symptom depends on how the
	// platform is addressed. An IP endpoint (on-prem) fails at connect with
	// "network is unreachable"; a hostname fails earlier at DNS with
	// "produced zero addresses". Assuming the first is what left the runtime
	// self-heal dead on hostname-addressed installs.
	if err := h.ensureNetworkConfigOnRoot(rootPath); err != nil {
		h.logger.Warn("failed to write default network config on target OS", "error", err)
	}

	// 7b. A netplan is useless if nothing starts the daemon that renders it.
	// Best-effort.
	if err := h.ensureNetworkdEnabledOnRoot(rootPath); err != nil {
		h.logger.Warn("failed to enable systemd-networkd on target OS", "error", err)
	}

	return warnings, nil
}

// maskEEPROMAutoUpdateOnRoot masks the distro's automatic EEPROM update units
// in the target rootfs (systemd treats a unit symlinked to /dev/null as
// masked). Manual, platform-driven `rpi-eeprom-update -d -f <signed image>`
// still works — only the unattended stock-firmware path is disabled.
func (h *CommandHandler) maskEEPROMAutoUpdateOnRoot(rootPath string) error {
	unitDir := filepath.Join(rootPath, "etc", "systemd", "system")
	if err := os.MkdirAll(unitDir, 0755); err != nil {
		return fmt.Errorf("failed to create %s: %w", unitDir, err)
	}
	for _, unit := range []string{"rpi-eeprom-update.service"} {
		link := filepath.Join(unitDir, unit)
		if fi, err := os.Lstat(link); err == nil {
			if fi.Mode()&os.ModeSymlink != 0 {
				if target, err := os.Readlink(link); err == nil && target == "/dev/null" {
					continue // already masked
				}
			}
			if err := os.Remove(link); err != nil {
				return fmt.Errorf("failed to replace %s: %w", link, err)
			}
		}
		if err := os.Symlink("/dev/null", link); err != nil {
			return fmt.Errorf("failed to mask %s: %w", unit, err)
		}
		h.logger.Info("masked OS EEPROM auto-update unit", "unit", unit)
	}
	return nil
}

// enableEEPROMUpdatesOnRoot writes /etc/default/rpi-eeprom-update in the target
// rootfs so rpi-eeprom-update may flash the EEPROM via flashrom from the running
// OS. RPI_EEPROM_USE_FLASHROM=1 is universal (CM4/CM5); CM4_ENABLE_RPI_EEPROM_UPDATE
// is required on CM4 and ignored on CM5, so setting both is safe. Merges with any
// existing file, replacing only these two keys.
func (h *CommandHandler) enableEEPROMUpdatesOnRoot(rootPath string) error {
	managed := map[string]string{
		"RPI_EEPROM_USE_FLASHROM":      "1",
		"CM4_ENABLE_RPI_EEPROM_UPDATE": "1",
	}
	cfgPath := filepath.Join(rootPath, "etc", "default", "rpi-eeprom-update")

	kept := []string{}
	if existing, err := os.ReadFile(cfgPath); err == nil {
		for _, line := range strings.Split(string(existing), "\n") {
			trimmed := strings.TrimSpace(line)
			if trimmed == "" {
				continue
			}
			key := strings.TrimSpace(strings.SplitN(trimmed, "=", 2)[0])
			if _, ok := managed[key]; ok {
				continue
			}
			kept = append(kept, line)
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("failed to read %s: %w", cfgPath, err)
	}

	var b strings.Builder
	for _, line := range kept {
		b.WriteString(line)
		b.WriteString("\n")
	}
	// Deterministic order.
	for _, k := range []string{"CM4_ENABLE_RPI_EEPROM_UPDATE", "RPI_EEPROM_USE_FLASHROM"} {
		b.WriteString(fmt.Sprintf("%s=%s\n", k, managed[k]))
	}

	if err := os.MkdirAll(filepath.Dir(cfgPath), 0755); err != nil {
		return fmt.Errorf("failed to create %s: %w", filepath.Dir(cfgPath), err)
	}
	if err := os.WriteFile(cfgPath, []byte(b.String()), 0644); err != nil {
		return fmt.Errorf("failed to write %s: %w", cfgPath, err)
	}
	h.logger.Info("pre-enabled OS-side EEPROM updates on target rootfs", "path", cfgPath)
	return nil
}

// writeEnvironmentOnRoot delivers the effective env-secret set to the target
// filesystem as the root-only /etc/orchestrator/env and removes the copies older
// agents left in /etc/environment (see reconcileEnvSecretsOnRoot). An empty set
// is a real input: it removes the file, which is how the last detached secret
// leaves the device.
//
// The returned warning is non-empty when the legacy cleanup was skipped (see
// reconcileEnvSecretsOnRoot); the delivery itself succeeded.
func (h *CommandHandler) writeEnvironmentOnRoot(rootPath string, env map[string]string) (string, error) {
	warning, err := reconcileEnvSecretsOnRoot(rootPath, env)
	if err != nil {
		return "", err
	}
	if warning != "" {
		h.logger.Warn("left /etc/environment unchanged on target OS", "reason", warning)
	}
	h.logger.Info("reconciled environment secrets on target OS", "count", len(env),
		"path", filepath.Join(rootPath, envSecretsRelPath))
	return warning, nil
}

// MigrateLegacyEnvironmentSecrets runs once at agent start on the running
// system: a set an older agent wrote into /etc/environment, where pam_env hands
// it to every login session, moves into the root-only file. Best-effort — a
// failure is logged and the next provision retries the removal.
func (h *CommandHandler) MigrateLegacyEnvironmentSecrets() {
	migrated, err := migrateLegacyEnvironmentOnRoot("/")
	if err != nil {
		h.logger.Warn("failed to move environment secrets out of /etc/environment", "error", err)
		return
	}
	if migrated {
		h.logger.Info("moved environment secrets from /etc/environment to the root-only file",
			"path", "/"+envSecretsRelPath)
	}
}

// userExists checks if a user exists in the passwd file.
func (h *CommandHandler) userExists(rootPath, username string) (bool, error) {
	passwdPath := filepath.Join(rootPath, "etc", "passwd")
	passwdContent, err := os.ReadFile(passwdPath)
	if err != nil {
		return false, fmt.Errorf("failed to read /etc/passwd: %w", err)
	}

	lines := strings.Split(string(passwdContent), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		fields := strings.Split(line, ":")
		if len(fields) >= 1 && fields[0] == username {
			return true, nil
		}
	}

	return false, nil
}

// ensureUserHasLoginShell ensures a user has a valid login shell (not nologin/false).
func (h *CommandHandler) ensureUserHasLoginShell(rootPath, username string) error {
	passwdPath := filepath.Join(rootPath, "etc", "passwd")
	passwdContent, err := os.ReadFile(passwdPath)
	if err != nil {
		return fmt.Errorf("failed to read /etc/passwd: %w", err)
	}

	lines := strings.Split(string(passwdContent), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		fields := strings.Split(line, ":")
		if len(fields) >= 7 && fields[0] == username {
			currentShell := fields[6]
			// Check if shell is a non-login shell
			if currentShell == "/usr/sbin/nologin" || currentShell == "/sbin/nologin" ||
				currentShell == "/bin/false" || currentShell == "/usr/bin/false" {
				// Set shell to /bin/bash (or /bin/sh as fallback)
				chrootCmd := exec.Command("chroot", rootPath, "usermod", "-s", "/bin/bash", username)
				var stderr bytes.Buffer
				chrootCmd.Stderr = &stderr
				if err := chrootCmd.Run(); err != nil {
					// Try /bin/sh as fallback if /bin/bash doesn't exist
					chrootCmd = exec.Command("chroot", rootPath, "usermod", "-s", "/bin/sh", username)
					stderr.Reset()
					chrootCmd.Stderr = &stderr
					if err := chrootCmd.Run(); err != nil {
						return fmt.Errorf("failed to set login shell for user %s: %w (stderr: %s)", username, err, stderr.String())
					}
					h.logger.Info("set shell to /bin/sh for user", "username", username)
				} else {
					h.logger.Info("set shell to /bin/bash for user", "username", username)
				}
			}
			return nil
		}
	}

	return fmt.Errorf("user %s not found in passwd file", username)
}

// createUserOnRoot creates a new user account.
func (h *CommandHandler) createUserOnRoot(rootPath, username, passwordHash string) error {
	// Try useradd first (most common)
	chrootCmd := exec.Command("chroot", rootPath, "useradd", "-m", "-s", "/bin/bash", username)
	var stderr bytes.Buffer
	chrootCmd.Stderr = &stderr
	if err := chrootCmd.Run(); err != nil {
		// Fallback to adduser (Debian/Ubuntu)
		chrootCmd = exec.Command("chroot", rootPath, "adduser", "--disabled-password", "--gecos", "", username)
		stderr.Reset()
		chrootCmd.Stderr = &stderr
		if err := chrootCmd.Run(); err != nil {
			return fmt.Errorf("failed to create user %s: %w (stderr: %s)", username, err, stderr.String())
		}
	}

	// Set password if provided. A HASH, applied with `chpasswd -e` — see
	// setPasswordHashOnRoot.
	if passwordHash != "" {
		if err := h.setPasswordHashOnRoot(rootPath, username, passwordHash); err != nil {
			return fmt.Errorf("failed to set password for new user: %w", err)
		}
	}

	// Add user to sudo group
	if err := h.addUserToSudoers(rootPath, username); err != nil {
		h.logger.Warn("failed to add user to sudoers", "username", username, "error", err)
		// Continue anyway - user creation succeeded, sudo is optional
	}

	return nil
}

// setPasswordOnRoot is GONE, and its absence is the property worth stating: the
// agent has no code path that accepts a cleartext password
// from the platform at all. Both senders (the access config and
// provision_connection) hash server-side and land on setPasswordHashOnRoot; a
// helper that took a plaintext password would only be an invitation to
// reintroduce the leak. Do not add one back.

// setPasswordHashOnRoot installs an already-hashed password with `chpasswd -e`,
// which writes the value into /etc/shadow verbatim instead of hashing it.
//
// This is how the access config sets passwords: the platform hashes
// server-side and never sends the cleartext, because an unprivileged shell on
// one node could read that node's adoption token, open a stream as it, and be
// handed the account's cleartext passwords for every node in the account.
//
// The hash is validated against shadowHashPattern BEFORE anything is applied
// (validateAccessConfig), which matters more than it looks: chpasswd reads
// `user:value` lines, so a colon or newline inside the value would not make a
// bad password, it would address a different account.
func (h *CommandHandler) setPasswordHashOnRoot(rootPath, username, hash string) error {
	chrootCmd := exec.Command("chroot", rootPath, "chpasswd", "-e")
	chrootCmd.Stdin = strings.NewReader(fmt.Sprintf("%s:%s\n", username, hash))
	var stderr bytes.Buffer
	chrootCmd.Stderr = &stderr
	if err := chrootCmd.Run(); err != nil {
		// The hash is not secret in the way a password is, but it is still
		// credential material and stderr may echo the input line, so only the
		// username is reported.
		return fmt.Errorf("failed to set password hash for user %s: %w (stderr: %s)", username, err, stderr.String())
	}
	return nil
}

// addUserToSudoers adds a user to the sudo group (or wheel group on some systems).
// This gives the user sudo privileges.
func (h *CommandHandler) addUserToSudoers(rootPath, username string) error {
	// Try adding to 'sudo' group first (most common on Debian/Ubuntu)
	chrootCmd := exec.Command("chroot", rootPath, "usermod", "-aG", "sudo", username)
	var stderr bytes.Buffer
	chrootCmd.Stderr = &stderr
	if err := chrootCmd.Run(); err != nil {
		// Fallback to 'wheel' group (common on RHEL/CentOS/Fedora)
		chrootCmd = exec.Command("chroot", rootPath, "usermod", "-aG", "wheel", username)
		stderr.Reset()
		chrootCmd.Stderr = &stderr
		if err := chrootCmd.Run(); err != nil {
			// If both fail, try gpasswd as an alternative method
			chrootCmd = exec.Command("chroot", rootPath, "gpasswd", "-a", username, "sudo")
			stderr.Reset()
			chrootCmd.Stderr = &stderr
			if err := chrootCmd.Run(); err != nil {
				// Last attempt with wheel group using gpasswd
				chrootCmd = exec.Command("chroot", rootPath, "gpasswd", "-a", username, "wheel")
				stderr.Reset()
				chrootCmd.Stderr = &stderr
				if err := chrootCmd.Run(); err != nil {
					return fmt.Errorf("failed to add user %s to sudoers: %w (stderr: %s)", username, err, stderr.String())
				}
				h.logger.Info("added user to wheel group using gpasswd", "username", username)
			} else {
				h.logger.Info("added user to sudo group using gpasswd", "username", username)
			}
		} else {
			h.logger.Info("added user to wheel group", "username", username)
		}
	} else {
		h.logger.Info("added user to sudo group", "username", username)
	}
	return nil
}

// provisionSSHKeyOnRoot provisions an SSH public key for a user.
//
// Every filesystem step goes through an anchor rather than a path string, and
// that is the whole of this function's security.
//
// The home directory belongs to the account being provisioned, and an
// unprivileged local user is exactly what this product manufactures — a non-sudo
// access entry is one. So the user can replace their own ~/.ssh, and they used
// to be able to replace it with a symlink to /etc: os.MkdirAll stats THROUGH
// the link, sees a directory and returns nil, and the ownership step that
// followed was os.Chown + os.Chmod on the same string. Root then chowned /etc to
// that user at mode 0700. A symlink planted at authorized_keys was the same bug
// one level down, with root writing through it.
//
// With target_device empty — the default, and what the provision-access starter
// sends — rootPath is "/", so this ran against the LIVE system.
//
// The anchoring approach is the one anchored_file_linux.go already documents for
// write_file and delete_file; it simply never reached this path.
func (h *CommandHandler) provisionSSHKeyOnRoot(rootPath, username, sshKey string) error {
	// The account's real home decides where sshd reads authorized_keys, so it
	// is resolved from passwd and never guessed. Failing here is deliberate:
	// the alternative is a green command that granted nothing.
	entry, err := lookupPasswdEntry(rootPath, username)
	if err != nil {
		return err
	}
	home, err := resolveProvisionHome(username, entry.Home)
	if err != nil {
		return err
	}
	uid, gid, err := numericPasswdIDs(entry.UID, entry.GID)
	if err != nil {
		return err
	}

	homeDir := filepath.Join(rootPath, home)
	root := os.Geteuid() == 0

	// The home directory itself is created by path. Its parent (/home, or the
	// image's equivalent) is root-owned, so the user being provisioned cannot
	// plant anything at this name; everything BELOW it is theirs, which is why
	// the rest of this function stops using strings here.
	if root {
		if err := os.MkdirAll(homeDir, 0755); err != nil {
			return fmt.Errorf("failed to create home directory: %w", err)
		}
	}
	// Canonicalise before anchoring: openAnchorDir walks the path refusing a
	// symlink at any component, so a legitimately linked /home
	// (or a linked mount point on the offline path) has to be resolved first.
	// The walk then only ever refuses a tree that changed after this resolve.
	anchorHome := homeDir
	if resolved, rerr := filepath.EvalSymlinks(homeDir); rerr == nil {
		anchorHome = resolved
	}
	homeFD, err := openAnchorDir(anchorHome)
	if err != nil {
		return fmt.Errorf("failed to open home directory: %w", err)
	}
	defer func() { _ = unix.Close(homeFD) }()
	if root {
		if err := chownFD(homeFD, uid, gid); err != nil {
			return fmt.Errorf("failed to set home directory ownership: %w", err)
		}
	}

	// .ssh, created and verified through the home anchor. A pre-planted symlink
	// fails here instead of redirecting everything below.
	sshDirTarget, err := anchoredIn(homeFD, ".ssh", homeDir)
	if err != nil {
		return err
	}
	if err := sshDirTarget.EnsureDir(0700); err != nil {
		return fmt.Errorf("failed to create .ssh directory: %w", err)
	}
	if root {
		if err := sshDirTarget.Chown(uid, gid); err != nil {
			return fmt.Errorf("failed to prepare .ssh directory: %w", err)
		}
		if err := sshDirTarget.Chmod(0700); err != nil {
			return fmt.Errorf("failed to prepare .ssh directory: %w", err)
		}
	}

	sshFD, err := unix.Openat(homeFD, ".ssh", unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("failed to open .ssh directory: %w", err)
	}
	defer func() { _ = unix.Close(sshFD) }()

	sshDirDisplay := filepath.Join(homeDir, ".ssh")
	keysTarget, err := anchoredIn(sshFD, "authorized_keys", sshDirDisplay)
	if err != nil {
		return err
	}

	// Read what is there, through the anchor and refusing a symlink. An absent
	// file is the ordinary first-provision case; anything else is refused rather
	// than silently treated as empty, because treating it as empty would DROP
	// the keys already installed.
	var existingKeys []string
	exists, err := keysTarget.Exists()
	if err != nil {
		return fmt.Errorf("failed to inspect authorized_keys: %w", err)
	}
	if exists {
		content, err := keysTarget.ReadBounded(maxAuthorizedKeysBytes)
		if err != nil {
			return fmt.Errorf("failed to read authorized_keys: %w", err)
		}
		for _, line := range strings.Split(strings.TrimSpace(string(content)), "\n") {
			line = strings.TrimSpace(line)
			if line != "" && !strings.HasPrefix(line, "#") {
				existingKeys = append(existingKeys, line)
			}
		}
	}

	keyTrimmed := strings.TrimSpace(sshKey)
	for _, existingKey := range existingKeys {
		if existingKey == keyTrimmed {
			h.logger.Info("SSH key already exists in authorized_keys", "username", username)
			if root {
				if err := keysTarget.Chown(uid, gid); err != nil {
					h.logger.Warn("failed to reassert authorized_keys ownership", "error", err)
				}
				if err := keysTarget.Chmod(0600); err != nil {
					h.logger.Warn("failed to reassert authorized_keys permissions", "error", err)
				}
			}
			return nil
		}
	}

	existingKeys = append(existingKeys, keyTrimmed)
	content := strings.Join(existingKeys, "\n") + "\n"

	// AtomicWrite creates a fresh inode and renames it over the name, so a
	// symlink sitting there is REPLACED rather than written through.
	if err := keysTarget.AtomicWrite([]byte(content), 0600); err != nil {
		return fmt.Errorf("failed to write authorized_keys: %w", err)
	}
	if root {
		if err := keysTarget.Chown(uid, gid); err != nil {
			return fmt.Errorf("failed to secure authorized_keys: %w", err)
		}
	}

	h.logger.Info("SSH key provisioned successfully", "username", username, "home", home)
	return nil
}

// maxAuthorizedKeysBytes bounds the existing file this function reads back.
// Generous against any real key set (a key line is a few hundred bytes) and
// small enough that a device cannot be made to buffer a crafted file.
const maxAuthorizedKeysBytes = 1 << 20

// chownFD sets ownership of an already-open descriptor. Used for the home
// directory, whose fd is held for the rest of provisioning anyway — chowning
// the descriptor cannot be redirected by a rename after the open.
func chownFD(fd, uid, gid int) error {
	if err := unix.Fchownat(fd, "", uid, gid, unix.AT_EMPTY_PATH|unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return &os.PathError{Op: "fchownat", Path: fmt.Sprintf("/proc/self/fd/%d", fd), Err: err}
	}
	return nil
}

// provisionCAKeyOnRoot provisions a CA public key for certificate-based SSH authentication.
// It writes the CA key to /etc/ssh/ca_key.pub and configures sshd to trust it.
func (h *CommandHandler) provisionCAKeyOnRoot(rootPath, caKey string) error {
	// 1. Write CA key to /etc/ssh/ca_key.pub
	caKeyPath := filepath.Join(rootPath, "etc", "ssh", "ca_key.pub")
	caKeyContent := strings.TrimSpace(caKey) + "\n"

	if err := os.WriteFile(caKeyPath, []byte(caKeyContent), 0644); err != nil {
		return fmt.Errorf("failed to write CA key to %s: %w", caKeyPath, err)
	}
	h.logger.Info("CA key written", "path", caKeyPath)

	// 2. Add TrustedUserCAKeys to sshd_config if not already present
	sshdConfigPath := filepath.Join(rootPath, "etc", "ssh", "sshd_config")
	sshdConfigContent, err := os.ReadFile(sshdConfigPath)
	if err != nil {
		return fmt.Errorf("failed to read sshd_config: %w", err)
	}

	trustedCALine := "TrustedUserCAKeys /etc/ssh/ca_key.pub"
	configStr := string(sshdConfigContent)

	// Check if TrustedUserCAKeys is already configured
	if strings.Contains(configStr, "TrustedUserCAKeys") {
		// Check if it's already pointing to our CA key file
		if strings.Contains(configStr, trustedCALine) {
			h.logger.Info("TrustedUserCAKeys already configured in sshd_config")
		} else {
			// TrustedUserCAKeys exists but points elsewhere - update it
			h.logger.Warn("TrustedUserCAKeys already exists with different value, updating")
			// Replace existing TrustedUserCAKeys line
			lines := strings.Split(configStr, "\n")
			for i, line := range lines {
				trimmed := strings.TrimSpace(line)
				if strings.HasPrefix(trimmed, "TrustedUserCAKeys") && !strings.HasPrefix(trimmed, "#") {
					lines[i] = trustedCALine
					break
				}
			}
			configStr = strings.Join(lines, "\n")
			if err := os.WriteFile(sshdConfigPath, []byte(configStr), 0644); err != nil {
				return fmt.Errorf("failed to update sshd_config: %w", err)
			}
			h.logger.Info("updated TrustedUserCAKeys in sshd_config")
		}
	} else {
		// Add TrustedUserCAKeys to the end of the config
		if !strings.HasSuffix(configStr, "\n") {
			configStr += "\n"
		}
		configStr += "\n# CA-based SSH authentication\n" + trustedCALine + "\n"
		if err := os.WriteFile(sshdConfigPath, []byte(configStr), 0644); err != nil {
			return fmt.Errorf("failed to update sshd_config: %w", err)
		}
		h.logger.Info("added TrustedUserCAKeys to sshd_config")
	}

	// Note: sshd will pick up the new configuration on restart or reload.
	// The node will need to restart sshd or reboot for the changes to take effect.
	h.logger.Info("CA key provisioned successfully - sshd restart required for changes to take effect")
	return nil
}

// configureSSHServiceOnRoot enables SSH service and configures it to allow password authentication.
func (h *CommandHandler) configureSSHServiceOnRoot(rootPath string) error {
	// 1. Enable and start SSH service (try both 'ssh' and 'sshd' service names)
	// Most modern systems use 'ssh', but some use 'sshd'
	sshServiceNames := []string{"ssh", "sshd"}
	var enabled bool

	for _, serviceName := range sshServiceNames {
		// Check if service exists by trying to enable it
		enableCmd := exec.Command("chroot", rootPath, "systemctl", "enable", serviceName)
		var enableStderr bytes.Buffer
		enableCmd.Stderr = &enableStderr
		if err := enableCmd.Run(); err != nil {
			// Service might not exist, try next one
			h.logger.Debug("failed to enable SSH service", "service", serviceName, "error", err)
			continue
		}
		enabled = true
		h.logger.Info("enabled SSH service", "service", serviceName)

		// Try to start the service (may fail if systemd is not running in chroot, that's okay)
		startCmd := exec.Command("chroot", rootPath, "systemctl", "start", serviceName)
		var startStderr bytes.Buffer
		startCmd.Stderr = &startStderr
		if err := startCmd.Run(); err != nil {
			h.logger.Debug("failed to start SSH service in chroot (expected if systemd not running)", "service", serviceName, "error", err)
		} else {
			h.logger.Info("started SSH service", "service", serviceName)
		}
		break
	}

	if !enabled {
		h.logger.Warn("could not enable SSH service (service may not be installed or systemd not available)")
		// Continue anyway - service might be enabled by default or configured differently
	}

	// 2. Configure SSH to allow password authentication
	sshdConfigPath := filepath.Join(rootPath, "etc", "ssh", "sshd_config")
	if _, err := os.Stat(sshdConfigPath); os.IsNotExist(err) {
		h.logger.Warn("sshd_config not found, skipping SSH configuration", "path", sshdConfigPath)
		return nil // SSH might not be installed, that's okay
	}

	// Read existing config
	configContent, err := os.ReadFile(sshdConfigPath)
	if err != nil {
		return fmt.Errorf("failed to read sshd_config: %w", err)
	}

	lines := strings.Split(string(configContent), "\n")
	var updatedLines []string
	passwordAuthSet := false
	// Everything between the access reconciler's markers belongs to it, and this
	// function must not touch it.
	//
	// On an image with no Include directive the reconciler keeps its settings in
	// a marker block in this very file, so rewriting every
	// PasswordAuthentication line here silently flipped the ACCESS POLICY's own
	// statement to yes. The next apply_access_config then computed the same
	// desired ConfigHash, saw it unchanged, reported "already current" and never
	// corrected the drift — an account that had switched password logins off got
	// them back permanently, with the platform reporting convergence.
	inAccessBlock := false
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		lower := strings.ToLower(trimmed)

		switch {
		case strings.HasPrefix(trimmed, accessMarkerBegin):
			inAccessBlock = true
		case strings.HasPrefix(trimmed, accessMarkerEnd):
			inAccessBlock = false
		}
		if inAccessBlock || strings.HasPrefix(trimmed, accessMarkerEnd) {
			updatedLines = append(updatedLines, line)
			continue
		}

		// Check if PasswordAuthentication is already set
		if strings.HasPrefix(lower, "passwordauthentication") {
			// Update existing setting
			updatedLines = append(updatedLines, "PasswordAuthentication yes")
			passwordAuthSet = true
			continue
		}

		// Skip commented lines that might conflict
		if strings.HasPrefix(lower, "#passwordauthentication") {
			// Uncomment and set to yes
			updatedLines = append(updatedLines, "PasswordAuthentication yes")
			passwordAuthSet = true
			continue
		}

		updatedLines = append(updatedLines, line)
	}

	// Add PasswordAuthentication if not found
	if !passwordAuthSet {
		updatedLines = append(updatedLines, "")
		updatedLines = append(updatedLines, "# Allow password authentication")
		updatedLines = append(updatedLines, "PasswordAuthentication yes")
	}

	// Write updated config, then let sshd judge it and put the old one back if
	// it refuses.
	//
	// This was a bare os.WriteFile on the PRIMARY sshd config with no validation
	// at all, while the access reconciler — which edits the same file — snapshots
	// and validates for exactly this reason: a config sshd rejects means sshd
	// does not start on the next boot, and the node is stranded with no way in.
	updatedContent := strings.Join(updatedLines, "\n") + "\n"
	if err := writeFileAtomic(sshdConfigPath, []byte(updatedContent), 0o644); err != nil {
		return fmt.Errorf("failed to write sshd_config: %w", err)
	}
	if err := h.validateSSHDConfig(rootPath); err != nil {
		if restoreErr := writeFileAtomic(sshdConfigPath, configContent, 0o644); restoreErr != nil {
			h.logger.Error("sshd rejected the configuration AND the previous one could not be restored",
				"path", sshdConfigPath, "validate_error", err, "restore_error", restoreErr)
		}
		return fmt.Errorf("sshd rejected the configuration, reverted: %w", err)
	}

	h.logger.Info("configured SSH to allow password authentication", "config_path", sshdConfigPath)

	// On cloud-init images (e.g. Ubuntu) the main sshd_config does
	// `Include /etc/ssh/sshd_config.d/*.conf` near the top, and cloud-init ships
	// 50-cloud-init.conf with `PasswordAuthentication no`. sshd uses the FIRST
	// value seen, so our edit to the main file loses. Drop a 00- file that sorts
	// before cloud-init's so our setting wins.
	dropInDir := filepath.Join(rootPath, "etc", "ssh", "sshd_config.d")
	if _, err := os.Stat(dropInDir); err == nil {
		dropIn := filepath.Join(dropInDir, "00-orchestrator.conf")
		content := "# Managed by orchestrator; overrides cloud-init's PasswordAuthentication.\nPasswordAuthentication yes\nKbdInteractiveAuthentication yes\n"
		if err := os.WriteFile(dropIn, []byte(content), 0644); err != nil {
			h.logger.Warn("failed to write sshd drop-in", "path", dropIn, "error", err)
		} else {
			h.logger.Info("wrote sshd password-auth drop-in", "path", dropIn)
		}
	}
	return nil
}

// enableOrchestratorAgentService enables the orchestrator-agent systemd service to start on boot.
// This should be called after the package is installed and the adoption file is in place.
// enableAgentServiceOnTarget enables the installed variant's unit and drops a
// stale enable-symlink of the counterpart (dpkg -r removes the unit file but
// leaves the wants/ symlink dangling, and a dangling wants entry produces a
// failed unit on every boot of the installed OS).
func (h *CommandHandler) enableAgentServiceOnTarget(rootPath, variant string) error {
	serviceName := "orchestrator-agent"
	counterpartService := "orchestrator-watcher"
	if variant == "watcher" {
		serviceName, counterpartService = counterpartService, serviceName
	}
	staleLink := filepath.Join(rootPath, "etc", "systemd", "system", "multi-user.target.wants", counterpartService+".service")
	if err := os.Remove(staleLink); err == nil {
		h.logger.Info("removed the counterpart service's enable symlink", "link", staleLink)
	}

	// Check if systemd is available (service file should be installed by the package)
	servicePath := filepath.Join(rootPath, "etc", "systemd", "system", serviceName+".service")
	if _, err := os.Stat(servicePath); os.IsNotExist(err) {
		// For tar.gz installations, the service file might not be installed
		// Try to create it manually
		h.logger.Info("agent service unit not found, checking if we need to install it", "service", serviceName, "path", servicePath)

		// Check if the binary exists (the binary name matches the unit name for
		// both variants)
		binaryPath := filepath.Join(rootPath, "usr", "bin", serviceName)
		if _, err := os.Stat(binaryPath); os.IsNotExist(err) {
			// Also check /usr/local/bin for tar.gz installations
			binaryPath = filepath.Join(rootPath, "usr", "local", "bin", serviceName)
			if _, err := os.Stat(binaryPath); os.IsNotExist(err) {
				return fmt.Errorf("%s binary not found and service file not installed", serviceName)
			}
		}

		// tar.gz installations ship no unit file; warn and continue.
		h.logger.Warn("agent service unit not found, service may not start on boot", "service", serviceName, "path", servicePath)
		return nil
	}

	// Reload systemd daemon to pick up the new service file
	h.logger.Info("reloading systemd daemon", "root_path", rootPath)
	daemonReloadCmd := exec.Command("chroot", rootPath, "systemctl", "daemon-reload")
	var daemonReloadStderr bytes.Buffer
	daemonReloadCmd.Stderr = &daemonReloadStderr
	if err := daemonReloadCmd.Run(); err != nil {
		// daemon-reload might fail in chroot if systemd is not running, but that's okay
		// The service will be enabled and will start on the next boot
		h.logger.Debug("systemctl daemon-reload failed in chroot (expected if systemd not running)",
			"error", err,
			"stderr", daemonReloadStderr.String())
	} else {
		h.logger.Info("systemd daemon reloaded successfully")
	}

	// Enable the service to start on boot
	h.logger.Info("enabling agent service", "service", serviceName, "root_path", rootPath)
	enableCmd := exec.Command("chroot", rootPath, "systemctl", "enable", serviceName)
	var enableStderr bytes.Buffer
	enableCmd.Stderr = &enableStderr
	if err := enableCmd.Run(); err != nil {
		return fmt.Errorf("failed to enable %s service: %w (stderr: %s)", serviceName, err, enableStderr.String())
	}

	h.logger.Info("agent service enabled successfully", "service", serviceName)
	return nil
}

// handleEnableEEPROM handles enable_eeprom commands
func (h *CommandHandler) handleEnableEEPROM(commandID string, cmd *proto.EnableEEPROMCommand) error {
	h.logger.Info("enable EEPROM command received", "command_id", commandID)

	// Report command status: in_progress
	h.reportCommandStatus(commandID, "in_progress", 0, "Enabling EEPROM updates")

	// What this command is FOR: letting rpi-eeprom-update flash a
	// platform-SIGNED EEPROM image from the running OS via flashrom, instead of
	// the fallback that stages the package on SD/USB and reboots so the ROM's
	// recovery.bin flashes it. It does NOT re-enable the distro's unattended
	// EEPROM updates — that unit stays masked, deliberately, because stock
	// firmware drops our embedded pubkey and breaks signed netboot.
	//
	// Only RPI_EEPROM_USE_FLASHROM is universal. CM4_ENABLE_RPI_EEPROM_UPDATE
	// and the [cm4] SPI overlays are CM4-only — a [cm4] filter never matches a
	// CM5/Pi5 — so on anything else the overlays are inert and the reboot they
	// require is pure downtime. This used to reboot every board unconditionally.
	if err := h.enableEEPROMUpdatesOnRoot("/"); err != nil {
		errMsg := fmt.Sprintf("Failed to enable EEPROM updates: %v", err)
		h.logger.Error("failed to write the rpi-eeprom-update config", "command_id", commandID, "error", err)
		h.reportCommandStatus(commandID, "failed", 0, errMsg)
		return fmt.Errorf("failed to enable EEPROM updates: %w", err)
	}

	// This asks "does config.txt's [cm4] section apply here", which is NOT the
	// SoC question the EEPROM-package path asks. A Pi 4 B and a CM4S are both
	// BCM2711 — same firmware family as a CM4 — but neither is matched by
	// [cm4], so the SPI directives below would sit in their config.txt unread
	// and the reboot would buy nothing. Answered from the board revision code,
	// which the firmware writes from OTP.
	rev, revOK := detectBoardRevision()
	if !revOK {
		// Unknown board: do the universal half and stop. Rebooting hardware we
		// cannot identify, to apply overlays that may not apply to it, is the
		// worse of the two mistakes.
		h.logger.Warn("could not identify the board; skipping the CM4-only step", "command_id", commandID)
		// Say so explicitly. The platform pins a reboot-class command's node to
		// "restarting" at dispatch and waits for a reconnect; without this the
		// node sits pinned forever on every board that is not a CM4.
		h.reportCommandResult(commandID, "success",
			"EEPROM updates enabled (flashrom). Board not identified, so the CM4-only settings were skipped; no reboot needed.",
			map[string]string{"rebooting": "false"})
		return nil
	}
	if !rev.MatchesCM4Filter() {
		h.reportCommandResult(commandID, "success",
			"EEPROM updates enabled (flashrom). No reboot needed on this board.",
			map[string]string{"rebooting": "false"})
		return nil
	}

	// CM4 from here: the SPI overlays go into config.txt and only take effect
	// after a boot, so this is the one path that legitimately restarts.
	h.reportCommandStatus(commandID, "in_progress", 50, "Applying the CM4 SPI settings to config.txt")
	bootOrderWriter := hardware.NewBootOrderWriter(h.logger)
	if err := bootOrderWriter.FixCM4EEPROMConfig(); err != nil {
		errMsg := fmt.Sprintf("Failed to enable EEPROM updates: %v", err)
		h.logger.Error("failed to enable EEPROM updates", "command_id", commandID, "error", err)
		h.reportCommandStatus(commandID, "failed", 0, errMsg)
		return fmt.Errorf("failed to enable EEPROM updates: %w", err)
	}

	h.reportCommandStatus(commandID, "in_progress", 80, "EEPROM configuration updated, rebooting...")
	h.logger.Info("rebooting system after EEPROM enablement", "command_id", commandID)
	if err := rebootNow(); err != nil {
		errMsg := fmt.Sprintf("Reboot command failed: %v", err)
		h.logger.Error("reboot command failed", "command_id", commandID, "error", err)
		h.reportCommandStatus(commandID, "failed", 50, errMsg)
		return fmt.Errorf("reboot command failed: %w", err)
	}

	// The one path that really does reboot. Stated positively so the platform's
	// dispatch-time pin is confirmed rather than merely un-contradicted.
	h.reportCommandResult(commandID, "success", "EEPROM enabled, system rebooting",
		map[string]string{"rebooting": "true"})

	return nil
}

// handleEraseDrive handles erase_drive commands
func (h *CommandHandler) handleEraseDrive(commandID string, cmd *proto.EraseDriveCommand) error {
	h.logger.Info("erase drive command received", "command_id", commandID, "target_device", cmd.TargetDevice)

	// Report status: initial validation
	h.reportCommandStatus(commandID, "in_progress", 0, "Validating device...")

	// Validate storage reader is available
	if h.storageReader == nil {
		errMsg := "Storage reader not available"
		h.logger.Error("storage reader not available", "command_id", commandID)
		h.reportCommandStatus(commandID, "failed", 0, errMsg)
		return errors.New(errMsg)
	}

	// Validate device exists
	devices, err := h.storageReader.DetectDevices()
	if err != nil {
		errMsg := fmt.Sprintf("Failed to detect devices: %v", err)
		h.logger.Error("failed to detect devices", "command_id", commandID, "error", err)
		h.reportCommandStatus(commandID, "failed", 0, errMsg)
		return fmt.Errorf("failed to detect devices: %w", err)
	}

	// Check if device exists
	device, exists := devices[cmd.TargetDevice]
	if !exists || device == nil {
		errMsg := fmt.Sprintf("Device %s not found", cmd.TargetDevice)
		h.logger.Error("device not found", "command_id", commandID, "target_device", cmd.TargetDevice)
		h.reportCommandStatus(commandID, "failed", 0, errMsg)
		return fmt.Errorf("device %s not found", cmd.TargetDevice)
	}

	// Check if device is boot drive (any partition with mount_point == "/")
	for _, partition := range device.Partitions {
		if partition != nil && partition.MountPoint == "/" {
			errMsg := fmt.Sprintf("Cannot erase boot drive: device %s contains the root filesystem", cmd.TargetDevice)
			h.logger.Error("attempted to erase boot drive", "command_id", commandID, "target_device", cmd.TargetDevice)
			h.reportCommandStatus(commandID, "failed", 0, errMsg)
			return errors.New(errMsg)
		}
	}

	// Report status: device validated
	h.reportCommandStatus(commandID, "in_progress", 25, "Device validated, preparing to erase...")

	// Release the recovery bootstrap's own mounts on this device. wipefs opens
	// the whole-disk node O_EXCL, which Linux refuses while any partition of it
	// is mounted — and the provisioning card the device booted from is mounted
	// by the bootstrap itself. Without this the erase fails with "probing
	// initialization failed: Device or resource busy" and names nothing that
	// would let an operator work out why. No-op on an installed OS.
	released, _, restoreMounts, rerr := h.releaseBootMediaMounts(cmd.TargetDevice)
	if rerr != nil {
		h.logger.Warn("could not fully release the target device before erase",
			"command_id", commandID, "target_device", cmd.TargetDevice, "error", rerr)
	} else if len(released) > 0 {
		h.reportCommandStatus(commandID, "in_progress", 40,
			fmt.Sprintf("Released recovery mounts on %s (%s)", cmd.TargetDevice, strings.Join(released, ", ")))
	}

	// Ask the hardware whether it is there before handing the operator a tool's
	// internals. This runs AFTER the mounts are released, so a busy device is not
	// mistaken for a dead one: the probe opens read-only and shared, but keeping
	// the order means the two failures cannot be confused in the report either.
	if err := h.checkDeviceResponds(cmd.TargetDevice); err != nil {
		// Refused with nothing erased: put the card's mount back.
		restoreMounts()
		h.logger.Error("target device is not responding", "command_id", commandID,
			"target_device", cmd.TargetDevice, "error", err)
		h.reportCommandStatus(commandID, "failed", 40, err.Error())
		return err
	}

	// Report status: erasing
	h.reportCommandStatus(commandID, "in_progress", 50, "Erasing drive filesystem signatures...")

	// Execute wipefs -a to remove all filesystem signatures
	h.logger.Info("executing wipefs", "command_id", commandID, "target_device", cmd.TargetDevice)
	wipefsCmd := exec.Command("wipefs", "-a", cmd.TargetDevice)
	var wipefsStderr bytes.Buffer
	wipefsCmd.Stderr = &wipefsStderr

	if err := wipefsCmd.Run(); err != nil {
		errMsg := fmt.Sprintf("wipefs failed: %v (stderr: %s)", err, wipefsStderr.String())
		h.logger.Error("wipefs failed", "command_id", commandID, "target_device", cmd.TargetDevice, "error", err, "stderr", wipefsStderr.String())
		h.reportCommandStatus(commandID, "failed", 50, errMsg)
		return fmt.Errorf("wipefs failed on %s: %w (stderr: %s)", cmd.TargetDevice, err, wipefsStderr.String())
	}

	h.logger.Info("wipefs completed successfully", "command_id", commandID, "target_device", cmd.TargetDevice)

	// Report status: re-detecting drives
	h.reportCommandStatus(commandID, "in_progress", 75, "Drive erased, re-detecting storage devices...")

	// Trigger hardware info reporting to update drive information
	if h.hardwareInfoReporter != nil {
		if err := h.hardwareInfoReporter(); err != nil {
			h.logger.Warn("failed to trigger hardware info reporting after erase", "command_id", commandID, "error", err)
			// Don't fail the command if reporting fails, but log it
		} else {
			h.logger.Info("hardware info reporting triggered after erase", "command_id", commandID)
		}
	}

	// Report success
	h.reportCommandStatus(commandID, "success", 100, "Drive erased successfully and storage devices updated")

	return nil
}

// handleSetHostname changes the hostname of a managed (disk-booted) node. It
// persists via hostnamectl when available (also updating the running kernel
// hostname and notifying systemd), falling back to sethostname(2) +
// /etc/hostname, and keeps the /etc/hosts 127.0.1.1 mapping in sync.
func (h *CommandHandler) handleSetHostname(commandID string, cmd *proto.SetHostnameCommand) error {
	name := strings.TrimSpace(cmd.GetHostname())
	h.logger.Info("set hostname command received", "command_id", commandID, "hostname", name)
	h.reportCommandStatus(commandID, "in_progress", 0, "Setting hostname")

	if errMsg := setHostnameRejection(name); errMsg != "" {
		h.reportCommandStatus(commandID, "failed", 0, errMsg)
		return refusal.Wrap(fmt.Errorf("%s", errMsg))
	}

	if _, err := exec.LookPath("hostnamectl"); err == nil {
		if out, err := exec.Command("hostnamectl", "set-hostname", name).CombinedOutput(); err != nil {
			errMsg := fmt.Sprintf("hostnamectl failed: %v: %s", err, strings.TrimSpace(string(out)))
			h.reportCommandStatus(commandID, "failed", 0, errMsg)
			return fmt.Errorf("%s", errMsg)
		}
	} else {
		if err := syscall.Sethostname([]byte(name)); err != nil {
			errMsg := fmt.Sprintf("sethostname failed: %v", err)
			h.reportCommandStatus(commandID, "failed", 0, errMsg)
			return fmt.Errorf("%s", errMsg)
		}
		if err := os.WriteFile("/etc/hostname", []byte(name+"\n"), 0o644); err != nil {
			h.logger.Warn("failed to persist /etc/hostname", "command_id", commandID, "error", err)
		}
	}

	h.syncEtcHostsHostname(name)

	h.reportCommandStatus(commandID, "success", 100, fmt.Sprintf("Hostname set to %s", name))

	// Re-report system info so the platform reflects the new hostname promptly.
	if h.hardwareInfoReporter != nil {
		if err := h.hardwareInfoReporter(); err != nil {
			h.logger.Warn("failed to re-report system info after hostname change", "command_id", commandID, "error", err)
		}
	}
	return nil
}

// syncEtcHostsHostname keeps the loopback 127.0.1.1 mapping in /etc/hosts
// pointing at the current hostname (best-effort; failures are non-fatal).
func (h *CommandHandler) syncEtcHostsHostname(name string) {
	const path = "/etc/hosts"
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	if err := os.WriteFile(path, []byte(etcHostsWithHostname(string(data), name)), 0o644); err != nil {
		h.logger.Warn("failed to update /etc/hosts", "error", err)
	}
}

// handlePatchFile idempotently inserts or replaces a marker-delimited managed
// block in a text file (designed for /boot/firmware/config.txt). The original
// file is backed up once as <path>.orchestrator.bak before the first
// modification, and the write is atomic (temp file + rename + sync) so a
// power cut cannot leave a half-written boot config.
func (h *CommandHandler) handlePatchFile(commandID string, cmd *proto.PatchFileCommand) error {
	path := cmd.Path
	if path == "" {
		path = "/boot/firmware/config.txt"
	}
	marker := cmd.Marker
	if marker == "" {
		marker = DefaultPatchMarker
	}

	h.logger.Info("patch file command received",
		"command_id", commandID,
		"path", path,
		"marker", marker)

	// Path policy, which this handler had never run. patch_file is queueable and
	// carries no version floor, so it is the most reachable file writer in the
	// agent, and until now cmd.Path was used verbatim — the backend only trims
	// the string. The boot config is the whole point of the command, so it stays
	// exempt exactly as it is for write_file.
	if !isPlatformConfigPath(path) {
		resolved, rerr := h.resolveForFileOp(path, h.adoptionFilePath)
		if rerr != nil {
			h.reportCommandStatus(commandID, "failed", 0, rerr.Error())
			return rerr
		}
		path = resolved
	} else {
		path = canonicalPlatformConfigPath(path)
	}

	h.reportCommandStatus(commandID, "in_progress", 0, fmt.Sprintf("Patching %s (block '%s')", path, marker))
	return h.patchManagedBlockAtPath(commandID, path, cmd.Content, marker)
}

// patchManagedBlockAtPath is the whole edit — read, splice the managed block,
// back up once, write atomically — against an absolute path.
//
// Split out of handlePatchFile so the OFFLINE variant runs exactly this and not
// a second implementation of it: the marker splicing, the one-time backup, the
// O_EXCL|O_NOFOLLOW temp file and the directory sync are each here because
// something went wrong once, and a copy would inherit none of that history.
func (h *CommandHandler) patchManagedBlockAtPath(commandID, path, content, marker string) error {
	fail := func(format string, args ...interface{}) error {
		errMsg := fmt.Sprintf(format, args...)
		h.logger.Error("patch file failed", "command_id", commandID, "path", path, "error", errMsg)
		h.reportCommandStatus(commandID, "failed", 0, errMsg)
		return errors.New(errMsg)
	}

	// Anchor ONCE and do the read, the backup and the atomic write through the
	// same directory descriptor. This function used to walk the
	// path string six times — stat, read, backup lstat, backup create, temp
	// create, rename — and an unprivileged owner of any directory on the way
	// could swap a component for a symlink between two of them. The boot config
	// is root-owned, but the offline variant and the generic patch_file reach
	// any path the policy allows.
	target, err := openAnchored(path)
	if err != nil {
		return fail("target file is not accessible: %v", err)
	}
	defer target.Close()
	info, err := target.Lstat()
	if err != nil {
		return fail("target file is not accessible: %v", err)
	}
	if !info.Mode().IsRegular() {
		return fail("%s is not a regular file", path)
	}
	// Bounded, for the reason read_file got a 0.4.0 floor: an unbounded
	// os.ReadFile here blocks the agent's single command goroutine forever on a
	// FIFO and OOMs it on /proc/kcore. config.txt is a few kilobytes; nothing
	// this command legitimately patches is large.
	//
	// Oversize and non-UTF-8 are REFUSALS. Taking an empty read as the file's
	// contents would write a managed block over the whole file, save an EMPTY
	// backup, and report success — silent destruction of any file this command
	// cannot fully read.
	original, err := target.ReadBounded(DefaultReadMaxBytes)
	if err != nil {
		if strings.Contains(err.Error(), "is larger than") {
			return fail("%s is larger than the %d byte limit this command can safely rewrite", path, DefaultReadMaxBytes)
		}
		return fail("failed to read target file: %v", err)
	}
	if !utf8.Valid(original) {
		return fail("%s is not valid UTF-8; refusing to rewrite it as text", path)
	}

	updated, err := patchManagedBlock(original, content, marker)
	if err != nil {
		return fail("%v", err)
	}
	if string(updated) == string(original) {
		h.reportCommandStatus(commandID, "success", 100, fmt.Sprintf("Block '%s' in %s already up to date", marker, path))
		return nil
	}

	// One-time backup of the untouched original, next to it and through the
	// anchor. WriteSibling is O_EXCL|O_NOFOLLOW: the name is predictable, so a
	// pre-planted symlink must fail the create rather than be written through.
	backupName := filepath.Base(path) + ".orchestrator.bak"
	backupExists, err := target.SiblingExists(backupName)
	if err != nil {
		return fail("failed to check backup %s: %v", path+".orchestrator.bak", err)
	}
	if !backupExists {
		if berr := target.WriteSibling(backupName, original, info.Mode().Perm()); berr != nil {
			return fail("failed to write backup %s: %v", path+".orchestrator.bak", berr)
		}
	}

	h.reportCommandStatus(commandID, "in_progress", 50, "Writing patched file")

	// AtomicWrite: a random O_EXCL|O_NOFOLLOW temp in the anchored directory,
	// fsync, rename over the target, then fsync the directory so the rename
	// survives a power cut (FAT boot partitions are exactly where that matters).
	if err := target.AtomicWrite(updated, info.Mode().Perm()); err != nil {
		return fail("failed to replace target file: %v", err)
	}

	h.reportCommandStatus(commandID, "success", 100, fmt.Sprintf("Patched %s: block '%s' applied (reboot to take effect)", path, marker))
	h.logger.Info("patch file command executed successfully", "command_id", commandID, "path", path, "marker", marker)
	return nil
}
