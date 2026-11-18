//go:build linux

package handlers

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"log/slog"
	"os"
)

// The source node's identity must survive a crash during a generalized capture.
//
// generalizeRoot tars the adoption file, machine-id, host keys and hostname,
// strips them from the installed root, and restores them from a deferred
// cleanup. The tar lived in /tmp — the netboot initramfs TMPFS — and the window
// is the whole capture, bounded by a four-hour upload timeout. A power cut or a
// crash in that window loses the tar, and with it the node's adoption file: the
// device no longer belongs to any account, and the platform cannot repair it
// remotely (a tombstone restore returns the row, not the device).
//
// So a copy also goes onto the TARGET DISK, in the reserved window between the
// end of the root partition and the disk's backup GPT. That area is outside the
// capture extent by construction — the capture is [0, shrunk root end) and the
// shrink only ever moves that end DOWN — so the identity never travels inside
// the image it was stripped out of.
//
// It is a raw device write rather than a file because there is no filesystem
// out there, and it has to survive the very crash that would take a filesystem's
// journal with it.

const (
	// identityStashMagic marks the reserved window. Nothing else writes here, so
	// a wrong magic means "no stash", never "a corrupt stash".
	identityStashMagic = "ORCHIDST"

	// identityStashReserve is how much room the stash may use, taken from the
	// end of the disk. The payload is a tar of a machine-id, a hostname, an
	// adoption file and a handful of SSH host keys — tens of kilobytes — so this
	// is two orders of magnitude of headroom.
	identityStashReserve = 4 << 20

	// identityStashGPTTail is the space left untouched at the very end of the
	// device for the backup GPT.
	identityStashGPTTail = 1 << 20

	// identityStashHeaderSize is magic + payload length + sha256 of the payload.
	identityStashHeaderSize = 8 + 8 + 32
)

// identityStashOffset returns where the stash lives on a device, and whether the
// device has room for it beyond rootEndBytes.
//
// A device whose root partition runs right up to the end has no reserved window,
// and the caller must then fall back to the tmpfs copy alone rather than writing
// into the captured extent. That is not a hypothetical on a disk that has never
// been shrunk.
func identityStashOffset(deviceSizeBytes, rootEndBytes int64) (int64, bool) {
	offset := deviceSizeBytes - identityStashGPTTail - identityStashReserve
	if offset <= rootEndBytes {
		return 0, false
	}
	return offset, true
}

// writeIdentityStash copies payload into the device's reserved window.
func writeIdentityStash(devicePath string, offset int64, payload []byte) error {
	if int64(len(payload))+identityStashHeaderSize > identityStashReserve {
		return fmt.Errorf("identity backup is %d bytes, which does not fit the %d-byte reserved window",
			len(payload), identityStashReserve)
	}
	sum := sha256.Sum256(payload)
	buf := make([]byte, 0, identityStashHeaderSize+len(payload))
	buf = append(buf, identityStashMagic...)
	var lenBuf [8]byte
	binary.BigEndian.PutUint64(lenBuf[:], uint64(len(payload)))
	buf = append(buf, lenBuf[:]...)
	buf = append(buf, sum[:]...)
	buf = append(buf, payload...)

	f, err := os.OpenFile(devicePath, os.O_WRONLY, 0)
	if err != nil {
		return fmt.Errorf("opening %s to stash the identity backup: %w", devicePath, err)
	}
	defer func() { _ = f.Close() }()
	if _, err := f.WriteAt(buf, offset); err != nil {
		return fmt.Errorf("writing the identity stash: %w", err)
	}
	return f.Sync()
}

// readIdentityStash returns the stashed payload, or ok=false when there is none.
//
// A checksum mismatch is reported as an ERROR rather than as absence: an
// interrupted write is the one case where the difference matters, and restoring
// a half-written identity would be worse than restoring nothing.
func readIdentityStash(devicePath string, offset int64) ([]byte, bool, error) {
	f, err := os.Open(devicePath)
	if err != nil {
		return nil, false, err
	}
	defer func() { _ = f.Close() }()

	header := make([]byte, identityStashHeaderSize)
	if _, err := f.ReadAt(header, offset); err != nil {
		return nil, false, nil // unreadable window: treat as no stash
	}
	if !bytes.Equal(header[:8], []byte(identityStashMagic)) {
		return nil, false, nil
	}
	size := int64(binary.BigEndian.Uint64(header[8:16]))
	if size <= 0 || size+identityStashHeaderSize > identityStashReserve {
		return nil, false, fmt.Errorf("identity stash declares an implausible size (%d bytes)", size)
	}
	payload := make([]byte, size)
	if _, err := f.ReadAt(payload, offset+identityStashHeaderSize); err != nil {
		return nil, false, fmt.Errorf("reading the identity stash: %w", err)
	}
	sum := sha256.Sum256(payload)
	if !bytes.Equal(sum[:], header[16:48]) {
		return nil, false, fmt.Errorf("identity stash checksum mismatch; refusing to restore a partial identity")
	}
	return payload, true, nil
}

// clearIdentityStash erases the magic so a later capture does not restore an
// identity that has already been put back.
func clearIdentityStash(devicePath string, offset int64, logger *slog.Logger) {
	f, err := os.OpenFile(devicePath, os.O_WRONLY, 0)
	if err != nil {
		logger.Warn("could not open the device to clear the identity stash", "device", devicePath, "error", err)
		return
	}
	defer func() { _ = f.Close() }()
	if _, err := f.WriteAt(make([]byte, identityStashHeaderSize), offset); err != nil {
		logger.Warn("could not clear the identity stash", "device", devicePath, "error", err)
		return
	}
	_ = f.Sync()
}

// stashIdentityOnDisk copies the identity tar into the device's reserved window.
//
// Best-effort by design: it is a SECOND copy, and failing the capture because
// the belt could not be fitted while the braces are on would trade a rare loss
// for a common refusal. Every failure says so at WARN, because the operator's
// exposure changes when it does not work.
func (h *CommandHandler) stashIdentityOnDisk(targetDevice string, rootEndBytes int64) {
	payload, err := os.ReadFile(identityBackupTar)
	if err != nil {
		h.logger.Warn("could not read the identity backup to stash it on disk", "error", err)
		return
	}
	size := diskSizeBytes(targetDevice)
	if size <= 0 {
		h.logger.Warn("could not determine the device size; the identity backup exists only in the initramfs",
			"device", targetDevice)
		return
	}
	offset, ok := identityStashOffset(size, rootEndBytes)
	if !ok {
		h.logger.Warn("no room past the root partition for an on-disk identity backup; it exists only in the initramfs, so a crash during this capture would de-adopt this node",
			"device", targetDevice, "device_bytes", size, "root_end_bytes", rootEndBytes)
		return
	}
	if err := writeIdentityStash(targetDevice, offset, payload); err != nil {
		h.logger.Warn("could not stash the identity backup on disk; it exists only in the initramfs",
			"device", targetDevice, "error", err)
		return
	}
	h.logger.Info("identity backup stashed on disk, outside the capture extent",
		"device", targetDevice, "offset", offset, "bytes", len(payload))
}

// recoverStashedIdentity restores an identity left behind by a capture that
// never finished, and is called at the START of a capture — before anything is
// stripped.
//
// The case it answers: a previous generalized capture crashed after stripping,
// the initramfs tar died with the machine, and the node came back netbooted with
// no adoption file. The operator's natural next move is to retry the capture,
// and that is the moment this can put the identity back.
//
// It is deliberately conservative: it acts only on an intact stash with the
// right magic and a matching checksum, and it clears the stash afterwards so a
// later capture cannot resurrect an identity that has already been restored.
func (h *CommandHandler) recoverStashedIdentity(targetDevice, rootPart string, rootEndBytes int64) {
	size := diskSizeBytes(targetDevice)
	if size <= 0 {
		return
	}
	offset, ok := identityStashOffset(size, rootEndBytes)
	if !ok {
		return
	}
	payload, found, err := readIdentityStash(targetDevice, offset)
	if err != nil {
		h.logger.Warn("an on-disk identity backup is present but unusable", "device", targetDevice, "error", err)
		return
	}
	if !found {
		return
	}
	h.logger.Warn("found an identity backup from an interrupted capture; restoring it before proceeding",
		"device", targetDevice, "bytes", len(payload))
	if err := os.WriteFile(identityBackupTar, payload, 0o600); err != nil {
		h.logger.Warn("could not materialise the stashed identity backup", "error", err)
		return
	}
	if err := h.restoreIdentity(rootPart); err != nil {
		h.logger.Warn("could not restore the stashed identity", "error", err)
		return
	}
	clearIdentityStash(targetDevice, offset, h.logger)
	_ = os.Remove(identityBackupTar)
	h.logger.Info("identity from an interrupted capture restored", "device", targetDevice)
}
