package handlers

// Image download helpers shared by the install path. Deliberately NOT in
// command_handler_linux.go: that file is build-tagged linux, so anything in it
// is invisible to `go test` on a macOS dev machine — and these are the parts
// most worth testing without hardware.

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"time"

	"agent/pkg/domain/redact"
)

// imageHeadSize is how much of the image start is held in RAM until the digest
// is known, so a failed install cannot leave a bootable-looking disk. It covers
// the protective MBR, the primary GPT header and its partition entries (17 KiB
// in total) plus the first partition's volume boot record — RPi images place
// partition 1 at 1 or 4 MiB — so an aborted write denies the boot chain at two
// independent layers. It is also exactly one read chunk, which keeps the
// hold-back to "do not write the first buffer yet".
//
// This is NOT a security boundary: an image with an unusual layout could put a
// filesystem superblock below it. What makes an abort safe is the deliberate
// invalidation in invalidateTargetDevice, not the size chosen here.
const imageHeadSize = 4 * 1024 * 1024

// downloadStallTimeout aborts a download that stops making progress. There is
// deliberately NO overall deadline: a multi-GB image onto a CM4 over a busy
// LAN legitimately takes a long time, and an overall timeout would turn "slow"
// into "failed" — then somebody raises it until it means nothing. A stall is
// unambiguous, and it is the failure the bare http.Get could not detect: a
// black-holed connection left the command in_progress forever with the block
// device open.
const downloadStallTimeout = 90 * time.Second

// newOneShotTransport is the transport behind every client the agent builds
// for ONE operation and then drops — an image download, a package or
// signature fetch, the EEPROM manifest loop. Keep-alive is OFF on purpose:
// a transport that is discarded right after its response
// keeps the connection that response came back on parked in an idle pool
// nobody will ever drain, and neither the request context nor the client's
// timeout retires an idle keep-alive. With a fresh transport per call the
// pool is a sum, not a steady state — one socket and one goroutine per
// completed operation until the peer hangs up or the agent restarts. Closing
// the connection with the body costs a handshake per fetch, which these
// operations can afford; a leaked descriptor on a device that is not
// rebooted for weeks cannot be afforded. The deadlines on every phase that
// can hang before the body streams are unchanged.
func newOneShotTransport() *http.Transport {
	return &http.Transport{
		DialContext:           (&net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		TLSHandshakeTimeout:   15 * time.Second,
		ResponseHeaderTimeout: 60 * time.Second,
		ExpectContinueTimeout: 5 * time.Second,
		DisableKeepAlives:     true,
		// Belt and braces for a connection that reached the pool anyway.
		IdleConnTimeout: 30 * time.Second,
		MaxIdleConns:    1,
	}
}

// imageDownloadClient dials with real deadlines on every phase that can hang
// before the body starts streaming. The body itself is bounded by the stall
// watchdog rather than by a timeout, for the reason above.
func imageDownloadClient() *http.Client {
	return &http.Client{Transport: newOneShotTransport()}
}

// redactURL strips userinfo, query and fragment for logging. The image URL
// carries an `exp`/`sig` capability that is valid for an hour and grants the
// image to anyone holding it; a download_file URL can carry user:password@ as
// well as a query token; journald keeps either long past that, and the node
// web terminal can read it back. One definition, shared with the gRPC client's
// logging boundary: this copy kept userinfo while the
// text-redaction helper beside it dropped it.
func redactURL(raw string) string {
	return redact.URL(raw)
}

// disarmTargetBeforeWrite makes the target unbootable, durably, BEFORE the
// first byte of a new image lands on it: the head region (the MBR or
// protective MBR, the primary GPT and the first partition's boot record) and
// the device-end backup GPT are zeroed and the device is synced.
//
// The deferred invalidateTargetDevice covers every failure the agent lives to
// see. A power cut or a hard reset is not one of them: it leaves the previous
// install's partition table pointing into a half-written image, the boot ROM
// hands control to it, and the board hangs in initramfs instead of falling
// through BOOT_ORDER to the next device. With the head already gone, a reset
// at any point of the stream leaves a disk the ROM skips. The image's own head
// is still written last, after the digest matches, so the disk becomes
// bootable exactly when it holds a verified image.
//
// Unlike the post-failure invalidation this one is fatal: an install that
// cannot write zeros will not write an image either, and must not start.
func disarmTargetBeforeWrite(deviceFile *os.File) error {
	const tailZone = 1 << 20
	size, err := deviceFile.Seek(0, io.SeekEnd)
	if err != nil {
		return fmt.Errorf("cannot determine the target size: %w", err)
	}
	head := int64(imageHeadSize)
	if size > 0 && size < head {
		head = size
	}
	if _, err := deviceFile.WriteAt(make([]byte, head), 0); err != nil {
		return fmt.Errorf("cannot clear the target's partition table: %w", err)
	}
	if size > int64(imageHeadSize)+tailZone {
		if _, err := deviceFile.WriteAt(make([]byte, tailZone), size-tailZone); err != nil {
			return fmt.Errorf("cannot clear the target's backup partition table: %w", err)
		}
	}
	if err := deviceFile.Sync(); err != nil {
		return fmt.Errorf("cannot sync the cleared partition table: %w", err)
	}
	return nil
}

// invalidateTargetDevice makes the target deliberately unbootable after a
// failed install, so the ROM falls through BOOT_ORDER to HTTP and the platform
// gets another chance at the node on its next power cycle. The alternative —
// what happened before — is a disk with a valid partition table over a
// truncated filesystem, which looks bootable, hangs in initramfs, and costs a
// site visit.
//
// Best-effort throughout: every failure here is logged, never returned. The
// caller's error is the actionable one and must not be masked.
// invalidateTargetDeviceByPath is invalidateTargetDevice for a caller that no
// longer holds the device open — the post-install steps, which run after the
// write path has closed it.
//
// writtenBytes is unknown there, so the mid-device backup GPT of the image just
// streamed is not zeroed; the head and the device-end backup GPT are, and
// wipefs clears the rest. That is enough to make the disk refuse to boot, which
// is the whole requirement.
func (h *CommandHandler) invalidateTargetDeviceByPath(targetDevice string) {
	deviceFile, err := os.OpenFile(targetDevice, os.O_WRONLY, 0)
	if err != nil {
		h.logger.Error("could not open the target device to invalidate it; the disk may still boot",
			"device", targetDevice, "error", err)
		return
	}
	defer func() { _ = deviceFile.Close() }()
	h.invalidateTargetDevice(deviceFile, targetDevice, 0)
}

func (h *CommandHandler) invalidateTargetDevice(deviceFile *os.File, targetDevice string, writtenBytes int64) {
	const tailZone = 1 << 20 // 1 MiB: comfortably covers a backup GPT
	zeros := make([]byte, imageHeadSize)

	// 1. The head region. Nothing of THIS image was written there, but a
	//    previous install's table almost certainly was.
	if _, err := deviceFile.WriteAt(zeros, 0); err != nil {
		h.logger.Warn("failed to zero the image head during invalidation", "error", err)
	}

	// 2. The backup GPT belonging to the image just streamed. On a restore onto
	//    a larger disk this sits MID-device, not at the end, and tools happily
	//    rebuild a primary table from it.
	if writtenBytes > tailZone {
		if _, err := deviceFile.WriteAt(zeros[:tailZone], writtenBytes-tailZone); err != nil {
			h.logger.Warn("failed to zero the image backup GPT", "error", err)
		}
	}

	// 3. The backup GPT at the end of the DEVICE, which may be left over from
	//    whatever was installed before.
	if size, err := deviceFile.Seek(0, io.SeekEnd); err == nil && size > tailZone {
		if _, err := deviceFile.WriteAt(zeros[:tailZone], size-tailZone); err != nil {
			h.logger.Warn("failed to zero the device backup GPT", "error", err)
		}
	} else if err != nil {
		h.logger.Warn("could not determine device size during invalidation", "error", err)
	}

	if err := deviceFile.Sync(); err != nil {
		h.logger.Warn("failed to sync during invalidation", "error", err)
	}
	// Belt and braces: wipefs also clears signatures the zeroing above missed.
	if out, err := exec.Command("wipefs", "-a", targetDevice).CombinedOutput(); err != nil {
		h.logger.Warn("wipefs failed during invalidation", "error", err, "output", string(out))
	}
	h.logger.Warn("target device deliberately invalidated after a failed install",
		"device", targetDevice, "written_bytes", writtenBytes)
}

// prepareOnFirstRead runs prepare exactly once, when the image stream first
// delivers bytes and before any of them is handed on. Clearing the target —
// wipefs, the zeroed partition table — is what makes the previous system
// unbootable, so it waits until the download has actually started: a request
// refused outright, a missing image or a stream whose compressed header does
// not decode leaves the previous system on the disk as it was.
type prepareOnFirstRead struct {
	r        io.Reader
	prepare  func() error
	prepared bool
}

func newPrepareOnFirstRead(r io.Reader, prepare func() error) *prepareOnFirstRead {
	return &prepareOnFirstRead{r: r, prepare: prepare}
}

func (p *prepareOnFirstRead) Read(b []byte) (int, error) {
	n, err := p.r.Read(b)
	if n > 0 && !p.prepared {
		p.prepared = true
		if perr := p.prepare(); perr != nil {
			return 0, perr
		}
	}
	return n, err
}

// Prepared reports whether the target has been touched.
func (p *prepareOnFirstRead) Prepared() bool { return p.prepared }
