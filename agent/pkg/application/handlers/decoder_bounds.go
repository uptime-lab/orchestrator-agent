package handlers

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"net/url"
	"os/exec"
	"strings"

	"github.com/klauspost/compress/zstd"
	"github.com/ulikunitz/xz"
)

// Device-side decoding bounds. The backend's compression
// budget covers the backend; nothing bounded what a node allocated to decode
// an archive or an image, and the pure-Go xz reader RAISES its configured
// dictionary cap to whatever the stream declares (ulikunitz/xz v0.5.16,
// lzmafilter.go), so a header alone could ask a 1 GiB CM4 for a 3 GiB
// dictionary before a single byte was rejected.
//
// Two answers, in order of strength: the system xz binary under an explicit
// --memlimit-decompress, which refuses such a stream up front; and, where no
// binary exists (the recovery initramfs), the pure-Go reader behind a check
// of the FIRST block header's declared dictionary. That check is a tripwire,
// not a ceiling: a later block may declare more, and the library will grow
// for it. It is stated as such here rather than dressed up as a bound.
const (
	// xzDecodeMemLimit is the xz-utils --memlimit-decompress value: a share
	// of physical RAM, so a Pi with 1 GiB and one with 8 GiB each keep room
	// for the OS while multi-block images still decode with threads.
	xzDecodeMemLimit = "40%"
	// zstdMaxWindow bounds the zstd decoder's window (klauspost's default
	// accepts up to 512 MiB; the format allows far more); 128 MiB covers
	// every image the platform produces (zstd -15 uses 8 MiB) with margin
	// for long-mode archives.
	zstdMaxWindow = 128 << 20
	// zstdMaxMemory bounds the decoder's total allocations.
	zstdMaxMemory = 256 << 20
	// xzGoDictCap is the pure-Go reader's dictionary cap AND the first-block
	// tripwire: xz -T0 at the platform's -6 declares 8 MiB, -9 declares 64.
	xzGoDictCap = 64 << 20
	// maxTarTrailingBytes bounds what may follow the tar end marker in the
	// DECODED stream while the decoder is run to completion: tar padding is a
	// blocking factor's worth of zero blocks (10 KiB by default, 1 MiB at the
	// most exotic), so anything past this is not padding.
	maxTarTrailingBytes = 4 << 20
)

// xzBinaryLookup finds the XZ Utils binary for the archive path; a variable
// so a test can force the pure-Go fallback on a host that has the binary.
var xzBinaryLookup = findSystemXZ

// archiveDecoder is what extractTarInto reads the tar from: the decoded
// stream, the step that proves the decoder finished cleanly once tar has seen
// its end marker, and the release of whatever the decoder started.
type archiveDecoder struct {
	io.Reader
	// finish is the decoder's own completion (the xz process exit); nil for a
	// decoder whose completion surfaces through Read alone.
	finish  func() error
	release func()
}

// newArchiveDecoder picks the decompressor from the URL's PATH extension, not
// the whole URL — a signed URL ends in "?sig=…", which no HasSuffix would
// match — and returns the raw reader for anything it does not recognise.
func newArchiveDecoder(sourceURL string, r io.Reader) (*archiveDecoder, error) {
	ext := ""
	if u, err := url.Parse(sourceURL); err == nil {
		ext = strings.ToLower(u.Path)
	} else {
		ext = strings.ToLower(sourceURL)
	}
	switch {
	case strings.HasSuffix(ext, ".tar.gz") || strings.HasSuffix(ext, ".tgz"):
		gz, err := gzip.NewReader(r)
		if err != nil {
			return nil, err
		}
		return &archiveDecoder{Reader: gz, release: func() { _ = gz.Close() }}, nil
	case strings.HasSuffix(ext, ".tar.xz"):
		xr, finish, closeXZ, err := newBoundedXZReader(r)
		if err != nil {
			return nil, err
		}
		return &archiveDecoder{Reader: xr, finish: finish, release: closeXZ}, nil
	case strings.HasSuffix(ext, ".tar.zst"):
		// Bounded window and memory: a stream may declare
		// any window it likes, and the default decoder honours it.
		zr, err := zstd.NewReader(r, zstd.WithDecoderMaxWindow(zstdMaxWindow), zstd.WithDecoderMaxMemory(zstdMaxMemory), zstd.WithDecoderConcurrency(1))
		if err != nil {
			return nil, err
		}
		return &archiveDecoder{Reader: zr, release: zr.Close}, nil
	}
	return &archiveDecoder{Reader: r}, nil
}

// Release frees whatever the decoder started; safe after Finish and after an
// error mid-stream.
func (d *archiveDecoder) Release() {
	if d.release != nil {
		d.release()
	}
}

// Finish is called once tar has reported its end marker, and is what makes
// "the archive extracted" also mean "the archive was complete".
// The end marker sits BEFORE the container's completion —
// the gzip CRC/ISIZE, the zstd frame checksum and any frame after it, the xz
// index and footer, the xz process's exit — and archive/tar never reads past
// it, so a stream that failed only at its completion used to unpack and
// report success. The remainder is drained to EOF under a bound: legitimate
// trailing data is tar block padding, so more than maxTarTrailingBytes is
// refused rather than read to the end of a decompression bomb, and the
// existing decoder memory bounds hold throughout. A decoder with a completion
// of its own (the xz process) is then asked for it explicitly, so the exit
// status is judged here and not only by the deferred kill-and-wait.
func (d *archiveDecoder) Finish() error {
	n, err := io.CopyN(io.Discard, d.Reader, maxTarTrailingBytes+1)
	switch {
	case err == nil:
		return fmt.Errorf("archive continues more than %d bytes past its end marker; refusing it as incomplete or hostile", int64(maxTarTrailingBytes))
	case err != io.EOF:
		return fmt.Errorf("archive failed to complete after its end marker (%d trailing bytes read): %w", n, err)
	}
	if d.finish != nil {
		if err := d.finish(); err != nil {
			return fmt.Errorf("archive decoder did not complete cleanly: %w", err)
		}
	}
	return nil
}

// newBoundedXZReader decodes an .xz stream under the bounds above: the system
// binary with a memory limit when it passes xzBinaryLookup, else the pure-Go
// reader after the first-block dictionary check. The second return is the
// decoder's completion step (the process exit status for the binary; nil for
// the pure-Go reader, whose footer check surfaces through Read); the third
// releases whatever was started and is safe to call after an error
// mid-stream.
func newBoundedXZReader(r io.Reader) (io.Reader, func() error, func(), error) {
	if binary := xzBinaryLookup(); binary != "" {
		cmd := exec.Command(binary, "-dc", "-T0", "--memlimit-decompress="+xzDecodeMemLimit)
		cmd.Stdin = r
		stderr := &bytes.Buffer{}
		cmd.Stderr = stderr
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			return nil, nil, func() {}, fmt.Errorf("failed to pipe xz output: %w", err)
		}
		if err := cmd.Start(); err != nil {
			return nil, nil, func() {}, fmt.Errorf("failed to start xz: %w", err)
		}
		// The SAME reader the image path uses: on EOF it consults the
		// process exit and surfaces stderr. A bare stdout pipe turned an xz
		// refusal (the memory limit, a corrupt stream) into a clean EOF that
		// tar read as an empty or truncated archive and the command reported
		// as SUCCESS.
		xr := &xzExecReader{cmd: cmd, stdout: stdout, stderr: stderr}
		release := func() {
			_ = stdout.Close()
			xr.kill()
		}
		return xr, xr.finish, release, nil
	}
	br := bufio.NewReaderSize(r, 1<<20)
	if err := checkXZFirstBlockDictionary(br, xzGoDictCap); err != nil {
		return nil, nil, func() {}, err
	}
	xr, err := xz.ReaderConfig{DictCap: xzGoDictCap}.NewReader(br)
	if err != nil {
		return nil, nil, func() {}, err
	}
	return xr, nil, func() {}, nil
}

// checkXZFirstBlockDictionary peeks at the stream and block headers and
// refuses a first block whose LZMA2 filter declares a dictionary above cap.
// A stream this function cannot parse is left to the reader, which will
// reject it in its own words; only a parsed, over-cap declaration refuses.
func checkXZFirstBlockDictionary(br *bufio.Reader, cap int64) error {
	head, err := br.Peek(12 + 1)
	if err != nil {
		return nil
	}
	if !bytes.Equal(head[:6], []byte{0xFD, '7', 'z', 'X', 'Z', 0x00}) {
		return nil
	}
	if head[12] == 0 {
		return nil // index indicator: an empty stream
	}
	headerSize := (int(head[12]) + 1) * 4
	hdr, err := br.Peek(12 + headerSize)
	if err != nil {
		return nil
	}
	hdr = hdr[12:]
	flags := hdr[1]
	filters := int(flags&0x03) + 1
	pos := 2
	readVarint := func() (uint64, bool) {
		var v uint64
		for shift := 0; pos < len(hdr) && shift < 63; shift += 7 {
			b := hdr[pos]
			pos++
			v |= uint64(b&0x7F) << shift
			if b&0x80 == 0 {
				return v, true
			}
		}
		return 0, false
	}
	if flags&0x40 != 0 {
		if _, ok := readVarint(); !ok {
			return nil
		}
	}
	if flags&0x80 != 0 {
		if _, ok := readVarint(); !ok {
			return nil
		}
	}
	for i := 0; i < filters; i++ {
		id, ok := readVarint()
		if !ok {
			return nil
		}
		size, ok := readVarint()
		// Compared in uint64 space: a crafted 63-bit size overflowed the
		// int addition negative, passed the old bounds check and panicked
		// the slice below.
		if !ok || size > uint64(len(hdr)-pos) {
			return nil
		}
		props := hdr[pos : pos+int(size)]
		pos += int(size)
		if id != 0x21 || len(props) != 1 {
			continue
		}
		bits := int64(props[0] & 0x3F)
		if bits > 40 {
			return nil
		}
		var dict int64
		if bits == 40 {
			dict = 0xFFFFFFFF
		} else {
			dict = (2 | (bits & 1)) << (bits/2 + 11)
		}
		if dict > cap {
			return fmt.Errorf("xz stream declares a %d MiB dictionary; this node decodes at most %d MiB", dict>>20, cap>>20)
		}
	}
	return nil
}
