package handlers

import (
	"bufio"
	"bytes"
	"fmt"
	"hash"
	"io"
	"log/slog"
	"net/url"
	"os/exec"
	"path"
	"strings"
	"sync"

	"github.com/klauspost/compress/zstd"
	"github.com/ulikunitz/xz"
)

// countingHashReader wraps the raw download stream: it feeds every byte into
// the checksum hash and counts bytes, so the platform checksum (computed over
// the stored, possibly compressed file) can be verified and progress can be
// reported against Content-Length even when the payload is decompressed
// downstream.
type countingHashReader struct {
	reader io.Reader
	hash   hash.Hash
	count  int64
}

func (r *countingHashReader) Read(p []byte) (int, error) {
	n, err := r.reader.Read(p)
	if n > 0 {
		r.hash.Write(p[:n])
		r.count += int64(n)
	}
	return n, err
}

// BytesRead returns the number of raw (compressed) bytes consumed so far.
func (r *countingHashReader) BytesRead() int64 { return r.count }

// Compression formats of the downloaded image stream.
const (
	compressionNone = ""
	compressionXZ   = "xz"
	compressionZstd = "zstd"
)

// imageURLCompression detects the image compression from the URL path
// extension — the platform stores image files under their original extension,
// and signed CDN URLs only add query parameters.
func imageURLCompression(imageURL string) (string, error) {
	parsed, err := url.Parse(imageURL)
	if err != nil {
		return compressionNone, fmt.Errorf("failed to parse image URL: %w", err)
	}
	switch strings.ToLower(path.Ext(parsed.Path)) {
	case ".xz":
		return compressionXZ, nil
	case ".zst":
		return compressionZstd, nil
	default:
		return compressionNone, nil
	}
}

// imageStream yields raw image bytes ready to be written to a block device.
// cleanup must be called when the stream is abandoned (also safe after a
// complete read) so a spawned decompressor process never outlives the job.
// finish, when set, is the decoder's own completion (the xz process exit),
// asked for explicitly once the stream has been read to EOF.
type imageStream struct {
	io.Reader
	cleanup func()
	finish  func() error
}

func (s *imageStream) Close() {
	if s.cleanup != nil {
		s.cleanup()
	}
}

// Finish is called after the stream returned io.EOF and requires the decoder
// to have completed cleanly. The image loop reads to EOF, so an xz failure
// already surfaces through Read; this makes the exit status a judged step
// rather than something only the deferred kill-and-wait sees.
func (s *imageStream) Finish() error {
	if s.finish != nil {
		return s.finish()
	}
	return nil
}

// findSystemXZ returns the path of a real XZ Utils binary, or "" when only a
// stripped-down implementation (e.g. a busybox applet, which rejects -T) or
// nothing is available.
func findSystemXZ() string {
	binary, err := exec.LookPath("xz")
	if err != nil {
		return ""
	}
	out, err := exec.Command(binary, "--version").CombinedOutput()
	if err != nil || !strings.Contains(string(out), "XZ Utils") {
		return ""
	}
	return binary
}

// xzExecReader streams decompressed output of a system xz process and
// surfaces the process error instead of a silent short read.
type xzExecReader struct {
	cmd      *exec.Cmd
	stdout   io.ReadCloser
	stderr   *bytes.Buffer
	waitOnce sync.Once
	waitErr  error
}

func (x *xzExecReader) wait() error {
	x.waitOnce.Do(func() { x.waitErr = x.cmd.Wait() })
	return x.waitErr
}

func (x *xzExecReader) Read(p []byte) (int, error) {
	n, err := x.stdout.Read(p)
	if err == io.EOF {
		if waitErr := x.wait(); waitErr != nil {
			return n, fmt.Errorf("xz decompressor failed: %w (stderr: %s)", waitErr, strings.TrimSpace(x.stderr.String()))
		}
	}
	return n, err
}

// finish reports the process exit status. The caller must have drained
// stdout to EOF first, or xz blocks on a full pipe and this never returns.
func (x *xzExecReader) finish() error {
	if err := x.wait(); err != nil {
		return fmt.Errorf("xz decompressor failed: %w (stderr: %s)", err, strings.TrimSpace(x.stderr.String()))
	}
	return nil
}

func (x *xzExecReader) kill() {
	if x.cmd.Process != nil {
		_ = x.cmd.Process.Kill()
	}
	_ = x.wait()
}

// newImageStreamReader returns a stream of raw image bytes for the given
// compression format. zstd uses the built-in multi-core decoder; xz prefers
// the system xz binary (`xz -dc -T0`: multi-threaded C decoder, an order of
// magnitude faster than the pure-Go fallback on multi-block archives) and
// falls back to the built-in Go decompressor when no real XZ Utils binary is
// present.
func newImageStreamReader(compression string, r io.Reader, logger *slog.Logger) (*imageStream, error) {
	switch compression {
	case compressionNone:
		return &imageStream{Reader: r}, nil

	case compressionZstd:
		if logger != nil {
			logger.Info("decompressing with built-in zstd decoder")
		}
		// Bounded window and memory: the frame may declare
		// any window it likes and the default decoder honours it.
		decoder, err := zstd.NewReader(r, zstd.WithDecoderConcurrency(0), zstd.WithDecoderMaxWindow(zstdMaxWindow), zstd.WithDecoderMaxMemory(zstdMaxMemory))
		if err != nil {
			return nil, fmt.Errorf("failed to initialize zstd decompressor: %w", err)
		}
		return &imageStream{Reader: decoder, cleanup: decoder.Close}, nil

	case compressionXZ:
		binary := findSystemXZ()
		if logger != nil {
			if binary != "" {
				logger.Info("decompressing with system xz", "binary", binary)
			} else {
				logger.Info("system xz not found, using built-in single-threaded decompressor")
			}
		}
		return newXZStream(binary, r)

	default:
		return nil, fmt.Errorf("unsupported image compression %q", compression)
	}
}

// newXZStream builds an xz-decompressing stream: through the given XZ Utils
// binary when non-empty, with the pure-Go decoder otherwise.
func newXZStream(binary string, r io.Reader) (*imageStream, error) {
	if binary == "" {
		// The pure-Go reader behind the first-block dictionary tripwire and
		// a configured cap (see decoder_bounds.go for what
		// that does and does not bound).
		br := bufio.NewReaderSize(r, 1<<20)
		if err := checkXZFirstBlockDictionary(br, xzGoDictCap); err != nil {
			return nil, err
		}
		xzReader, err := xz.ReaderConfig{DictCap: xzGoDictCap}.NewReader(br)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize xz decompressor: %w", err)
		}
		return &imageStream{Reader: xzReader}, nil
	}

	// An explicit decode memory limit: xz refuses a stream whose dictionary
	// needs more than this up front, instead of the node finding out from
	// the OOM killer.
	cmd := exec.Command(binary, "-dc", "-T0", "--memlimit-decompress="+xzDecodeMemLimit)
	cmd.Stdin = r
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to pipe xz output: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start xz decompressor: %w", err)
	}
	reader := &xzExecReader{cmd: cmd, stdout: stdout, stderr: &stderr}
	return &imageStream{Reader: reader, cleanup: reader.kill, finish: reader.finish}, nil
}

// isTransientDownloadError reports whether an install download failure is
// worth retrying from scratch (network blip, platform restart mid-stream) as
// opposed to a persistent one (checksum mismatch, bad device).
func isTransientDownloadError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	for _, marker := range []string{
		"failed to download image",
		"failed to read chunk",
		"unexpected EOF",
		"connection reset",
		"xz decompressor failed",
	} {
		if strings.Contains(msg, marker) {
			return true
		}
	}
	return false
}
