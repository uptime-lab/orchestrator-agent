package handlers

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"io"
	"testing"

	"github.com/klauspost/compress/zstd"
	"github.com/ulikunitz/xz"
)

// Why these tests exist. extractTarInto returned when
// tar.Reader.Next reported the end marker, and a tar end marker sits BEFORE
// the compressed stream's trailer: the gzip CRC, the zstd frame checksum, the
// xz footer and the xz process exit were never reached, so an archive whose
// completion was corrupt or truncated unpacked and reported success. Each
// case below is a valid tar whose compressed container fails only at its
// completion; the tar loop must still see a clean end (the premise) and the
// decoder's Finish must refuse.

func smallTar(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	const content = "payload\n"
	if err := tw.WriteHeader(&tar.Header{Name: "file.txt", Mode: 0o644, Size: int64(len(content)), Typeflag: tar.TypeReg}); err != nil {
		t.Fatal(err)
	}
	_, _ = tw.Write([]byte(content))
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// readTarToEnd is the loop extractTarInto runs: Next until io.EOF, every
// entry consumed. It reports whether the archive's end was reached cleanly.
func readTarToEnd(t *testing.T, r io.Reader) {
	t.Helper()
	tr := tar.NewReader(r)
	for {
		_, err := tr.Next()
		if err == io.EOF {
			return
		}
		if err != nil {
			t.Fatalf("premise broken: the tar loop itself failed (%v); the case does not test the decoder's completion", err)
		}
		if _, err := io.Copy(io.Discard, tr); err != nil {
			t.Fatalf("premise broken: entry read failed: %v", err)
		}
	}
}

func gzipOf(t *testing.T, raw []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	_, _ = gz.Write(raw)
	_ = gz.Close()
	return buf.Bytes()
}

func zstdOf(t *testing.T, raw []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw, err := zstd.NewWriter(&buf, zstd.WithEncoderCRC(true))
	if err != nil {
		t.Fatal(err)
	}
	_, _ = zw.Write(raw)
	_ = zw.Close()
	return buf.Bytes()
}

func xzOf(t *testing.T, raw []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	xw, err := xz.NewWriter(&buf)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = xw.Write(raw)
	_ = xw.Close()
	return buf.Bytes()
}

// corruptTail flips the last byte: the gzip ISIZE, the zstd frame checksum,
// the xz footer magic.
func corruptTail(b []byte) []byte {
	out := append([]byte(nil), b...)
	out[len(out)-1] ^= 0xFF
	return out
}

func truncateTail(b []byte, n int) []byte {
	return append([]byte(nil), b[:len(b)-n]...)
}

func finishArchive(t *testing.T, name string, compressed []byte) error {
	t.Helper()
	dec, err := newArchiveDecoder(name, bytes.NewReader(compressed))
	if err != nil {
		t.Fatalf("%s: decoder refused the stream up front: %v", name, err)
	}
	defer dec.Release()
	readTarToEnd(t, dec)
	return dec.Finish()
}

func TestArchiveDecoderFinishAcceptsACleanArchive(t *testing.T) {
	raw := smallTar(t)
	for name, compressed := range map[string][]byte{
		"a.tar.gz":  gzipOf(t, raw),
		"a.tar.zst": zstdOf(t, raw),
		"a.tar.xz":  xzOf(t, raw),
		"a.tar":     raw,
	} {
		if err := finishArchive(t, name, compressed); err != nil {
			t.Errorf("%s: a clean archive was refused at completion: %v", name, err)
		}
	}
}

func TestArchiveDecoderFinishSurfacesGzipTrailerFailures(t *testing.T) {
	gz := gzipOf(t, smallTar(t))
	if err := finishArchive(t, "a.tar.gz", corruptTail(gz)); err == nil {
		t.Fatal("a gzip archive with a corrupt trailer completed as success")
	}
	if err := finishArchive(t, "a.tar.gz", truncateTail(gz, 8)); err == nil {
		t.Fatal("a gzip archive missing its trailer completed as success")
	}
}

func TestArchiveDecoderFinishSurfacesZstdTrailerFailures(t *testing.T) {
	zs := zstdOf(t, smallTar(t))
	// A corrupt or missing checksum on the ONE frame is refused by the zstd
	// decoder before it delivers the last block (measured: the tar loop
	// itself fails with "CRC check failed" / "unexpected EOF"), so those two
	// shapes never reach a clean end marker and are not the gap. What does
	// reach it is anything after a complete frame.
	for name, shape := range map[string][]byte{
		"garbage after the frame": append(append([]byte(nil), zs...), []byte("not a zstd frame")...),
		"a second, corrupt frame": append(append([]byte(nil), zs...), corruptTail(zstdOf(t, []byte("second frame")))...),
	} {
		t.Run(name, func(t *testing.T) {
			if err := finishArchive(t, "a.tar.zst", shape); err == nil {
				t.Fatalf("a zstd archive with %s completed as success", name)
			}
		})
	}
}

func TestArchiveDecoderFinishSurfacesXZFooterFailures(t *testing.T) {
	xzBytes := xzOf(t, smallTar(t))
	// The pure-Go path always (forced, so a host with the binary covers it
	// too), the XZ Utils path when the binary exists.
	lookups := map[string]func() string{"pure-go": func() string { return "" }}
	if b := findSystemXZ(); b != "" {
		lookups["xz-utils"] = func() string { return b }
	}
	for name, lookup := range lookups {
		t.Run(name, func(t *testing.T) {
			prev := xzBinaryLookup
			xzBinaryLookup = lookup
			t.Cleanup(func() { xzBinaryLookup = prev })
			if err := finishArchive(t, "a.tar.xz", xzOf(t, smallTar(t))); err != nil {
				t.Fatalf("control: a clean xz archive was refused: %v", err)
			}
			if err := finishArchive(t, "a.tar.xz", corruptTail(xzBytes)); err == nil {
				t.Fatal("an xz archive with a corrupt footer completed as success")
			}
			if err := finishArchive(t, "a.tar.xz", truncateTail(xzBytes, 12)); err == nil {
				t.Fatal("an xz archive missing its footer completed as success")
			}
		})
	}
}

// The drain that reaches the trailer is bounded: an archive whose DECODED
// stream keeps going after the end marker is refused rather than read to the
// end of a decompression bomb.
func TestArchiveDecoderFinishBoundsTrailingData(t *testing.T) {
	raw := smallTar(t)
	padded := append(append([]byte(nil), raw...), make([]byte, maxTarTrailingBytes+4096)...)
	err := finishArchive(t, "a.tar.gz", gzipOf(t, padded))
	if err == nil {
		t.Fatal("an archive with megabytes after its end marker completed as success")
	}
	// Ordinary tar padding (a blocking factor's worth of zeros) is fine.
	modest := append(append([]byte(nil), raw...), make([]byte, 20*512)...)
	if err := finishArchive(t, "a.tar.gz", gzipOf(t, modest)); err != nil {
		t.Fatalf("ordinary block padding after the end marker was refused: %v", err)
	}
}
