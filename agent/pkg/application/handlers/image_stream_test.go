package handlers

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"testing"

	zstdlib "github.com/klauspost/compress/zstd"
	"github.com/ulikunitz/xz"
)

func TestImageURLCompression(t *testing.T) {
	tests := []struct {
		name string
		url  string
		want string
	}{
		{
			name: "raw img",
			url:  "http://platform/cdn/acc/img-id.img",
			want: compressionNone,
		},
		{
			name: "raw iso with signature",
			url:  "http://platform/cdn/acc/img-id.iso?exp=123&sig=abc",
			want: compressionNone,
		},
		{
			name: "xz with signed query params",
			url:  "https://platform/cdn/acc/img-id.xz?exp=123&sig=abc.def",
			want: compressionXZ,
		},
		{
			name: "uppercase extension",
			url:  "http://platform/cdn/acc/IMG-ID.XZ",
			want: compressionXZ,
		},
		{
			name: "zstd with signed query params",
			url:  "https://platform/cdn/acc/img-id.zst?exp=123&sig=abc.def",
			want: compressionZstd,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := imageURLCompression(tt.url)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("imageURLCompression(%q) = %q, want %q", tt.url, got, tt.want)
			}
		})
	}
}

func TestImageStreamReaderXZRoundtrip(t *testing.T) {
	// Multi-megabyte payload so the stream crosses internal buffer boundaries.
	raw := make([]byte, 5*1024*1024)
	if _, err := rand.Read(raw); err != nil {
		t.Fatalf("failed to generate payload: %v", err)
	}

	var compressedBuf bytes.Buffer
	xzWriter, err := xz.NewWriter(&compressedBuf)
	if err != nil {
		t.Fatalf("failed to create xz writer: %v", err)
	}
	if _, err := xzWriter.Write(raw); err != nil {
		t.Fatalf("failed to compress payload: %v", err)
	}
	if err := xzWriter.Close(); err != nil {
		t.Fatalf("failed to finish compression: %v", err)
	}
	compressed := compressedBuf.Bytes()

	hash := sha256.New()
	source := &countingHashReader{reader: bytes.NewReader(compressed), hash: hash}
	reader, err := newImageStreamReader(compressionXZ, source, nil)
	if err != nil {
		t.Fatalf("failed to create stream reader: %v", err)
	}
	defer reader.Close()

	decompressed, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("failed to read stream: %v", err)
	}

	if !bytes.Equal(decompressed, raw) {
		t.Error("decompressed payload does not match the original")
	}
	if source.BytesRead() != int64(len(compressed)) {
		t.Errorf("BytesRead = %d, want %d (compressed size)", source.BytesRead(), len(compressed))
	}
	wantHash := sha256.Sum256(compressed)
	if !bytes.Equal(hash.Sum(nil), wantHash[:]) {
		t.Error("hash must cover the compressed stream (platform checksum semantics)")
	}
}

func TestZstdStreamRoundtripAndTruncation(t *testing.T) {
	raw := make([]byte, 5*1024*1024)
	if _, err := rand.Read(raw); err != nil {
		t.Fatalf("failed to generate payload: %v", err)
	}

	var compressedBuf bytes.Buffer
	encoder, err := zstdlib.NewWriter(&compressedBuf)
	if err != nil {
		t.Fatalf("failed to create zstd writer: %v", err)
	}
	if _, err := encoder.Write(raw); err != nil {
		t.Fatalf("failed to compress payload: %v", err)
	}
	if err := encoder.Close(); err != nil {
		t.Fatalf("failed to finish compression: %v", err)
	}
	compressed := compressedBuf.Bytes()

	hash := sha256.New()
	source := &countingHashReader{reader: bytes.NewReader(compressed), hash: hash}
	stream, err := newImageStreamReader(compressionZstd, source, nil)
	if err != nil {
		t.Fatalf("failed to create zstd stream: %v", err)
	}
	out, err := io.ReadAll(stream)
	stream.Close()
	if err != nil {
		t.Fatalf("failed to read zstd stream: %v", err)
	}
	if !bytes.Equal(out, raw) {
		t.Error("zstd decompressed payload does not match the original")
	}
	if source.BytesRead() != int64(len(compressed)) {
		t.Errorf("BytesRead = %d, want %d (compressed size)", source.BytesRead(), len(compressed))
	}
	wantHash := sha256.Sum256(compressed)
	if !bytes.Equal(hash.Sum(nil), wantHash[:]) {
		t.Error("hash must cover the compressed stream (platform checksum semantics)")
	}

	// A truncated stream must fail with a retryable error, not silently end.
	truncStream, err := newImageStreamReader(compressionZstd, bytes.NewReader(compressed[:len(compressed)/2]), nil)
	if err != nil {
		t.Fatalf("failed to create truncated zstd stream: %v", err)
	}
	_, err = io.ReadAll(truncStream)
	truncStream.Close()
	if err == nil {
		t.Fatal("truncated zstd stream must produce an error")
	}
	if !isTransientDownloadError(fmt.Errorf("failed to read chunk: %w", err)) {
		t.Errorf("zstd truncation error must be retryable, got: %v", err)
	}
}

func TestXZStreamSystemBinaryRoundtrip(t *testing.T) {
	binary := findSystemXZ()
	if binary == "" {
		t.Skip("no XZ Utils binary on this host")
	}

	raw := make([]byte, 2*1024*1024)
	if _, err := rand.Read(raw); err != nil {
		t.Fatalf("failed to generate payload: %v", err)
	}
	var compressedBuf bytes.Buffer
	xzWriter, err := xz.NewWriter(&compressedBuf)
	if err != nil {
		t.Fatalf("failed to create xz writer: %v", err)
	}
	if _, err := xzWriter.Write(raw); err != nil {
		t.Fatalf("failed to compress payload: %v", err)
	}
	if err := xzWriter.Close(); err != nil {
		t.Fatalf("failed to finish compression: %v", err)
	}

	stream, err := newXZStream(binary, bytes.NewReader(compressedBuf.Bytes()))
	if err != nil {
		t.Fatalf("failed to create exec stream: %v", err)
	}
	defer stream.Close()

	out, err := io.ReadAll(stream)
	if err != nil {
		t.Fatalf("failed to read exec stream: %v", err)
	}
	if !bytes.Equal(out, raw) {
		t.Error("system-xz decompressed payload does not match the original")
	}
}

func TestXZStreamTruncatedInputSurfacesError(t *testing.T) {
	raw := make([]byte, 1024*1024)
	if _, err := rand.Read(raw); err != nil {
		t.Fatalf("failed to generate payload: %v", err)
	}
	var compressedBuf bytes.Buffer
	xzWriter, err := xz.NewWriter(&compressedBuf)
	if err != nil {
		t.Fatalf("failed to create xz writer: %v", err)
	}
	if _, err := xzWriter.Write(raw); err != nil {
		t.Fatalf("failed to compress payload: %v", err)
	}
	if err := xzWriter.Close(); err != nil {
		t.Fatalf("failed to finish compression: %v", err)
	}
	truncated := compressedBuf.Bytes()[:compressedBuf.Len()/2]

	// Cover the pure-Go path always and the exec path when available.
	binaries := []string{""}
	if b := findSystemXZ(); b != "" {
		binaries = append(binaries, b)
	}
	for _, binary := range binaries {
		stream, err := newXZStream(binary, bytes.NewReader(truncated))
		if err != nil {
			t.Fatalf("failed to create stream (binary=%q): %v", binary, err)
		}
		_, err = io.ReadAll(stream)
		stream.Close()
		if err == nil {
			t.Errorf("truncated stream must produce an error (binary=%q)", binary)
		} else if !isTransientDownloadError(fmt.Errorf("failed to read chunk: %w", err)) {
			t.Errorf("truncation error must be retryable, got: %v", err)
		}
	}
}

func TestImageStreamReaderPassthrough(t *testing.T) {
	raw := []byte("raw image bytes")
	hash := sha256.New()
	source := &countingHashReader{reader: bytes.NewReader(raw), hash: hash}
	reader, err := newImageStreamReader(compressionNone, source, nil)
	if err != nil {
		t.Fatalf("failed to create stream reader: %v", err)
	}
	defer reader.Close()

	out, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("failed to read stream: %v", err)
	}
	if !bytes.Equal(out, raw) {
		t.Error("passthrough must not alter the payload")
	}
	wantHash := sha256.Sum256(raw)
	if !bytes.Equal(hash.Sum(nil), wantHash[:]) {
		t.Error("hash must cover the raw stream")
	}
}
