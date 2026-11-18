//go:build linux

package handlers

import (
	"archive/tar"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	proto "agent/pkg/infrastructure/grpc/proto"
)

// Why this test exists. The anchored staging file the anchor walk
// introduced was opened O_WRONLY. download_file writes the
// archive through that descriptor, hashes it, rewinds it and extracts from the
// SAME descriptor — the property that makes the checksum cover the bytes that
// are unpacked. The seek succeeded and the first read failed with EBADF, so
// every extract=true download failed AFTER the whole archive had been fetched
// and verified. The archive tests exercised extractTar directly and never met
// the descriptor; this one goes through the handler.
func TestDownloadWithExtractUnpacksTheVerifiedArchive(t *testing.T) {
	dest := filepath.Join(t.TempDir(), "unpacked")
	const content = "hello from the archive\n"

	archive, err := io.ReadAll(tarBytes(t, func(tw *tar.Writer) {
		_ = tw.WriteHeader(&tar.Header{Name: "hello.txt", Mode: 0o644, Size: int64(len(content)), Typeflag: tar.TypeReg})
		_, _ = tw.Write([]byte(content))
	}))
	if err != nil {
		t.Fatalf("reading the archive bytes: %v", err)
	}
	sum := sha256.Sum256(archive)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(archive)
	}))
	defer srv.Close()

	h := downloadTestHandler()
	if err := h.handleDownloadFile("cmd-extract", &proto.DownloadFileCommand{
		Url:      srv.URL + "/bundle.tar",
		DestPath: dest,
		Extract:  true,
		Checksum: hex.EncodeToString(sum[:]),
	}); err != nil {
		t.Fatalf("download with extract failed: %v", err)
	}

	got, err := os.ReadFile(filepath.Join(dest, "hello.txt"))
	if err != nil {
		t.Fatalf("the archive member was not extracted: %v", err)
	}
	if string(got) != content {
		t.Fatalf("extracted content = %q, want %q", got, content)
	}
	// The staging temp must be gone from the destination's parent.
	entries, _ := os.ReadDir(filepath.Dir(dest))
	for _, e := range entries {
		if len(e.Name()) > len(".orchestrator-") && e.Name()[:len(".orchestrator-")] == ".orchestrator-" {
			t.Fatalf("staging temp %s was left behind", e.Name())
		}
	}
}
