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

// A refused archive leaves the destination as it was: the members that come
// BEFORE the refused entry are not unpacked either. The archive is judged whole
// from the staging descriptor before anything is written.
func TestDownloadWithExtractRefusalLeavesNothingBehind(t *testing.T) {
	root := t.TempDir()
	dest := filepath.Join(root, "unpacked")

	archive, err := io.ReadAll(tarBytes(t, func(tw *tar.Writer) {
		body := []byte("fine\n")
		_ = tw.WriteHeader(&tar.Header{Name: "dir/", Mode: 0o755, Typeflag: tar.TypeDir})
		_ = tw.WriteHeader(&tar.Header{Name: "dir/ok.txt", Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg})
		_, _ = tw.Write(body)
		_ = tw.WriteHeader(&tar.Header{Name: "link", Typeflag: tar.TypeSymlink, Linkname: "dir/ok.txt"})
		evil := []byte("escaped\n")
		_ = tw.WriteHeader(&tar.Header{Name: "../../outside.txt", Mode: 0o644, Size: int64(len(evil)), Typeflag: tar.TypeReg})
		_, _ = tw.Write(evil)
	}))
	if err != nil {
		t.Fatalf("reading the archive bytes: %v", err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(archive)
	}))
	defer srv.Close()

	h := downloadTestHandler()
	if err := h.handleDownloadFile("cmd-extract-refused", &proto.DownloadFileCommand{
		Url:      srv.URL + "/bundle.tar",
		DestPath: dest,
		Extract:  true,
	}); err == nil {
		t.Fatal("an archive with an escaping member was accepted")
	}

	entries, err := os.ReadDir(dest)
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	for _, e := range entries {
		t.Errorf("the refused archive left %s in the destination", e.Name())
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(root), "outside.txt")); err == nil {
		t.Fatal("the escaping member was written")
	}
}

// An archive refused because a member is reached through a symlink the SAME
// archive creates is refused before anything is written: the member before it
// is not unpacked and a pre-existing file of that name is not replaced.
func TestExtractTarRefusesMemberThroughOwnSymlinkBeforeWriting(t *testing.T) {
	dest := filepath.Join(t.TempDir(), "dest")
	if err := os.MkdirAll(filepath.Join(dest, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dest, "sub", "a.txt"), []byte("original"), 0o644); err != nil {
		t.Fatal(err)
	}
	r := tarBytes(t, func(tw *tar.Writer) {
		body := []byte("replaced")
		_ = tw.WriteHeader(&tar.Header{Name: "sub/", Typeflag: tar.TypeDir, Mode: 0o755})
		_ = tw.WriteHeader(&tar.Header{Name: "sub/a.txt", Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(body))})
		_, _ = tw.Write(body)
		_ = tw.WriteHeader(&tar.Header{Name: "d", Typeflag: tar.TypeSymlink, Linkname: "sub"})
		_ = tw.WriteHeader(&tar.Header{Name: "d/x", Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(body))})
		_, _ = tw.Write(body)
	})
	if err := extractTar(r, "https://example/pkg.tar", dest); err == nil {
		t.Fatal("a member reached through the archive's own symlink was accepted")
	}
	if got, err := os.ReadFile(filepath.Join(dest, "sub", "a.txt")); err != nil || string(got) != "original" {
		t.Errorf("sub/a.txt = %q, err = %v; the refused archive replaced it", got, err)
	}
	if _, err := os.Lstat(filepath.Join(dest, "d")); err == nil {
		t.Error("the refused archive created its symlink")
	}
}

// The judging pass must not change what a good archive unpacks to, including
// a hardlink to an earlier member.
func TestExtractTarJudgedArchiveStillUnpacksHardlinks(t *testing.T) {
	dest := filepath.Join(t.TempDir(), "dest")
	r := tarBytes(t, func(tw *tar.Writer) {
		body := []byte("shared")
		_ = tw.WriteHeader(&tar.Header{Name: "a.txt", Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(body))})
		_, _ = tw.Write(body)
		_ = tw.WriteHeader(&tar.Header{Name: "b.txt", Typeflag: tar.TypeLink, Linkname: "a.txt", Mode: 0o644})
		_ = tw.WriteHeader(&tar.Header{Name: "c", Typeflag: tar.TypeSymlink, Linkname: "a.txt"})
	})
	if err := extractTar(r, "https://example/pkg.tar", dest); err != nil {
		t.Fatalf("a good archive was refused: %v", err)
	}
	for _, name := range []string{"a.txt", "b.txt", "c"} {
		if got, err := os.ReadFile(filepath.Join(dest, name)); err != nil || string(got) != "shared" {
			t.Errorf("%s = %q, err = %v", name, got, err)
		}
	}
}
