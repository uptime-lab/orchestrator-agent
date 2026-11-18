//go:build linux

package handlers

import (
	"archive/tar"
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func tarBytes(t *testing.T, build func(tw *tar.Writer)) *bytes.Reader {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	build(tw)
	if err := tw.Close(); err != nil {
		t.Fatalf("closing tar: %v", err)
	}
	return bytes.NewReader(buf.Bytes())
}

// A hardlink pointing outside the extraction root must be refused. The old guard
// validated dir(target)+linkname while os.Link consumed cleanDir+linkname, so an
// entry linking to ../../../../etc/shadow passed the check and hardlinked the
// real file — after which a regular-file entry of the same name overwrote it as
// root.
func TestExtractTarRefusesAHardlinkEscape(t *testing.T) {
	dir := t.TempDir()
	// A sentinel "outside" file we must not be able to hardlink/overwrite.
	outside := filepath.Join(dir, "outside_secret")
	if err := os.WriteFile(outside, []byte("do-not-touch"), 0o600); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(dir, "dest")

	r := tarBytes(t, func(tw *tar.Writer) {
		// Hardlink an in-dest name to the sentinel one level up.
		_ = tw.WriteHeader(&tar.Header{
			Name:     "sub/evil",
			Typeflag: tar.TypeLink,
			Linkname: "../outside_secret",
			Mode:     0o644,
		})
		// Then a regular file of the same name that would overwrite it.
		body := []byte("PWNED")
		_ = tw.WriteHeader(&tar.Header{Name: "sub/evil", Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(body))})
		_, _ = tw.Write(body)
	})

	if err := extractTar(r, "https://example/pkg.tar", dest); err == nil {
		t.Error("extractTar accepted a hardlink escaping the destination")
	}
	if got, _ := os.ReadFile(outside); string(got) != "do-not-touch" {
		t.Errorf("the outside file was modified: %q", got)
	}
}

// A hardlink that stays inside the destination is a legitimate archive shape and
// must still work.
func TestExtractTarAllowsAnInternalHardlink(t *testing.T) {
	dest := filepath.Join(t.TempDir(), "dest")
	r := tarBytes(t, func(tw *tar.Writer) {
		body := []byte("shared")
		_ = tw.WriteHeader(&tar.Header{Name: "a.txt", Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(body))})
		_, _ = tw.Write(body)
		_ = tw.WriteHeader(&tar.Header{Name: "b.txt", Typeflag: tar.TypeLink, Linkname: "a.txt", Mode: 0o644})
	})
	if err := extractTar(r, "https://example/pkg.tar", dest); err != nil {
		t.Fatalf("a legitimate internal hardlink was refused: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(dest, "b.txt"))
	if err != nil || string(got) != "shared" {
		t.Errorf("internal hardlink content = %q, err = %v", got, err)
	}
}
