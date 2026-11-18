//go:build linux

package handlers

import (
	"archive/tar"
	"os"
	"path/filepath"
	"testing"
)

// Why these tests exist. extractTar
// resolved an entry's parent with EvalSymlinks and read every resolution error
// as "the parent does not exist yet, so it will be created inside the
// destination". When an EXISTING ancestor was a symlink pointing outside and
// only a descendant below it was missing, that inference was false: MkdirAll
// and OpenFile then walked through the link and wrote outside the tree, as
// root, with no race needed. Directory entries never asked at all.

// symlinkedDest returns a destination whose entry "a" is a symlink to a
// directory OUTSIDE it, and that outside directory.
func symlinkedDest(t *testing.T) (dest, outside string) {
	t.Helper()
	outside = t.TempDir()
	dest = filepath.Join(t.TempDir(), "dest")
	if err := os.MkdirAll(dest, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dest, "a")); err != nil {
		t.Fatal(err)
	}
	return dest, outside
}

func assertNothingOutside(t *testing.T, outside string) {
	t.Helper()
	entries, err := os.ReadDir(outside)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("the extraction escaped through the symlink: %s now holds %v", outside, entries)
	}
}

func TestExtractTarRefusesAFileBelowAMissingParentUnderASymlinkedAncestor(t *testing.T) {
	dest, outside := symlinkedDest(t)
	r := tarBytes(t, func(tw *tar.Writer) {
		_ = tw.WriteHeader(&tar.Header{Name: "a/b/c.txt", Mode: 0o644, Size: 5, Typeflag: tar.TypeReg})
		_, _ = tw.Write([]byte("hello"))
	})
	if err := extractTar(r, "x.tar", dest); err == nil {
		t.Fatal("a file below a missing parent under a symlinked ancestor was extracted")
	}
	assertNothingOutside(t, outside)
}

func TestExtractTarRefusesADirectoryEntryThroughASymlinkedAncestor(t *testing.T) {
	dest, outside := symlinkedDest(t)
	r := tarBytes(t, func(tw *tar.Writer) {
		_ = tw.WriteHeader(&tar.Header{Name: "a/b/", Mode: 0o755, Typeflag: tar.TypeDir})
	})
	if err := extractTar(r, "x.tar", dest); err == nil {
		t.Fatal("a directory entry was created through a symlinked ancestor")
	}
	assertNothingOutside(t, outside)
}

func TestExtractTarRefusesASymlinkEntryThroughASymlinkedAncestor(t *testing.T) {
	dest, outside := symlinkedDest(t)
	r := tarBytes(t, func(tw *tar.Writer) {
		_ = tw.WriteHeader(&tar.Header{Name: "a/b/l", Mode: 0o777, Typeflag: tar.TypeSymlink, Linkname: "c"})
	})
	if err := extractTar(r, "x.tar", dest); err == nil {
		t.Fatal("a symlink entry was created through a symlinked ancestor")
	}
	assertNothingOutside(t, outside)
}

func TestExtractTarRefusesAFileDirectlyUnderASymlinkedAncestor(t *testing.T) {
	// The parent EXISTS here (it is the link), which the old check caught by
	// resolving it; the anchored walk must refuse it too, by name.
	dest, outside := symlinkedDest(t)
	r := tarBytes(t, func(tw *tar.Writer) {
		_ = tw.WriteHeader(&tar.Header{Name: "a/c.txt", Mode: 0o644, Size: 5, Typeflag: tar.TypeReg})
		_, _ = tw.Write([]byte("hello"))
	})
	if err := extractTar(r, "x.tar", dest); err == nil {
		t.Fatal("a file was written directly through a symlinked ancestor")
	}
	assertNothingOutside(t, outside)
}

func TestExtractTarCreatesNestedEntriesInsideTheDestination(t *testing.T) {
	// The positive case: missing parents are created, files land with their
	// mode, an internal symlink and an internal hardlink both resolve inside.
	dest := filepath.Join(t.TempDir(), "dest")
	r := tarBytes(t, func(tw *tar.Writer) {
		_ = tw.WriteHeader(&tar.Header{Name: "d1/", Mode: 0o750, Typeflag: tar.TypeDir})
		_ = tw.WriteHeader(&tar.Header{Name: "d1/d2/f.txt", Mode: 0o640, Size: 3, Typeflag: tar.TypeReg})
		_, _ = tw.Write([]byte("abc"))
		_ = tw.WriteHeader(&tar.Header{Name: "d1/link", Mode: 0o777, Typeflag: tar.TypeSymlink, Linkname: "d2/f.txt"})
		_ = tw.WriteHeader(&tar.Header{Name: "d1/hard", Mode: 0o640, Typeflag: tar.TypeLink, Linkname: "d1/d2/f.txt"})
	})
	if err := extractTar(r, "x.tar", dest); err != nil {
		t.Fatalf("extractTar: %v", err)
	}
	if got, err := os.ReadFile(filepath.Join(dest, "d1/d2/f.txt")); err != nil || string(got) != "abc" {
		t.Fatalf("f.txt = %q, %v", got, err)
	}
	if info, err := os.Stat(filepath.Join(dest, "d1/d2/f.txt")); err != nil || info.Mode().Perm() != 0o640 {
		t.Fatalf("f.txt mode = %v, %v", info.Mode(), err)
	}
	if info, err := os.Stat(filepath.Join(dest, "d1")); err != nil || info.Mode().Perm() != 0o750 {
		t.Fatalf("d1 mode = %v, %v", info.Mode(), err)
	}
	if got, err := os.ReadFile(filepath.Join(dest, "d1/link")); err != nil || string(got) != "abc" {
		t.Fatalf("symlink did not resolve inside: %q, %v", got, err)
	}
	if got, err := os.ReadFile(filepath.Join(dest, "d1/hard")); err != nil || string(got) != "abc" {
		t.Fatalf("hardlink did not resolve inside: %q, %v", got, err)
	}
}
