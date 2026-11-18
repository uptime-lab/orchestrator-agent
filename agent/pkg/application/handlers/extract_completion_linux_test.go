//go:build linux

package handlers

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

// Decoder completion at the extraction level: a valid tar end marker followed by a
// bad container completion must fail extractTarInto, whatever the archive
// already unpacked. The decoder-level cases are in decoder_finish_test.go
// (portable); this one proves the handler's loop asks for the completion.
func TestExtractionRefusesAnArchiveThatFailsAtCompletion(t *testing.T) {
	raw := smallTar(t)
	cases := map[string][]byte{
		"a.tar.gz":  corruptTail(gzipOf(t, raw)),
		"a.tar.xz":  corruptTail(xzOf(t, raw)),
		"a.tar.zst": append(append([]byte(nil), zstdOf(t, raw)...), []byte("not a zstd frame")...),
	}
	for name, archive := range cases {
		t.Run(name, func(t *testing.T) {
			dest := filepath.Join(t.TempDir(), "unpacked")
			rootFD, err := openOrCreateDirNoSymlinks(dest)
			if err != nil {
				t.Fatal(err)
			}
			defer unix.Close(rootFD)
			if err := extractTarInto(rootFD, bytes.NewReader(archive), name, dest, nil); err == nil {
				t.Fatalf("%s: an archive whose container fails at completion extracted as success", name)
			}
		})
	}
	// Control: the same archives intact extract and leave the member behind.
	for name, archive := range map[string][]byte{"a.tar.gz": gzipOf(t, raw), "a.tar.xz": xzOf(t, raw), "a.tar.zst": zstdOf(t, raw)} {
		dest := filepath.Join(t.TempDir(), "unpacked")
		rootFD, err := openOrCreateDirNoSymlinks(dest)
		if err != nil {
			t.Fatal(err)
		}
		if err := extractTarInto(rootFD, bytes.NewReader(archive), name, dest, nil); err != nil {
			t.Fatalf("%s: control archive refused: %v", name, err)
		}
		_ = unix.Close(rootFD)
		if _, err := os.Stat(filepath.Join(dest, "file.txt")); err != nil {
			t.Fatalf("%s: control member missing: %v", name, err)
		}
	}
}
