package pkgver

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"fmt"
	"testing"
)

func TestCompare(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"0.2.9", "0.2.10", -1},
		{"0.2.10", "0.2.9", 1},
		{"0.2.22", "0.2.22", 0},
		{"v0.2.22", "0.2.22", 0},
		{"0.2.22-snapshot", "0.2.22", 0},
		{"0.3", "0.2.22", 1},
		{"1.0.0", "0.9.9", 1},
		{"", "0.0.1", -1},
	}
	for _, tc := range cases {
		if got := Compare(tc.a, tc.b); got != tc.want {
			t.Errorf("Compare(%q, %q) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
	}
}

// buildDeb assembles a minimal ar archive shaped like an nfpm .deb: a
// debian-binary entry followed by control.tar.gz holding ./control.
func buildDeb(t *testing.T, controlContent string) []byte {
	t.Helper()

	var controlTarGz bytes.Buffer
	gz := gzip.NewWriter(&controlTarGz)
	tw := tar.NewWriter(gz)
	if err := tw.WriteHeader(&tar.Header{Name: "./control", Mode: 0o644, Size: int64(len(controlContent))}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte(controlContent)); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}

	var deb bytes.Buffer
	deb.WriteString(arMagic)
	writeEntry := func(name string, data []byte) {
		fmt.Fprintf(&deb, "%-16s%-12s%-6s%-6s%-8s%-10d`\n", name, "0", "0", "0", "100644", len(data))
		deb.Write(data)
		if len(data)%2 == 1 {
			deb.WriteByte('\n')
		}
	}
	writeEntry("debian-binary", []byte("2.0\n"))
	writeEntry("control.tar.gz", controlTarGz.Bytes())
	return deb.Bytes()
}

func TestDebControlVersion(t *testing.T) {
	deb := buildDeb(t, "Package: orchestrator-agent\nVersion: 0.2.23\nArchitecture: arm64\n")
	v, err := DebControlVersion(deb)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v != "0.2.23" {
		t.Fatalf("expected 0.2.23, got %q", v)
	}
}

func TestDebControlVersionMissingField(t *testing.T) {
	deb := buildDeb(t, "Package: orchestrator-agent\n")
	if _, err := DebControlVersion(deb); err == nil {
		t.Fatal("expected an error for a control file without Version")
	}
}

func TestDebControlVersionNotAnArchive(t *testing.T) {
	if _, err := DebControlVersion([]byte("definitely not a deb")); err == nil {
		t.Fatal("expected an error for a non-ar payload")
	}
}

// A final odd-sized non-control entry that exactly fills the buffer must fail
// cleanly, not panic on the 2-byte-alignment slice bump.
func TestDebControlVersionOddFinalEntryNoPanic(t *testing.T) {
	var deb bytes.Buffer
	deb.WriteString(arMagic)
	// One 1-byte entry named "debian-binary", no trailing pad → buffer ends
	// on an odd boundary with no control.tar present.
	fmt.Fprintf(&deb, "%-16s%-12s%-6s%-6s%-8s%-10d`\n", "debian-binary", "0", "0", "0", "100644", 1)
	deb.WriteByte('X')

	if _, err := DebControlVersion(deb.Bytes()); err == nil {
		t.Fatal("expected an error for an ar with no control.tar entry")
	}
}
