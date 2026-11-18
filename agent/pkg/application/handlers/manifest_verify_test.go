package handlers

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writePackage lays out a dir with the given files and a manifest covering
// exactly `covered`. It returns the dir.
func writePackage(t *testing.T, files map[string]string, covered []string) string {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	var manifest strings.Builder
	for _, name := range covered {
		sum := sha256.Sum256([]byte(files[name]))
		fmt.Fprintf(&manifest, "%x  %s\n", sum, name)
	}
	if err := os.WriteFile(filepath.Join(dir, "SHA256SUMS"), []byte(manifest.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

func goodPackage() map[string]string {
	return map[string]string{
		"recovery.bin": "recovery payload",
		"pieeprom.upd": "eeprom image",
		"pieeprom.sig": "signature",
	}
}

func TestVerifyAcceptsACompleteManifest(t *testing.T) {
	files := goodPackage()
	dir := writePackage(t, files, eepromPackageFiles)
	if err := verifySHA256SUMS(dir, "SHA256SUMS", eepromPackageFiles); err != nil {
		t.Fatalf("a complete, correct package must verify: %v", err)
	}
}

// THE regression. An empty manifest used to return nil, and the caller logged
// "EEPROM package verified" and flashed the device.
func TestVerifyRefusesAnEmptyManifest(t *testing.T) {
	for _, manifest := range []string{"", "\n", "   \n\t\n"} {
		files := goodPackage()
		dir := writePackage(t, files, nil)
		if err := os.WriteFile(filepath.Join(dir, "SHA256SUMS"), []byte(manifest), 0o600); err != nil {
			t.Fatal(err)
		}
		err := verifySHA256SUMS(dir, "SHA256SUMS", eepromPackageFiles)
		if err == nil {
			t.Fatalf("an empty manifest (%q) must NOT verify — it verifies nothing", manifest)
		}
		if !strings.Contains(err.Error(), "does not cover") {
			t.Fatalf("the error should name what was not covered, got %v", err)
		}
	}
}

// A truncated manifest is the realistic failure: the object was cut short, so
// the last file is simply never hashed.
func TestVerifyRefusesAPartialManifest(t *testing.T) {
	files := goodPackage()
	dir := writePackage(t, files, eepromPackageFiles[:2])
	err := verifySHA256SUMS(dir, "SHA256SUMS", eepromPackageFiles)
	if err == nil {
		t.Fatal("a manifest missing an entry must not verify")
	}
	if !strings.Contains(err.Error(), eepromPackageFiles[2]) {
		t.Fatalf("the error should name the uncovered file, got %v", err)
	}
}

// Corruption of a covered file is still caught (the behaviour that already
// worked must keep working).
func TestVerifyCatchesACorruptedFile(t *testing.T) {
	files := goodPackage()
	dir := writePackage(t, files, eepromPackageFiles)
	if err := os.WriteFile(filepath.Join(dir, "pieeprom.upd"), []byte("tampered"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := verifySHA256SUMS(dir, "SHA256SUMS", eepromPackageFiles); err == nil {
		t.Fatal("a content mismatch must not verify")
	}
}

func TestVerifyRefusesAMissingFile(t *testing.T) {
	files := goodPackage()
	dir := writePackage(t, files, eepromPackageFiles)
	if err := os.Remove(filepath.Join(dir, "pieeprom.sig")); err != nil {
		t.Fatal(err)
	}
	if err := verifySHA256SUMS(dir, "SHA256SUMS", eepromPackageFiles); err == nil {
		t.Fatal("a file listed but absent must not verify")
	}
}

// The manifest arrives over the network, so a name is a file in dir and never
// a path out of it.
func TestVerifyRefusesAPathInTheManifest(t *testing.T) {
	files := goodPackage()
	dir := writePackage(t, files, eepromPackageFiles)
	line := fmt.Sprintf("%x  ../escape\n", sha256.Sum256([]byte("x")))
	if err := os.WriteFile(filepath.Join(dir, "SHA256SUMS"), []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}
	err := verifySHA256SUMS(dir, "SHA256SUMS", eepromPackageFiles)
	if err == nil || !strings.Contains(err.Error(), "illegal file name") {
		t.Fatalf("a path in the manifest must be refused, got %v", err)
	}
}

func TestVerifyRefusesAMalformedLine(t *testing.T) {
	files := goodPackage()
	dir := writePackage(t, files, eepromPackageFiles)
	body, err := os.ReadFile(filepath.Join(dir, "SHA256SUMS"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "SHA256SUMS"), append(body, []byte("garbage\n")...), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := verifySHA256SUMS(dir, "SHA256SUMS", eepromPackageFiles); err == nil {
		t.Fatal("a hash-less line must be refused rather than skipped")
	}
}

// A missing manifest file is an error, not a pass.
func TestVerifyRefusesAnAbsentManifest(t *testing.T) {
	dir := t.TempDir()
	if err := verifySHA256SUMS(dir, "SHA256SUMS", eepromPackageFiles); err == nil {
		t.Fatal("an absent manifest must not verify")
	}
}
