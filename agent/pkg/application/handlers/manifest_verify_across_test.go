package handlers

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func writePkgFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return fmt.Sprintf("%x", sha256.Sum256([]byte(content)))
}

func writeManifest(t *testing.T, dir string, sums map[string]string) {
	t.Helper()
	var body string
	for name, sum := range sums {
		body += sum + "  " + name + "\n"
	}
	if err := os.WriteFile(filepath.Join(dir, "SHA256SUMS"), []byte(body), 0o644); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
}

// The package has to be re-verified WHERE THE ROM WILL READ IT.
//
// The manifest is checked where the package was downloaded; the copy onto a
// small FAT boot partition is exactly where a short write or a full filesystem
// turns a verified package into a truncated one — and the ROM loads recovery.bin
// unconditionally on the next boot, on a machine nobody can reach.
func TestPackageIsVerifiedWhereItWillBeRead(t *testing.T) {
	src, dst := t.TempDir(), t.TempDir()
	sums := map[string]string{}
	for _, f := range eepromPackageFiles {
		sums[f] = writePkgFile(t, src, f, "contents of "+f)
	}
	writeManifest(t, src, sums)

	// A faithful copy verifies, with the trigger still under its staged name.
	staged := "recovery.bin.staged"
	for _, f := range eepromPackageFiles {
		name := f
		if f == eepromTriggerFile {
			name = staged
		}
		writePkgFile(t, dst, name, "contents of "+f)
	}
	if err := verifySHA256SUMSAcross(src, dst, "SHA256SUMS", eepromPackageFiles,
		map[string]string{eepromTriggerFile: staged}); err != nil {
		t.Fatalf("a faithful copy failed verification: %v", err)
	}

	// A truncated copy of the trigger must be caught BEFORE it is armed.
	writePkgFile(t, dst, staged, "contents of rec")
	err := verifySHA256SUMSAcross(src, dst, "SHA256SUMS", eepromPackageFiles,
		map[string]string{eepromTriggerFile: staged})
	if err == nil {
		t.Fatal("a truncated recovery.bin passed verification on the boot partition; the ROM would run it and the node needs a physical visit")
	}
}

// A file that never made it across is an absence, not a pass.
func TestAMissingFileOnTheBootPartitionFailsVerification(t *testing.T) {
	src, dst := t.TempDir(), t.TempDir()
	sums := map[string]string{}
	for _, f := range eepromPackageFiles {
		sums[f] = writePkgFile(t, src, f, "contents of "+f)
	}
	writeManifest(t, src, sums)
	// Only one of the three arrives.
	writePkgFile(t, dst, "pieeprom.upd", "contents of pieeprom.upd")

	if err := verifySHA256SUMSAcross(src, dst, "SHA256SUMS", eepromPackageFiles, nil); err == nil {
		t.Fatal("an incomplete package passed verification")
	}
}
