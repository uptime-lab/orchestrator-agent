package handlers

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// eepromPackageFiles are the files that make up a signed EEPROM package. It is
// the required-set passed to verifySHA256SUMS: the manifest must cover all
// three, or nothing is flashed.
var eepromPackageFiles = []string{"recovery.bin", "pieeprom.upd", "pieeprom.sig"}

// eepromTriggerFile is the one file the ROM looks for. Its PRESENCE is what
// makes the next boot flash the EEPROM, which is why it is written last and
// renamed into place rather than copied under its final name.
const eepromTriggerFile = "recovery.bin"

// verifySHA256SUMS checks every "<hash>  <file>" line in dir/sumsFile against
// the actual file contents in dir, and requires that every name in `required`
// was covered by a line that verified.
//
// It is fail-CLOSED, and the required-set is the reason. The previous version
// verified whatever the manifest happened to list and returned nil otherwise,
// which made a truncated manifest indistinguishable from a good one: an empty
// file passed VACUOUSLY (strings.Split never returns an empty slice, so the
// len(lines)==0 guard was dead code and every iteration hit the `continue`),
// and a manifest merely missing an entry meant that file was never hashed at
// all. The caller then logged "EEPROM package verified" and handed the bytes to
// rpi-eeprom-update -d -f.
//
// The realistic trigger is a truncated CDN or proxy object rather than an
// attacker, but the consequence is a Pi that no longer boots and needs someone
// to walk to the rack — the one failure in this product that cannot be
// recovered remotely. "Verified nothing" must therefore never return success.
//
// This file carries no build tag on purpose. It is pure standard library, and
// keeping it out of command_handler_linux.go is what lets its tests run during
// an ordinary `go test ./...` on a macOS dev machine instead of only inside the
// Linux CI container.
func verifySHA256SUMS(dir, sumsFile string, required []string) error {
	return verifySHA256SUMSAcross(dir, dir, sumsFile, required, nil)
}

// verifySHA256SUMSAcross is verifySHA256SUMS with the manifest and the files it
// describes in DIFFERENT directories, and with an optional rename map for a file
// staged under a temporary name.
//
// It exists so the EEPROM package can be re-verified where it will actually be
// READ — on the boot partition — rather than only where it was downloaded. The
// bytes the ROM loads are the ones that matter, and a copy is exactly where a
// short write or a full filesystem turns a verified package into a truncated
// one. `nameOnDisk` maps a manifest name to the name the file currently has, so
// the trigger file can be checked while it is still staged under a temp name.
func verifySHA256SUMSAcross(manifestDir, contentDir, sumsFile string, required []string, nameOnDisk map[string]string) error {
	content, err := os.ReadFile(filepath.Join(manifestDir, sumsFile))
	if err != nil {
		return err
	}
	verified := make(map[string]bool, len(required))
	for _, line := range strings.Split(string(content), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue // blank line
		}
		if len(fields) < 2 {
			return fmt.Errorf("malformed line in %s: %q", sumsFile, line)
		}
		want, name := fields[0], fields[len(fields)-1]
		// The manifest is data fetched over the network; a name is a plain file
		// inside dir, never a path.
		if name != filepath.Base(name) || name == "." || name == ".." {
			return fmt.Errorf("illegal file name in %s: %q", sumsFile, name)
		}
		onDisk := name
		if nameOnDisk != nil {
			if staged, ok := nameOnDisk[name]; ok {
				onDisk = staged
			}
		}
		data, err := os.ReadFile(filepath.Join(contentDir, onDisk))
		if err != nil {
			return fmt.Errorf("missing file %s from manifest: %w", name, err)
		}
		got := fmt.Sprintf("%x", sha256.Sum256(data))
		if !strings.EqualFold(got, want) {
			return fmt.Errorf("checksum mismatch for %s: want %s got %s", name, want, got)
		}
		verified[name] = true
	}
	for _, name := range required {
		if !verified[name] {
			return fmt.Errorf("%s does not cover %s: %d of %d required files verified",
				sumsFile, name, len(verified), len(required))
		}
	}
	return nil
}
