//go:build linux

package hardware

import (
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"strings"
)

// EEPROMUptimeTokenKey is the key used to store the adoption file content in EEPROM
const EEPROMUptimeTokenKey = "UPTIME_TOKEN"

// EEPROMAdoptionStorage reads adoption file content from the EEPROM
// (UPTIME_TOKEN). It is read-only by design: the token is baked into the
// per-device EEPROM image by the server-side eeprom-signer; writing it
// on-device (rpi-eeprom-config --apply) would rebuild the EEPROM from the
// stock base image and drop our embedded public key (docs/NETWORK-FIRST.md).
type EEPROMAdoptionStorage struct {
	logger *slog.Logger
}

// NewEEPROMAdoptionStorage creates a new EEPROM adoption storage instance
func NewEEPROMAdoptionStorage(logger *slog.Logger) *EEPROMAdoptionStorage {
	return &EEPROMAdoptionStorage{
		logger: logger,
	}
}

// ReadAdoptionFileFromDisk reads the raw adoption file content from disk
// Returns the base64-encoded string as-is
func (e *EEPROMAdoptionStorage) ReadAdoptionFileFromDisk(path string) (string, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("failed to read adoption file: %w", err)
	}

	// Trim whitespace and return as-is (base64 string)
	return strings.TrimSpace(string(content)), nil
}

// ReadAdoptionFileFromEEPROM reads the adoption file content from EEPROM
// Returns the base64-encoded string from UPTIME_TOKEN field
func (e *EEPROMAdoptionStorage) ReadAdoptionFileFromEEPROM() (string, error) {
	// Read bootloader config
	cmd := exec.Command("vcgencmd", "bootloader_config")
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to read bootloader config: %w", err)
	}

	// Parse output to find UPTIME_TOKEN line
	keyPrefix := EEPROMUptimeTokenKey + "="
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, keyPrefix) {
			// Extract value after =
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				return strings.TrimSpace(parts[1]), nil
			}
		}
	}

	// UPTIME_TOKEN not found
	return "", nil
}
