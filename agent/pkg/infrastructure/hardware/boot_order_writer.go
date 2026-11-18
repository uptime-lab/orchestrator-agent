//go:build linux

package hardware

import (
	"bufio"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
)

// fileConfigReader is an interface for reading and writing configuration files
// This abstraction allows testing with in-memory strings instead of real files
type fileConfigReader interface {
	// ReadFile reads the content of a file at the given path
	ReadFile(path string) (string, error)
	// WriteFile writes content to a file at the given path
	WriteFile(path, content string) error
	// FileExists checks if a file exists at the given path
	FileExists(path string) bool
}

// BootOrderWriter holds the Raspberry Pi EEPROM enablement fixes (see
// FixCM4EEPROMConfig). Boot-order changes themselves are NOT done here — they
// are flashed as exact server-signed images from the eeprom-signer.
type BootOrderWriter struct {
	logger         *slog.Logger
	fileReader     fileConfigReader
	configTxtPaths []string
}

// NewBootOrderWriterWithReader creates a new boot order writer with a custom file reader
// This is useful for testing with in-memory file operations
func NewBootOrderWriterWithReader(logger *slog.Logger, reader fileConfigReader, configTxtPaths []string) *BootOrderWriter {
	return &BootOrderWriter{
		logger:         logger,
		fileReader:     reader,
		configTxtPaths: configTxtPaths,
	}
}

// NewBootOrderWriter creates a new boot order writer
func NewBootOrderWriter(logger *slog.Logger) *BootOrderWriter {
	return &BootOrderWriter{
		logger:         logger,
		fileReader:     &realFileReader{},
		configTxtPaths: []string{"/boot/firmware/config.txt", "/boot/config.txt"},
	}
}

// realFileReader implements fileConfigReader using real file system operations
type realFileReader struct{}

func (r *realFileReader) ReadFile(path string) (string, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return string(content), nil
}

// WriteFile replaces a file atomically: write a sibling temp file, fsync it,
// rename over the target, then fsync the directory.
//
// The plain os.WriteFile this replaced truncated the target first, so a power
// cut or a crash mid-write left a half-written file. One of the two files this
// writer touches is /boot/firmware/config.txt, where "half-written" means a
// device that does not boot and has to be recovered by hand.
func (r *realFileReader) WriteFile(path, content string) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".orchestrator-*.tmp")
	if err != nil {
		return fmt.Errorf("failed to create a temp file in %s: %w", dir, err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }() // no-op once the rename succeeds

	if _, err := tmp.WriteString(content); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("failed to write %s: %w", tmpName, err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("failed to sync %s: %w", tmpName, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("failed to close %s: %w", tmpName, err)
	}
	// CreateTemp makes the file 0600; these are world-readable config files.
	if err := os.Chmod(tmpName, 0644); err != nil {
		return fmt.Errorf("failed to chmod %s: %w", tmpName, err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("failed to replace %s: %w", path, err)
	}
	// vfat (the boot partition) does not honour a directory fsync, but on the
	// filesystems that do, this is what makes the rename durable.
	if d, derr := os.Open(dir); derr == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

func (r *realFileReader) FileExists(path string) bool {
	_, err := os.Stat(path)
	return !os.IsNotExist(err)
}

// NOTE: this writer intentionally has no "set boot order" method. All EEPROM
// changes are flashed as exact server-signed images from the eeprom-signer
// (see the update_boot_order handler); rebuilding the config on-device with
// rpi-eeprom-config --apply would drop the embedded public key and break
// signed network boot (docs/NETWORK-FIRST.md). This type only keeps the
// enable-OS-side-EEPROM-updates fix (FixCM4EEPROMConfig).

// BootOrderArrayToHex converts an array of boot device enums to a BOOT_ORDER
// hex string (e.g. ["nvme","http","sd","restart"] -> "0xf176"). Exported for
// the bootstrap recovery-package path, which needs the hex to locate the
// server-generated EEPROM package.
func BootOrderArrayToHex(order []string) (string, error) {
	return bootOrderArrayToHex(order)
}

// bootOrderArrayToHex converts array of boot device enums to hex string
// Builds hex right-to-left from array
func bootOrderArrayToHex(order []string) (string, error) {
	// Map boot device enums to hex digits
	// Based on Raspberry Pi boot order documentation: https://www.raspberrypi.com/documentation/computers/raspberry-pi.html#BOOT_ORDER
	deviceToDigit := map[string]string{
		"sd_card_detect": "0",
		"sd":             "1",
		"network":        "2",
		"rpiboot":        "3",
		"usb_msd":        "4",
		"bcm_usb_msd":    "5",
		"nvme":           "6",
		"http":           "7",
		"stop":           "e",
		"restart":        "f",
	}

	var hexDigits []string

	// Convert array to hex digits (right-to-left)
	for i := len(order) - 1; i >= 0; i-- {
		device := strings.ToLower(strings.TrimSpace(order[i]))
		if digit, ok := deviceToDigit[device]; ok {
			hexDigits = append(hexDigits, digit)
		} else {
			// Build list of valid devices for error message
			validDevices := make([]string, 0, len(deviceToDigit))
			for d := range deviceToDigit {
				validDevices = append(validDevices, d)
			}
			return "", fmt.Errorf("invalid boot device: %s (must be one of: %s)", device, strings.Join(validDevices, ", "))
		}
	}

	if len(hexDigits) == 0 {
		return "", fmt.Errorf("boot order array cannot be empty")
	}

	// Build hex string and prepend 0x
	hex := "0x" + strings.Join(hexDigits, "")
	return hex, nil
}

// IsCM4EEPROMError checks if the error output indicates CM4 EEPROM updates are
// not enabled (fixable with FixCM4EEPROMConfig).
func IsCM4EEPROMError(stderr string) bool {
	return strings.Contains(stderr, "CM4") &&
		(strings.Contains(stderr, "rpi-eeprom-update is not enabled") ||
			strings.Contains(stderr, "CM4_ENABLE_RPI_EEPROM_UPDATE"))
}

// FixCM4EEPROMConfig applies the necessary configuration to enable CM4 EEPROM updates
// This is a public method that can be called from command handlers
func (w *BootOrderWriter) FixCM4EEPROMConfig() error {
	// Fix 1: Update /etc/default/rpi-eeprom-update
	if err := w.updateRpiEepromUpdateConfig(); err != nil {
		return fmt.Errorf("failed to update rpi-eeprom-update config: %w", err)
	}

	// Fix 2: Update config.txt with CM4 settings
	if err := w.updateConfigTxtForCM4(); err != nil {
		return fmt.Errorf("failed to update config.txt: %w", err)
	}

	return nil
}

// updateRpiEepromUpdateConfig updates /etc/default/rpi-eeprom-update with CM4 settings
func (w *BootOrderWriter) updateRpiEepromUpdateConfig() error {
	configPath := "/etc/default/rpi-eeprom-update"

	w.logger.Info("updating rpi-eeprom-update config", "path", configPath)

	// Read existing file if it exists
	var content string
	var err error
	if w.fileReader.FileExists(configPath) {
		content, err = w.fileReader.ReadFile(configPath)
		if err != nil {
			return fmt.Errorf("failed to read %s: %w", configPath, err)
		}
	}

	// Parse content into lines
	var lines []string
	if content != "" {
		scanner := bufio.NewScanner(strings.NewReader(content))
		for scanner.Scan() {
			lines = append(lines, scanner.Text())
		}
		if err := scanner.Err(); err != nil {
			return fmt.Errorf("failed to parse %s: %w", configPath, err)
		}
	}

	hasFlashrom := false
	hasCM4Enable := false
	var updatedLines []string

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		// Skip comments and empty lines for now, we'll add them back
		if strings.HasPrefix(trimmed, "#") || trimmed == "" {
			updatedLines = append(updatedLines, line)
			continue
		}

		// Check if settings already exist
		if strings.HasPrefix(trimmed, "RPI_EEPROM_USE_FLASHROM=") {
			hasFlashrom = true
			// Update to ensure it's set to 1
			updatedLines = append(updatedLines, "RPI_EEPROM_USE_FLASHROM=1")
			continue
		}
		if strings.HasPrefix(trimmed, "CM4_ENABLE_RPI_EEPROM_UPDATE=") {
			hasCM4Enable = true
			// Update to ensure it's set to 1
			updatedLines = append(updatedLines, "CM4_ENABLE_RPI_EEPROM_UPDATE=1")
			continue
		}

		updatedLines = append(updatedLines, line)
	}

	// Add missing settings
	if !hasFlashrom {
		updatedLines = append(updatedLines, "RPI_EEPROM_USE_FLASHROM=1")
		w.logger.Info("added RPI_EEPROM_USE_FLASHROM=1")
	}
	if !hasCM4Enable {
		updatedLines = append(updatedLines, "CM4_ENABLE_RPI_EEPROM_UPDATE=1")
		w.logger.Info("added CM4_ENABLE_RPI_EEPROM_UPDATE=1")
	}

	// Write back to file
	newContent := strings.Join(updatedLines, "\n")
	if !strings.HasSuffix(newContent, "\n") && len(updatedLines) > 0 {
		newContent += "\n"
	}

	if err := w.fileReader.WriteFile(configPath, newContent); err != nil {
		return fmt.Errorf("failed to write %s: %w", configPath, err)
	}

	w.logger.Info("rpi-eeprom-update config updated successfully")
	return nil
}

// updateConfigTxtForCM4 updates config.txt with CM4-specific settings
func (w *BootOrderWriter) updateConfigTxtForCM4() error {
	// Try both possible config.txt paths
	var configPath string
	var content string

	// Find which config.txt exists
	for _, path := range w.configTxtPaths {
		if w.fileReader.FileExists(path) {
			var readErr error
			content, readErr = w.fileReader.ReadFile(path)
			if readErr == nil {
				configPath = path
				break
			}
			return fmt.Errorf("failed to read %s: %w", path, readErr)
		}
	}

	if configPath == "" {
		return fmt.Errorf("config.txt not found in %v", w.configTxtPaths)
	}

	w.logger.Info("updating config.txt for CM4", "path", configPath)

	// Parse the file to check what exists in the [cm4] section
	lines := strings.Split(content, "\n")
	var newLines []string
	inCM4Section := false
	hasCM4Section := false
	hasSPIInCM4 := false
	hasAudremapInCM4 := false
	hasSPIGPIOInCM4 := false

	// First pass: check what exists in [cm4] section
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		if trimmed == "[cm4]" {
			hasCM4Section = true
			inCM4Section = true
			continue
		}

		// If we're in the [cm4] section and hit another section, exit it
		if inCM4Section && strings.HasPrefix(trimmed, "[") && trimmed != "[cm4]" {
			inCM4Section = false
		}

		// Check for settings within [cm4] section
		if inCM4Section {
			if trimmed == "dtparam=spi=on" {
				hasSPIInCM4 = true
			} else if trimmed == "dtoverlay=audremap" {
				hasAudremapInCM4 = true
			} else if trimmed == "dtoverlay=spi-gpio40-45" {
				hasSPIGPIOInCM4 = true
			}
		}
	}

	// If all settings already exist in [cm4] section, no update needed
	if hasCM4Section && hasSPIInCM4 && hasAudremapInCM4 && hasSPIGPIOInCM4 {
		w.logger.Info("config.txt already has all CM4 settings in [cm4] section, no update needed")
		return nil
	}

	// Second pass: build the updated file. Only the settings the first pass
	// found missing are inserted (right after the first [cm4] header), so
	// existing lines are never dropped.
	cm4SettingsAdded := false

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		newLines = append(newLines, line)

		if trimmed == "[cm4]" && !cm4SettingsAdded {
			if !hasSPIInCM4 {
				newLines = append(newLines, "dtparam=spi=on")
				w.logger.Info("added dtparam=spi=on to [cm4] section")
			}
			if !hasAudremapInCM4 {
				newLines = append(newLines, "dtoverlay=audremap")
				w.logger.Info("added dtoverlay=audremap to [cm4] section")
			}
			if !hasSPIGPIOInCM4 {
				newLines = append(newLines, "dtoverlay=spi-gpio40-45")
				w.logger.Info("added dtoverlay=spi-gpio40-45 to [cm4] section")
			}
			cm4SettingsAdded = true
		}
	}

	// If [cm4] section doesn't exist, add it at the end
	if !hasCM4Section {
		// Ensure content ends with newline
		contentEnd := strings.TrimRight(strings.Join(newLines, "\n"), "\n")
		newLines = []string{contentEnd, "", "[cm4]", "dtparam=spi=on", "dtoverlay=audremap", "dtoverlay=spi-gpio40-45"}
		w.logger.Info("added [cm4] section with all required settings")
	}

	content = strings.Join(newLines, "\n")
	if !strings.HasSuffix(content, "\n") && len(newLines) > 0 {
		content += "\n"
	}

	// Write the updated content
	// Keep one pristine copy the first time we ever touch this file, matching
	// what patch_file does for the same path. If the managed edit turns out to
	// be wrong, there is something to restore from the recovery bootstrap.
	backupPath := configPath + ".orchestrator.bak"
	if !w.fileReader.FileExists(backupPath) {
		if original, rerr := w.fileReader.ReadFile(configPath); rerr == nil {
			if berr := w.fileReader.WriteFile(backupPath, original); berr != nil {
				w.logger.Warn("could not write the one-time config.txt backup", "path", backupPath, "error", berr)
			}
		}
	}

	if err := w.fileReader.WriteFile(configPath, content); err != nil {
		return fmt.Errorf("failed to write %s: %w", configPath, err)
	}

	w.logger.Info("config.txt updated successfully with CM4 settings")
	return nil
}
