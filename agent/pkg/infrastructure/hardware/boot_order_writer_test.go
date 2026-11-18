//go:build linux

package hardware

import (
	"log/slog"
	"os"
	"strings"
	"testing"
)

// inMemoryFileReader implements fileConfigReader using in-memory map for testing
type inMemoryFileReader struct {
	files map[string]string
}

func newInMemoryFileReader() *inMemoryFileReader {
	return &inMemoryFileReader{
		files: make(map[string]string),
	}
}

func (r *inMemoryFileReader) ReadFile(path string) (string, error) {
	content, exists := r.files[path]
	if !exists {
		return "", os.ErrNotExist
	}
	return content, nil
}

func (r *inMemoryFileReader) WriteFile(path, content string) error {
	if r.files == nil {
		r.files = make(map[string]string)
	}
	r.files[path] = content
	return nil
}

func (r *inMemoryFileReader) FileExists(path string) bool {
	_, exists := r.files[path]
	return exists
}

func (r *inMemoryFileReader) GetFile(path string) string {
	return r.files[path]
}

func TestUpdateRpiEepromUpdateConfig_EmptyFile(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	reader := newInMemoryFileReader()
	writer := NewBootOrderWriterWithReader(logger, reader, []string{})

	err := writer.updateRpiEepromUpdateConfig()
	if err != nil {
		t.Fatalf("updateRpiEepromUpdateConfig failed: %v", err)
	}

	content := reader.GetFile("/etc/default/rpi-eeprom-update")
	expectedLines := []string{
		"RPI_EEPROM_USE_FLASHROM=1",
		"CM4_ENABLE_RPI_EEPROM_UPDATE=1",
	}

	for _, expected := range expectedLines {
		if !strings.Contains(content, expected) {
			t.Errorf("expected to find %s in content, got: %s", expected, content)
		}
	}
}

func TestUpdateRpiEepromUpdateConfig_WithExistingSettings(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	reader := newInMemoryFileReader()
	reader.WriteFile("/etc/default/rpi-eeprom-update", "RPI_EEPROM_USE_FLASHROM=0\nCM4_ENABLE_RPI_EEPROM_UPDATE=0\n")
	writer := NewBootOrderWriterWithReader(logger, reader, []string{})

	err := writer.updateRpiEepromUpdateConfig()
	if err != nil {
		t.Fatalf("updateRpiEepromUpdateConfig failed: %v", err)
	}

	content := reader.GetFile("/etc/default/rpi-eeprom-update")
	if !strings.Contains(content, "RPI_EEPROM_USE_FLASHROM=1") {
		t.Errorf("expected RPI_EEPROM_USE_FLASHROM=1, got: %s", content)
	}
	if !strings.Contains(content, "CM4_ENABLE_RPI_EEPROM_UPDATE=1") {
		t.Errorf("expected CM4_ENABLE_RPI_EEPROM_UPDATE=1, got: %s", content)
	}
}

func TestUpdateRpiEepromUpdateConfig_WithComments(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	reader := newInMemoryFileReader()
	initialContent := "# This is a comment\n# Another comment\nRPI_EEPROM_USE_FLASHROM=0\n"
	reader.WriteFile("/etc/default/rpi-eeprom-update", initialContent)
	writer := NewBootOrderWriterWithReader(logger, reader, []string{})

	err := writer.updateRpiEepromUpdateConfig()
	if err != nil {
		t.Fatalf("updateRpiEepromUpdateConfig failed: %v", err)
	}

	content := reader.GetFile("/etc/default/rpi-eeprom-update")
	// Comments should be preserved
	if !strings.Contains(content, "# This is a comment") {
		t.Errorf("expected to preserve comment, got: %s", content)
	}
	if !strings.Contains(content, "RPI_EEPROM_USE_FLASHROM=1") {
		t.Errorf("expected RPI_EEPROM_USE_FLASHROM=1, got: %s", content)
	}
	if !strings.Contains(content, "CM4_ENABLE_RPI_EEPROM_UPDATE=1") {
		t.Errorf("expected CM4_ENABLE_RPI_EEPROM_UPDATE=1, got: %s", content)
	}
}

func TestUpdateRpiEepromUpdateConfig_PartialSettings(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	reader := newInMemoryFileReader()
	reader.WriteFile("/etc/default/rpi-eeprom-update", "RPI_EEPROM_USE_FLASHROM=1\n")
	writer := NewBootOrderWriterWithReader(logger, reader, []string{})

	err := writer.updateRpiEepromUpdateConfig()
	if err != nil {
		t.Fatalf("updateRpiEepromUpdateConfig failed: %v", err)
	}

	content := reader.GetFile("/etc/default/rpi-eeprom-update")
	if !strings.Contains(content, "RPI_EEPROM_USE_FLASHROM=1") {
		t.Errorf("expected RPI_EEPROM_USE_FLASHROM=1, got: %s", content)
	}
	if !strings.Contains(content, "CM4_ENABLE_RPI_EEPROM_UPDATE=1") {
		t.Errorf("expected CM4_ENABLE_RPI_EEPROM_UPDATE=1, got: %s", content)
	}
}

func TestUpdateConfigTxtForCM4_NoCM4Section(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	reader := newInMemoryFileReader()
	initialContent := "dtparam=audio=on\nenable_uart=1\n"
	reader.WriteFile("/boot/config.txt", initialContent)
	writer := NewBootOrderWriterWithReader(logger, reader, []string{"/boot/config.txt"})

	err := writer.updateConfigTxtForCM4()
	if err != nil {
		t.Fatalf("updateConfigTxtForCM4 failed: %v", err)
	}

	content := reader.GetFile("/boot/config.txt")
	// Should have original content
	if !strings.Contains(content, "dtparam=audio=on") {
		t.Errorf("expected to preserve original content, got: %s", content)
	}
	// Should have [cm4] section
	if !strings.Contains(content, "[cm4]") {
		t.Errorf("expected [cm4] section, got: %s", content)
	}
	// Should have all CM4 settings
	expectedSettings := []string{
		"dtparam=spi=on",
		"dtoverlay=audremap",
		"dtoverlay=spi-gpio40-45",
	}
	for _, setting := range expectedSettings {
		if !strings.Contains(content, setting) {
			t.Errorf("expected to find %s, got: %s", setting, content)
		}
	}
}

func TestUpdateConfigTxtForCM4_WithCM4SectionMissingSettings(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	reader := newInMemoryFileReader()
	initialContent := "[cm4]\ndtparam=spi=on\n[all]\ndtparam=audio=on\n"
	reader.WriteFile("/boot/config.txt", initialContent)
	writer := NewBootOrderWriterWithReader(logger, reader, []string{"/boot/config.txt"})

	err := writer.updateConfigTxtForCM4()
	if err != nil {
		t.Fatalf("updateConfigTxtForCM4 failed: %v", err)
	}

	content := reader.GetFile("/boot/config.txt")
	// Should have [cm4] section
	if !strings.Contains(content, "[cm4]") {
		t.Errorf("expected [cm4] section, got: %s", content)
	}
	// Should have all CM4 settings in [cm4] section
	if !strings.Contains(content, "dtparam=spi=on") {
		t.Errorf("expected dtparam=spi=on, got: %s", content)
	}
	if !strings.Contains(content, "dtoverlay=audremap") {
		t.Errorf("expected dtoverlay=audremap, got: %s", content)
	}
	if !strings.Contains(content, "dtoverlay=spi-gpio40-45") {
		t.Errorf("expected dtoverlay=spi-gpio40-45, got: %s", content)
	}
	// Should preserve [all] section
	if !strings.Contains(content, "[all]") {
		t.Errorf("expected to preserve [all] section, got: %s", content)
	}
}

func TestUpdateConfigTxtForCM4_WithCompleteCM4Section(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	reader := newInMemoryFileReader()
	initialContent := "[cm4]\ndtparam=spi=on\ndtoverlay=audremap\ndtoverlay=spi-gpio40-45\n[all]\ndtparam=audio=on\n"
	reader.WriteFile("/boot/config.txt", initialContent)
	writer := NewBootOrderWriterWithReader(logger, reader, []string{"/boot/config.txt"})

	err := writer.updateConfigTxtForCM4()
	if err != nil {
		t.Fatalf("updateConfigTxtForCM4 failed: %v", err)
	}

	content := reader.GetFile("/boot/config.txt")
	// Should still have all settings
	if !strings.Contains(content, "[cm4]") {
		t.Errorf("expected [cm4] section, got: %s", content)
	}
	if !strings.Contains(content, "dtparam=spi=on") {
		t.Errorf("expected dtparam=spi=on, got: %s", content)
	}
	if !strings.Contains(content, "dtoverlay=audremap") {
		t.Errorf("expected dtoverlay=audremap, got: %s", content)
	}
	if !strings.Contains(content, "dtoverlay=spi-gpio40-45") {
		t.Errorf("expected dtoverlay=spi-gpio40-45, got: %s", content)
	}
}

func TestUpdateConfigTxtForCM4_WithSettingsOutsideCM4Section(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	reader := newInMemoryFileReader()
	// Settings exist but not in [cm4] section - should still add them to [cm4]
	initialContent := "dtparam=spi=on\ndtoverlay=audremap\n[cm4]\n[all]\n"
	reader.WriteFile("/boot/config.txt", initialContent)
	writer := NewBootOrderWriterWithReader(logger, reader, []string{"/boot/config.txt"})

	err := writer.updateConfigTxtForCM4()
	if err != nil {
		t.Fatalf("updateConfigTxtForCM4 failed: %v", err)
	}

	content := reader.GetFile("/boot/config.txt")
	// Should have [cm4] section with all settings
	if !strings.Contains(content, "[cm4]") {
		t.Errorf("expected [cm4] section, got: %s", content)
	}
	// Check that settings are in [cm4] section (after [cm4] line)
	lines := strings.Split(content, "\n")
	inCM4Section := false
	foundSPI := false
	foundAudremap := false
	foundSPIGPIO := false

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "[cm4]" {
			inCM4Section = true
			continue
		}
		if strings.HasPrefix(trimmed, "[") && trimmed != "[cm4]" {
			inCM4Section = false
			continue
		}
		if inCM4Section {
			if trimmed == "dtparam=spi=on" {
				foundSPI = true
			}
			if trimmed == "dtoverlay=audremap" {
				foundAudremap = true
			}
			if trimmed == "dtoverlay=spi-gpio40-45" {
				foundSPIGPIO = true
			}
		}
	}

	if !foundSPI {
		t.Errorf("expected dtparam=spi=on in [cm4] section, got: %s", content)
	}
	if !foundAudremap {
		t.Errorf("expected dtoverlay=audremap in [cm4] section, got: %s", content)
	}
	if !foundSPIGPIO {
		t.Errorf("expected dtoverlay=spi-gpio40-45 in [cm4] section, got: %s", content)
	}
}

func TestUpdateConfigTxtForCM4_FileNotFound(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	reader := newInMemoryFileReader()
	writer := NewBootOrderWriterWithReader(logger, reader, []string{"/boot/firmware/config.txt", "/boot/config.txt"})

	err := writer.updateConfigTxtForCM4()
	if err == nil {
		t.Fatal("expected error when config.txt not found")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("expected 'not found' error, got: %v", err)
	}
}

func TestUpdateConfigTxtForCM4_FirmwarePath(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	reader := newInMemoryFileReader()
	initialContent := "dtparam=audio=on\n"
	reader.WriteFile("/boot/firmware/config.txt", initialContent)
	writer := NewBootOrderWriterWithReader(logger, reader, []string{"/boot/firmware/config.txt", "/boot/config.txt"})

	err := writer.updateConfigTxtForCM4()
	if err != nil {
		t.Fatalf("updateConfigTxtForCM4 failed: %v", err)
	}

	content := reader.GetFile("/boot/firmware/config.txt")
	if !strings.Contains(content, "[cm4]") {
		t.Errorf("expected [cm4] section, got: %s", content)
	}
}

func TestIsCM4EEPROMError(t *testing.T) {
	tests := []struct {
		name     string
		stderr   string
		expected bool
	}{
		{
			name:     "CM4 error message",
			stderr:   "ERROR: EEPROM image 'rpi-eeprom-update is not enabled by default on CM4.",
			expected: true,
		},
		{
			name:     "CM4_ENABLE_RPI_EEPROM_UPDATE mentioned",
			stderr:   "CM4_ENABLE_RPI_EEPROM_UPDATE",
			expected: true,
		},
		{
			name:     "CM4 but not EEPROM error",
			stderr:   "Some CM4 related message",
			expected: false,
		},
		{
			name:     "Empty stderr",
			stderr:   "",
			expected: false,
		},
		{
			name:     "Other error",
			stderr:   "Some other error message",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsCM4EEPROMError(tt.stderr)
			if result != tt.expected {
				t.Errorf("IsCM4EEPROMError(%q) = %v, expected %v", tt.stderr, result, tt.expected)
			}
		})
	}
}
