//go:build !linux

package hardware

import (
	"fmt"
	"log/slog"
)

// EEPROMAdoptionStorage reads adoption file content from EEPROM (stub for non-Linux)
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
func (e *EEPROMAdoptionStorage) ReadAdoptionFileFromDisk(path string) (string, error) {
	return "", fmt.Errorf("EEPROM adoption storage not supported on this platform")
}

// ReadAdoptionFileFromEEPROM reads the adoption file content from EEPROM
func (e *EEPROMAdoptionStorage) ReadAdoptionFileFromEEPROM() (string, error) {
	return "", fmt.Errorf("EEPROM adoption storage not supported on this platform")
}
