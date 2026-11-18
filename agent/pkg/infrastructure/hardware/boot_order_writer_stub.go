//go:build !linux

package hardware

import (
	"log/slog"
)

// BootOrderWriter holds Raspberry Pi EEPROM enablement fixes (stub for non-Linux)
type BootOrderWriter struct {
	logger *slog.Logger
}

// NewBootOrderWriter creates a new boot order writer
func NewBootOrderWriter(logger *slog.Logger) *BootOrderWriter {
	return &BootOrderWriter{
		logger: logger,
	}
}
