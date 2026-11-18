//go:build !linux

package hardware

import (
	"context"
)

// BootOrderReader reads boot order from Raspberry Pi EEPROM (stub for non-Linux)
type BootOrderReader struct{}

// NewBootOrderReader creates a new boot order reader
func NewBootOrderReader() *BootOrderReader {
	return &BootOrderReader{}
}

// GetBootOrderHex returns empty string on non-Linux systems
func (r *BootOrderReader) GetBootOrderHex(ctx context.Context) (string, error) {
	return "", nil
}

// GetBootOrder returns empty array on non-Linux systems
func (r *BootOrderReader) GetBootOrder(ctx context.Context) ([]string, error) {
	return []string{}, nil
}

