//go:build !linux

package hardware

import (
	"context"
	"log/slog"

	proto "agent/pkg/infrastructure/grpc/proto"
)

// SystemInfoReader collects system information (stub for non-Linux systems)
type SystemInfoReader struct {
	logger *slog.Logger
}

// NewSystemInfoReader creates a new system info reader (stub for non-Linux)
func NewSystemInfoReader(logger *slog.Logger) *SystemInfoReader {
	return &SystemInfoReader{
		logger: logger,
	}
}

// SystemInfoComponents holds the collected system information components
type SystemInfoComponents struct {
	Network  *proto.NetworkInfo
	Hardware *proto.HardwareInfo
	OS       *proto.OSInfo
}

// CollectSystemInfo collects system information (stub - returns empty components on non-Linux)
func (r *SystemInfoReader) CollectSystemInfo(ctx context.Context) (*SystemInfoComponents, error) {
	// Return empty components for non-Linux systems
	return &SystemInfoComponents{}, nil
}

// IsRaspberryPi checks if the system is a Raspberry Pi (stub - returns false on non-Linux)
func (r *SystemInfoReader) IsRaspberryPi() (bool, error) {
	return false, nil
}

// ReadThrottledFlags reports that this platform cannot answer. The agent's
// power watch treats `false` as "nothing to watch" and stops, so a non-Linux
// build costs nothing rather than polling a command that will never exist.
func (r *SystemInfoReader) ReadThrottledFlags(_ context.Context) (uint32, bool) {
	return 0, false
}
