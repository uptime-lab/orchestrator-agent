//go:build !linux

package hardware

import (
	"log/slog"
	"time"

	proto "agent/pkg/infrastructure/grpc/proto"
)

// MetricsReader is a no-op on non-Linux platforms (the agent only ships on
// Linux devices; darwin/windows builds exist for development).
type MetricsReader struct {
	logger *slog.Logger
}

func NewMetricsReader(logger *slog.Logger) *MetricsReader {
	return &MetricsReader{logger: logger}
}

// Read returns an empty sample (only a timestamp) off Linux.
func (r *MetricsReader) Read() *proto.MetricsUpdate {
	return &proto.MetricsUpdate{Timestamp: time.Now().Unix()}
}
