//go:build !linux

package hardware

import "log/slog"

// ApplyRecoveryHostname is Linux-only; the netboot bootstrap never runs on
// other platforms.
func ApplyRecoveryHostname(_ *slog.Logger) {}
