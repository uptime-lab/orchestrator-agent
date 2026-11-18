//go:build !linux

package hardware

import "log/slog"

// CleanupStaleEEPROMArtifacts is Linux-only; EEPROM recovery packages only
// exist on Raspberry Pi boot media.
func CleanupStaleEEPROMArtifacts(_ *slog.Logger) {}
