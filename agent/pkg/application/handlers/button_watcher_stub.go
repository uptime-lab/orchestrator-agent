//go:build !linux

package handlers

import (
	"log/slog"

	ports "agent/pkg/application/ports/out"
)

// StartButtonWatcher is linux-only; the physical button rides GPIO.
func StartButtonWatcher(_ *slog.Logger, _ ports.PlatformClient, _, _, _ string, _ *CommandHandler) {
}
