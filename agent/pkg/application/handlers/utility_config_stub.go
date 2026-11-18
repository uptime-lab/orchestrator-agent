//go:build !linux

package handlers

import (
	"fmt"

	proto "agent/pkg/infrastructure/grpc/proto"
)

// handleApplyUtilityConfig applies utilities (stub for non-Linux).
func (h *CommandHandler) handleApplyUtilityConfig(commandID string, cmd *proto.ApplyUtilityConfigCommand) error {
	msg := "utilities are not supported on this platform"
	h.reportCommandResult(commandID, "failed", msg, nil)
	return fmt.Errorf("%s", msg)
}
