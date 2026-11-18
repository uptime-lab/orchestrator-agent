//go:build !linux

package handlers

import (
	"fmt"

	proto "agent/pkg/infrastructure/grpc/proto"
)

// handleApplyAccessConfig is unavailable off Linux: the reconciler drives
// useradd/chage/visudo and sshd, none of which exist in a comparable form
// elsewhere. Reported as a clean failure so the platform does not leave the
// command hanging (which would pin the node in "maintenance").
func (h *CommandHandler) handleApplyAccessConfig(commandID string, cmd *proto.ApplyAccessConfigCommand) error {
	msg := "apply_access_config is only supported on Linux nodes"
	h.reportCommandStatus(commandID, "failed", 0, msg)
	return fmt.Errorf("%s", msg)
}

func (h *CommandHandler) handleApplyAccessConfigOffline(commandID string, cmd *proto.ApplyAccessConfigOfflineCommand) error {
	msg := "apply_access_config_offline is only supported on Linux nodes"
	h.reportCommandStatus(commandID, "failed", 0, msg)
	return fmt.Errorf("%s", msg)
}
