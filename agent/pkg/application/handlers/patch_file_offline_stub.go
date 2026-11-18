//go:build !linux

package handlers

import (
	"fmt"

	proto "agent/pkg/infrastructure/grpc/proto"
)

// handlePatchFileOffline is unavailable off Linux: it mounts a partition of the
// target disk and edits the installed system's file through the mount. Reported
// as a clean failure so the platform does not leave the command hanging (which
// would pin the node in "maintenance").
func (h *CommandHandler) handlePatchFileOffline(commandID string, cmd *proto.PatchFileOfflineCommand) error {
	msg := "patch_file_offline is only supported on Linux nodes"
	h.reportCommandStatus(commandID, "failed", 0, msg)
	return fmt.Errorf("%s", msg)
}
