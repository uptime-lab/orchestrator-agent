package handlers

import (
	"fmt"

	"agent/pkg/application/config"
	proto "agent/pkg/infrastructure/grpc/proto"
)

// handleReleaseIdentity deletes this node's adoption file so the device returns
// to a clean, unadopted state.
//
// Dispatched when the platform deletes the node. Without it the device keeps
// retrying forever against a platform that no longer has a row for it: the
// adoption file still names a node_id that does not exist, so ConnectionInit is
// refused, and a network-first device cannot even reach recovery because
// HTTP-boot withholds an unknown serial. Such a device stays powered and on the
// network, invisible to the platform.
//
// Not platform-specific: it removes two files. It lives outside
// command_handler_linux.go for that reason — a Pi is not the only thing that can
// be deleted, and a stub returning "not supported on this platform" would leave a
// macOS or Windows agent stranded in exactly the way this fixes.
//
// The connection is deliberately NOT torn down afterwards. The platform deletes
// the node immediately after dispatching this, and a self-inflicted disconnect
// would race the very status report this is trying to send. The identity is gone
// from disk, so the next agent start finds no adoption file and waits to be
// adopted again.
func (h *CommandHandler) handleReleaseIdentity(commandID string, cmd *proto.ReleaseIdentityCommand) error {
	reason := cmd.GetReason()
	h.logger.Info("release identity command received", "command_id", commandID, "reason", reason)
	h.reportCommandStatus(commandID, "in_progress", 0, "Releasing this node's adoption identity")

	if h.adoptionFilePath == "" {
		// Nothing to release and nothing to guess at. Refusing beats deleting a
		// path this agent did not read its identity from.
		errMsg := "no adoption file path is configured, so there is no identity to release"
		h.reportCommandStatus(commandID, "failed", 0, errMsg)
		return fmt.Errorf("%s", errMsg)
	}

	parser := config.NewParserWithLogger(h.logger)
	if err := parser.ReleaseAdoption(h.adoptionFilePath, reason); err != nil {
		errMsg := fmt.Sprintf("failed to release the adoption identity: %v", err)
		h.reportCommandStatus(commandID, "failed", 0, errMsg)
		return fmt.Errorf("%s", errMsg)
	}

	h.reportCommandStatus(commandID, "success", 100,
		"Adoption identity released — this device is now unadopted and will wait to be adopted again")
	return nil
}
