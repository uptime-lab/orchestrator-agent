//go:build darwin

package handlers

import (
	"fmt"
	"time"

	proto "agent/pkg/infrastructure/grpc/proto"
)

// handleShutdown handles shutdown commands (noop for darwin)
func (h *CommandHandler) handleShutdown(commandID string, cmd *proto.ShutdownCommand) error {
	h.logger.Info("shutdown command received (noop on darwin)", "command_id", commandID, "delay_seconds", cmd.DelaySeconds)
	h.logger.Info("status update: shutting_down (noop)", "message", fmt.Sprintf("System would shutdown in %d seconds (not implemented on darwin)", cmd.DelaySeconds))
	return nil
}

// handleRestart handles restart commands (noop for darwin)
func (h *CommandHandler) handleRestart(commandID string, cmd *proto.RestartCommand) error {
	h.logger.Info("restart command received (noop on darwin)", "command_id", commandID, "delay_seconds", cmd.DelaySeconds)
	h.logger.Info("status update: restarting (noop)", "message", fmt.Sprintf("System would restart in %d seconds (not implemented on darwin)", cmd.DelaySeconds))
	return nil
}

// handleStatusCheck handles status check commands (noop for darwin)
func (h *CommandHandler) handleStatusCheck(commandID string, cmd *proto.StatusCheckCommand) error {
	h.logger.Info("status check command received (noop on darwin)", "command_id", commandID)
	h.logger.Info("status update: online (noop)", "message", "System status: online (not implemented on darwin)")
	return nil
}

// handleInstallOS handles OS installation commands (mock implementation for testing)
func (h *CommandHandler) handleInstallOS(commandID string, cmd *proto.InstallOSCommand) error {
	h.logger.Info("install OS command received (mock)",
		"command_id", commandID,
		"image_id", cmd.ImageId,
		"target_device", cmd.TargetDevice,
		"reboot", cmd.Reboot)

	// Send status update: installing
	// platformClient is guaranteed to be non-nil and implement the interface (set in constructor)
	if err := h.platformClient.SendStatusUpdate(h.nodeID, h.accountID, h.uniqueToken, "os_installing", "Starting OS installation"); err != nil {
		h.logger.Warn("failed to send status update", "error", err)
	}

	// Simulate installation process with sleep
	h.logger.Info("simulating OS installation (sleeping for 60 seconds)")
	time.Sleep(60 * time.Second)

	// Send status update: installation complete
	// platformClient is guaranteed to be non-nil and implement the interface (set in constructor)
	if cmd.Reboot {
		if err := h.platformClient.SendStatusUpdate(h.nodeID, h.accountID, h.uniqueToken, "restarting", "OS installation complete, rebooting"); err != nil {
			h.logger.Warn("failed to send status update", "error", err)
		}
	} else {
		if err := h.platformClient.SendStatusUpdate(h.nodeID, h.accountID, h.uniqueToken, "online", "OS installation complete"); err != nil {
			h.logger.Warn("failed to send status update", "error", err)
		}
	}

	h.logger.Info("install OS command executed successfully (mock)", "command_id", commandID)
	return nil
}
