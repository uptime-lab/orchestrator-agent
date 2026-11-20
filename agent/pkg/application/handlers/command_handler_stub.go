//go:build !linux

package handlers

import (
	"fmt"

	proto "agent/pkg/infrastructure/grpc/proto"
)

// handleUpdateFile handles file update commands (stub for non-Linux)
func (h *CommandHandler) handleUpdateFile(commandID string, cmd *proto.UpdateFileCommand) error {
	return fmt.Errorf("file update not supported on this platform")
}

// handlePatchFile handles managed-block file patch commands (stub for non-Linux)
func (h *CommandHandler) handlePatchFile(commandID string, cmd *proto.PatchFileCommand) error {
	return fmt.Errorf("file patching not supported on this platform")
}

// handleReadFile handles file read commands (stub for non-Linux)
func (h *CommandHandler) handleReadFile(commandID string, cmd *proto.ReadFileCommand) error {
	return fmt.Errorf("read_file not supported on this platform")
}

// handleWaitForFile handles wait-for-file commands (stub for non-Linux)
func (h *CommandHandler) handleWaitForFile(commandID string, cmd *proto.WaitForFileCommand) error {
	return fmt.Errorf("wait_for_file not supported on this platform")
}

// handleRunScript handles script execution commands (stub for non-Linux)
func (h *CommandHandler) handleRunScript(commandID string, cmd *proto.RunScriptCommand) error {
	return fmt.Errorf("run_script not supported on this platform")
}

// handleUpdateBootOrder handles boot order update commands (stub for non-Linux)
func (h *CommandHandler) handleUpdateBootOrder(commandID string, cmd *proto.UpdateBootOrderCommand) error {
	return fmt.Errorf("boot order update not supported on this platform")
}

// handleInstallAgentOnVolume handles agent installation on volume commands (stub for non-Linux)
func (h *CommandHandler) handleInstallAgentOnVolume(commandID string, cmd *proto.InstallAgentOnVolumeCommand) error {
	return fmt.Errorf("agent installation on volume not supported on this platform")
}

// handleUpdateAgent handles agent self-update commands (stub for non-Linux)
func (h *CommandHandler) handleUpdateAgent(commandID string, cmd *proto.UpdateAgentCommand) error {
	return fmt.Errorf("agent self-update not supported on this platform")
}

// handleProvisionConnection handles provision connection commands (stub for non-Linux)
func (h *CommandHandler) handleProvisionConnection(commandID string, cmd *proto.ProvisionConnectionCommand) error {
	return fmt.Errorf("provision connection not supported on this platform")
}

// handleEnableEEPROM handles enable EEPROM commands (stub for non-Linux)
func (h *CommandHandler) handleEnableEEPROM(commandID string, cmd *proto.EnableEEPROMCommand) error {
	return fmt.Errorf("enable EEPROM not supported on this platform")
}

// handleEraseDrive handles erase drive commands (stub for non-Linux)
func (h *CommandHandler) handleEraseDrive(commandID string, cmd *proto.EraseDriveCommand) error {
	return fmt.Errorf("erase drive not supported on this platform")
}

// handleSetHostname handles hostname change commands (stub for non-Linux)
func (h *CommandHandler) handleSetHostname(commandID string, cmd *proto.SetHostnameCommand) error {
	return fmt.Errorf("set hostname not supported on this platform")
}

// handleCaptureImage handles disk-capture commands (stub for non-Linux)
func (h *CommandHandler) handleCaptureImage(commandID string, cmd *proto.CaptureImageCommand) error {
	return fmt.Errorf("image capture not supported on this platform")
}

// handleInstallPackages handles package install commands (stub for non-Linux)
func (h *CommandHandler) handleInstallPackages(commandID string, cmd *proto.InstallPackagesCommand) error {
	return fmt.Errorf("install packages not supported on this platform")
}

// handleApplyDeviceProfile applies a device profile (stub for non-Linux)
func (h *CommandHandler) handleApplyDeviceProfile(commandID string, cmd *proto.ApplyDeviceProfileCommand) error {
	h.reportCommandStatus(commandID, "failed", 0, "device profiles are only supported on Linux nodes")
	return fmt.Errorf("device profiles not supported on this platform")
}

// StartRTCKeeper is a no-op off Linux: the hardware clock it seeds is reached
// through the Linux RTC ioctls.
func (h *CommandHandler) StartRTCKeeper() {}

// MigrateLegacyEnvironmentSecrets is a no-op off Linux: older agents wrote env
// secrets into /etc/environment on Linux only.
func (h *CommandHandler) MigrateLegacyEnvironmentSecrets() {}

// handleIdentify blinks the locate LED (stub for non-Linux)
func (h *CommandHandler) handleIdentify(commandID string, cmd *proto.IdentifyCommand) error {
	h.reportCommandStatus(commandID, "failed", 0, "identify is only supported on Linux nodes")
	return fmt.Errorf("identify not supported on this platform")
}

// handleManageService handles service management commands (stub for non-Linux)
func (h *CommandHandler) handleManageService(commandID string, cmd *proto.ManageServiceCommand) error {
	return fmt.Errorf("manage service not supported on this platform")
}

// handleDownloadFile handles file download commands (stub for non-Linux)
func (h *CommandHandler) handleDownloadFile(commandID string, cmd *proto.DownloadFileCommand) error {
	return fmt.Errorf("download file not supported on this platform")
}

// handleWriteFile handles arbitrary file write commands (stub for non-Linux)
func (h *CommandHandler) handleWriteFile(commandID string, cmd *proto.WriteFileCommand) error {
	return fmt.Errorf("write file not supported on this platform")
}

// handleDeleteFile handles file deletion commands (stub for non-Linux)
func (h *CommandHandler) handleDeleteFile(commandID string, cmd *proto.DeleteFileCommand) error {
	msg := "delete_file is only supported on Linux"
	h.reportCommandResult(commandID, "failed", msg, nil)
	return fmt.Errorf("%s", msg)
}

// handleApplyWatchdogConfig handles watchdog configuration (stub for non-Linux)
func (h *CommandHandler) handleApplyWatchdogConfig(commandID string, cmd *proto.ApplyWatchdogConfigCommand) error {
	msg := "apply_watchdog_config is only supported on Linux"
	h.reportCommandResult(commandID, "failed", msg, nil)
	return fmt.Errorf("%s", msg)
}

// CheckWatchdogBreaker is a no-op off Linux.
func (h *CommandHandler) CheckWatchdogBreaker() {}

// RunWatchdogBreakerGate is a no-op off Linux (exit 0: never block a start).
func RunWatchdogBreakerGate() int { return 0 }
