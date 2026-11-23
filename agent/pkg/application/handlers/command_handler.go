package handlers

import (
	"context"
	"fmt"
	"log/slog"
	"runtime/debug"
	"sync"

	ports "agent/pkg/application/ports/out"
	"agent/pkg/domain/node"
	"agent/pkg/domain/refusal"
	proto "agent/pkg/infrastructure/grpc/proto"
	"agent/pkg/infrastructure/hardware"
)

// CommandHandler handles commands received from the platform
type CommandHandler struct {
	logger               *slog.Logger
	platformClient       ports.PlatformClient
	fileReader           *hardware.FileReader
	storageReader        *hardware.StorageReader
	hardwareInfoReporter func() error // Callback to trigger hardware info reporting
	nodeID               string
	accountID            string
	uniqueToken          string
	adoptionConfig       *node.AdoptionConfig
	// agentVersion is the RUNNING agent's version (ldflags), the floor for
	// the update_agent anti-rollback check.
	agentVersion string
	// adoptionFilePath is where this agent read its identity from. It is a
	// runtime flag, so the protected-path check cannot know it as a constant —
	// and deleting or overwriting that file de-adopts the node permanently.
	adoptionFilePath string
	// identify blink state: one blink at a time, a repeat command replaces the
	// running one. The pre-blink LED state is saved once at the transition
	// into blinking and restored by whichever blink ends the run (generation-
	// checked, so a replaced blink's late restore is a no-op). Guarded by
	// identifyMu.
	identifyMu              sync.Mutex
	identifyCancel          context.CancelFunc
	identifyGen             uint64
	identifyLED             string
	// identifyNeo is the digital-LED (WS2812 over RP1 PIO) client of the
	// RUNNING blink; nil on boards without one. Owned under identifyMu.
	identifyNeo             hardware.NeoPixel
	// ledMu serialises LED-config applies; led owns stealth, the sysfs LED
	// state and the ambient indication loop (see led_manager_linux.go).
	ledMu sync.Mutex
	led   *ledManager
	identifySavedTrigger    string
	identifySavedBrightness string
	identifySavedValid      bool
	// buttonReconfigure re-arms the physical-button watcher when an applied
	// device profile changes the button line (SetButtonReconfigure; linux
	// wiring only).
	buttonReconfigure func(gpio int)
}

// SetButtonReconfigure wires the button watcher's re-arm hook.
func (h *CommandHandler) SetButtonReconfigure(fn func(gpio int)) {
	h.buttonReconfigure = fn
}

// NewCommandHandler creates a new command handler
// platformClient must not be nil - it is required for command status reporting
func NewCommandHandler(logger *slog.Logger, platformClient ports.PlatformClient, nodeID, accountID, uniqueToken string) *CommandHandler {
	if platformClient == nil {
		panic("platformClient cannot be nil - it is required for command status reporting")
	}
	return &CommandHandler{
		logger:         logger,
		platformClient: platformClient,
		nodeID:         nodeID,
		accountID:      accountID,
		uniqueToken:    uniqueToken,
	}
}

// SetFileReader sets the file reader for handling file commands
func (h *CommandHandler) SetFileReader(reader *hardware.FileReader) {
	h.fileReader = reader
}

// SetStorageReader sets the storage reader for device validation
func (h *CommandHandler) SetStorageReader(reader *hardware.StorageReader) {
	h.storageReader = reader
}

// SetHardwareInfoReporter sets the callback to trigger hardware info reporting
func (h *CommandHandler) SetHardwareInfoReporter(reporter func() error) {
	h.hardwareInfoReporter = reporter
}

// SetAdoptionConfig sets the adoption config used for agent installation on new volumes
func (h *CommandHandler) SetAdoptionConfig(cfg *node.AdoptionConfig) {
	h.adoptionConfig = cfg
}

// HasAdoptionConfig reports whether an adoption config has been provided.
//
// Exists so the connect path can avoid REPLACING one. The identity handoff
// swaps in this node's own credential, and the connect path runs again on every
// reconnect with the config the process started from — which for a
// master-token session is the shared enrolment token. Since install_os writes
// whatever is here onto the disk it images, re-setting it would bake the shared
// token into the installed OS.
func (h *CommandHandler) HasAdoptionConfig() bool {
	return h.adoptionConfig != nil
}

// SetAdoptionFilePath records where the adoption file was read from, so file
// operations can refuse to touch it.
func (h *CommandHandler) SetAdoptionFilePath(path string) {
	h.adoptionFilePath = path
}

// SetAgentVersion sets the running agent's version (anti-rollback floor for
// self-update).
func (h *CommandHandler) SetAgentVersion(version string) {
	h.agentVersion = version
}

// reportCommandStatus reports command status and progress to the platform
// platformClient is guaranteed to be non-nil and implement the interface (set in constructor)
func (h *CommandHandler) reportCommandStatus(commandID, status string, progress int32, details string) {
	// Redact here, at the one place every handler passes through, rather than in
	// each message: the leak comes from Go's own *url.Error embedding the whole
	// URL, so it reappears in any handler that reports err.Error() on a request.
	details = redactURLsInText(details)
	if err := h.platformClient.SendCommandStatus(h.nodeID, h.accountID, h.uniqueToken, commandID, status, progress, details); err != nil {
		h.logger.Warn("failed to send command status update", "command_id", commandID, "status", status, "progress", progress, "error", err)
	} else {
		h.logger.Debug("command status update sent successfully", "command_id", commandID, "status", status, "progress", progress)
	}
}

// reportCommandResult reports a terminal command status carrying structured
// outputs (workflow blocks: read_file/wait_for_file/run_script).
func (h *CommandHandler) reportCommandResult(commandID, status, details string, result map[string]string) {
	// Same choke point as reportCommandStatus. The `result` map is NOT touched:
	// it is the block's declared output (a file's contents, a script's stdout),
	// the platform stores it as encv1: ciphertext and redacts it per caller, and
	// rewriting it here would corrupt the value a later block reads.
	details = redactURLsInText(details)
	if err := h.platformClient.SendCommandStatusWithResult(h.nodeID, h.accountID, h.uniqueToken, commandID, status, 100, details, result); err != nil {
		h.logger.Warn("failed to send command result", "command_id", commandID, "status", status, "error", err)
	}
}

// HandleCommand processes a command from the platform
func (h *CommandHandler) HandleCommand(command *proto.Command) (err error) {
	h.logger.Info("processing command", "command_id", command.CommandId, "issued_at", command.IssuedAt)

	// A panic inside a handler is reported as a FAILED command from HERE,
	// where the node identity needed for a status report exists. The client's
	// dispatch also recovers (platform_client.guarded) but can only log: a
	// command it swallowed silently stays in_progress until the platform's
	// 30-minute abandonment sweep — and that sweep deliberately EXCLUDES the
	// device-exclusive slugs (install_os, erase_drive, capture_image, the
	// offline applies), which it cannot tell from a legitimately long run. A
	// panic in one of those would have left the node in maintenance with the
	// exclusive lock held until someone restarted the agent by hand. The
	// message carries the panic value, never the
	// stack: the stack goes to the log, and the platform surfaces this text.
	defer func() {
		if r := recover(); r != nil {
			h.logger.Error("command handler panicked; reporting the command failed",
				"command_id", command.CommandId, "panic", fmt.Sprint(r), "stack", string(debug.Stack()))
			h.reportCommandResult(command.CommandId, "failed",
				fmt.Sprintf("the agent hit an internal error while executing this command: %v", r), nil)
			err = fmt.Errorf("command %s panicked: %v", command.CommandId, r)
		}
	}()

	switch cmd := command.CommandType.(type) {
	case *proto.Command_Shutdown:
		return h.handleShutdown(command.CommandId, cmd.Shutdown)
	case *proto.Command_Restart:
		return h.handleRestart(command.CommandId, cmd.Restart)
	case *proto.Command_StatusCheck:
		return h.handleStatusCheck(command.CommandId, cmd.StatusCheck)
	case *proto.Command_InstallOs:
		return h.handleInstallOS(command.CommandId, cmd.InstallOs)
	case *proto.Command_UpdateFile:
		return h.handleUpdateFile(command.CommandId, cmd.UpdateFile)
	case *proto.Command_UpdateBootOrder:
		return h.handleUpdateBootOrder(command.CommandId, cmd.UpdateBootOrder)
	case *proto.Command_InstallAgentOnVolume:
		return h.handleInstallAgentOnVolume(command.CommandId, cmd.InstallAgentOnVolume)
	case *proto.Command_ProvisionConnection:
		return h.handleProvisionConnection(command.CommandId, cmd.ProvisionConnection)
	case *proto.Command_EnableEeprom:
		return h.handleEnableEEPROM(command.CommandId, cmd.EnableEeprom)
	case *proto.Command_EraseDrive:
		return h.handleEraseDrive(command.CommandId, cmd.EraseDrive)
	case *proto.Command_UpdateAgent:
		return h.handleUpdateAgent(command.CommandId, cmd.UpdateAgent)
	case *proto.Command_SetHostname:
		return h.handleSetHostname(command.CommandId, cmd.SetHostname)
	case *proto.Command_ReleaseIdentity:
		return h.handleReleaseIdentity(command.CommandId, cmd.ReleaseIdentity)
	case *proto.Command_PatchFile:
		return h.handlePatchFile(command.CommandId, cmd.PatchFile)
	case *proto.Command_ReadFile:
		return h.handleReadFile(command.CommandId, cmd.ReadFile)
	case *proto.Command_WaitForFile:
		return h.handleWaitForFile(command.CommandId, cmd.WaitForFile)
	case *proto.Command_RunScript:
		return h.handleRunScript(command.CommandId, cmd.RunScript)
	case *proto.Command_ApplyAccessConfig:
		return h.handleApplyAccessConfig(command.CommandId, cmd.ApplyAccessConfig)
	case *proto.Command_ApplyAccessConfigOffline:
		return h.handleApplyAccessConfigOffline(command.CommandId, cmd.ApplyAccessConfigOffline)
	case *proto.Command_PatchFileOffline:
		return h.handlePatchFileOffline(command.CommandId, cmd.PatchFileOffline)
	case *proto.Command_CaptureImage:
		return h.handleCaptureImage(command.CommandId, cmd.CaptureImage)
	case *proto.Command_InstallPackages:
		return h.handleInstallPackages(command.CommandId, cmd.InstallPackages)
	case *proto.Command_ManageService:
		return h.handleManageService(command.CommandId, cmd.ManageService)
	case *proto.Command_DownloadFile:
		return h.handleDownloadFile(command.CommandId, cmd.DownloadFile)
	case *proto.Command_WriteFile:
		return h.handleWriteFile(command.CommandId, cmd.WriteFile)
	case *proto.Command_DeleteFile:
		return h.handleDeleteFile(command.CommandId, cmd.DeleteFile)
	case *proto.Command_ApplyWatchdogConfig:
		return h.handleApplyWatchdogConfig(command.CommandId, cmd.ApplyWatchdogConfig)
	case *proto.Command_ApplyDeviceProfile:
		return h.handleApplyDeviceProfile(command.CommandId, cmd.ApplyDeviceProfile)
	case *proto.Command_ApplyUtilityConfig:
		return h.handleApplyUtilityConfig(command.CommandId, cmd.ApplyUtilityConfig)
	case *proto.Command_ApplyLedConfig:
		return h.handleApplyLEDConfig(command.CommandId, cmd.ApplyLedConfig)
	case *proto.Command_Identify:
		return h.handleIdentify(command.CommandId, cmd.Identify)
	default:
		// Report failure so the platform doesn't leave the command hanging in
		// "sent" (which pins the node in "maintenance"). This happens when a
		// newer platform sends a command type this (older) agent can't decode.
		errMsg := "unknown or unsupported command type"
		h.reportCommandStatus(command.CommandId, "failed", 0, errMsg)
		return refusal.Wrap(fmt.Errorf("%s", errMsg))
	}
}
