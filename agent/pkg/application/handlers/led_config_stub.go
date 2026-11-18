//go:build !linux

package handlers

import (
	proto "agent/pkg/infrastructure/grpc/proto"
)

// ledManager exists on non-Linux builds only so the shared handler struct can
// carry the pointer; it can never be constructed.
type ledManager struct{}

func (h *CommandHandler) handleApplyLEDConfig(commandID string, cmd *proto.ApplyLEDConfigCommand) error {
	h.reportCommandStatus(commandID, "failed", 0, "LED configuration is not supported on this platform")
	return nil
}

// StartLEDManager is a no-op off Linux.
func (h *CommandHandler) StartLEDManager() {}

func (h *CommandHandler) pauseIndication()  {}
func (h *CommandHandler) resumeIndication() {}
