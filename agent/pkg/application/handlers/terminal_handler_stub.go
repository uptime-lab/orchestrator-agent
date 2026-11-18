//go:build !linux

package handlers

import (
	"log/slog"

	proto "agent/pkg/infrastructure/grpc/proto"
)

// TerminalHandler is a no-op off Linux (the agent only ships on Linux devices;
// darwin/windows builds exist for development).
type TerminalHandler struct {
	logger     *slog.Logger
	sendClosed func(sessionID string, exitCode int32, errMsg string)
}

func NewTerminalHandler(
	logger *slog.Logger,
	_ func(sessionID string, data []byte),
	sendClosed func(sessionID string, exitCode int32, errMsg string),
) *TerminalHandler {
	return &TerminalHandler{logger: logger, sendClosed: sendClosed}
}

// Handle refuses any terminal open on unsupported platforms.
func (h *TerminalHandler) Handle(msg *proto.PlatformToNode) {
	if open := msg.GetTerminalOpen(); open != nil {
		h.sendClosed(open.GetSessionId(), 1, "terminal not supported on this platform")
	}
}

// CloseAllSessions mirrors the Linux implementation's signature; there are
// never sessions to close here. Without it the service package does not
// compile off Linux, which is where development builds run.
func (h *TerminalHandler) CloseAllSessions(reason string) {}
