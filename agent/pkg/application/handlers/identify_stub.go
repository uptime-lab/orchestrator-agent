//go:build !linux

package handlers

// StopIdentify restores the locate LED on shutdown; there is no LED to
// restore off-Linux.
func (h *CommandHandler) StopIdentify() {}
