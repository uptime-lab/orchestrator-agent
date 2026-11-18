//go:build linux

package handlers

import (
	proto "agent/pkg/infrastructure/grpc/proto"
)

// handleApplyLEDConfig converges the node's LED behaviour (stealth / ACT+PWR
// off / ambient indication) and persists it for boot re-apply. Wholesale like
// every other apply_*: the payload IS the desired state, so an empty command
// restores defaults.
func (h *CommandHandler) handleApplyLEDConfig(commandID string, cmd *proto.ApplyLEDConfigCommand) error {
	h.reportCommandStatus(commandID, "in_progress", 10, "Applying LED configuration")
	// A running identify blink is stopped FIRST: its end-of-blink restore
	// would otherwise rewrite the pre-blink sysfs state over what this apply
	// is about to write (silently reverting an ACT/PWR change the platform
	// records as converged), and its open driver handle would collide with
	// the blank/indication writes below. Stopping a locate blink because the
	// operator reconfigured the same LEDs is the honest order of precedence.
	h.StopIdentify()
	cfg := ledConfig{
		ConfigHash:     cmd.ConfigHash,
		StealthMode:    cmd.StealthMode,
		ActLEDOff:      cmd.ActLedOff,
		PwrLEDOff:      cmd.PwrLedOff,
		DigitalSources: cmd.DigitalSources,
		DigitalGPIO:    int(cmd.DigitalGpio),
		StealthGPIO:    int(cmd.StealthGpio),
	}
	for _, spec := range cmd.DigitalLeds {
		if spec == nil {
			continue
		}
		cfg.DigitalLEDs = append(cfg.DigitalLEDs, ledSpec{
			Source:     spec.Source,
			Low:        spec.Low,
			High:       spec.High,
			Brightness: int(spec.Brightness),
		})
	}
	summary, err := h.applyLEDConfig(cfg)
	if err != nil {
		h.reportCommandStatus(commandID, "failed", 0, "LED configuration failed: "+err.Error())
		return err
	}
	h.reportCommandResult(commandID, "success", "LED configuration applied: "+summary,
		map[string]string{"generation": cmd.ConfigHash})
	return nil
}
