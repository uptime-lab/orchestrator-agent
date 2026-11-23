//go:build linux

package handlers

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	proto "agent/pkg/infrastructure/grpc/proto"
	"agent/pkg/infrastructure/hardware"
)

// The locate blink. Contract with the platform (see IdentifyCommand in the
// proto): report terminal SUCCESS immediately after STARTING the blink — a
// command held in_progress for the blink duration would pin the node in
// `maintenance` exactly while an operator is trying to find it — and stop on
// a local timer. A repeat command replaces the running blink (restoring the
// LED first), which is how "extend" works without an unsettled command.

const (
	identifyMinSec     = 5
	identifyDefaultSec = 30
	identifyMaxSec     = 3600
	identifyHalfPeriod = 250 * time.Millisecond
)

// sysLEDCandidates: ACT is the activity LED on every recent Pi; led0 is its
// older name; PWR/led1 is the fallback where ACT is absent or hidden.
var sysLEDCandidates = []string{"ACT", "led0", "PWR", "led1"}

func (h *CommandHandler) handleIdentify(commandID string, cmd *proto.IdentifyCommand) error {
	// A stop is its own operation, reported immediately — the UI's off gesture
	// used to be spelled "identify for the 5-second minimum", which made the
	// LED of a NON-blinking node flash for five seconds on every off click.
	if cmd.Stop {
		h.StopIdentify()
		h.reportCommandStatus(commandID, "success", 100, "blink stopped")
		return nil
	}
	duration := time.Duration(cmd.DurationSec) * time.Second
	if cmd.DurationSec <= 0 {
		duration = identifyDefaultSec * time.Second
	}
	if duration < identifyMinSec*time.Second {
		duration = identifyMinSec * time.Second
	}
	if duration > identifyMaxSec*time.Second {
		duration = identifyMaxSec * time.Second
	}

	// The neopixel backend blinks the board's digital LEDs IN ADDITION to the
	// sysfs LED, never instead of it: the sys-led is the one renderer that
	// exists on every board, and a neopixel driver that cannot initialise
	// (non-RP1 module in the carrier, /dev/pio0 absent, PIO busy) must degrade
	// to the blink the operator already relies on, not to darkness. The
	// driver covers RP1 boards (Pi 5 / CM5) via /dev/pio0 and BCM2711 boards
	// (Pi 4 / CM4) via the PWM serializer; anything else degrades here.
	var neo hardware.NeoPixel
	neoNote := ""
	if cmd.Backend == "neopixel" && cmd.Gpio > 0 {
		// Pause BEFORE opening: the ambient indication loop holds the driver
		// (a PIO state machine / the PWM block) and must release it first.
		// A RUNNING blink's own handle must go too — on RP1 the claimed state
		// machine makes the second open fail, which turned the documented
		// "repeat to extend" gesture into a blink going dark mid-locate.
		h.pauseIndication()
		h.releaseIdentifyNeo()
		var err error
		neo, err = hardware.OpenNeoPixel(int(cmd.Gpio))
		if err != nil {
			neoNote = " (digital LEDs unavailable: " + err.Error() + ")"
			neo = nil
			// The blink proceeds sys-led-only; the chain stays the loop's.
			h.resumeIndication()
		}
	} else if cmd.Backend != "" && cmd.Backend != "sys-led" && cmd.Backend != "neopixel" {
		msg := fmt.Sprintf("identify backend %q is not supported by this agent", cmd.Backend)
		h.reportCommandStatus(commandID, "failed", 0, msg)
		return fmt.Errorf("%s", msg)
	}

	led, err := findSysLED("/sys/class/leds")
	if err != nil {
		if neo != nil {
			neo.Close()
		}
		h.resumeIndication()
		msg := "no controllable LED found on this device"
		h.reportCommandStatus(commandID, "failed", 0, msg)
		return fmt.Errorf("%s: %w", msg, err)
	}

	if err := h.startBlink(led, neo, identifyColor(cmd.Color), duration); err != nil {
		if neo != nil {
			neo.Close()
		}
		h.resumeIndication()
		msg := fmt.Sprintf("cannot start blink: %v", err)
		h.reportCommandStatus(commandID, "failed", 0, msg)
		return fmt.Errorf("%s", msg)
	}
	what := filepath.Base(led)
	if neo != nil {
		what += " + digital LEDs"
	}
	h.reportCommandStatus(commandID, "success", 100,
		fmt.Sprintf("blinking %s for %s%s", what, duration, neoNote))
	return nil
}

// identifyColor maps the platform's color name to RGB; blue is the default
// because it is what the blade's registry entry declares.
func identifyColor(name string) [3]uint8 {
	switch name {
	case "red":
		return [3]uint8{255, 0, 0}
	case "green":
		return [3]uint8{0, 255, 0}
	case "white":
		return [3]uint8{255, 255, 255}
	default: // "", "blue"
		return [3]uint8{0, 0, 255}
	}
}

// identifyNeoLEDCount bounds how many chain positions each frame covers; the
// blade front carries a handful, extra words fall off the end of the chain.
const identifyNeoLEDCount = 8

// ButtonPress is the button watcher's local handler, and a press means one of
// two different things depending on what the node is doing:
//
//   - An identify blink is RUNNING: the press IS the acknowledgement — the
//     human found the machine — so the blink stops: once the button on the
//     blinking machine has been pressed, the blink has done its job and
//     further blinking is noise.
//   - Nothing is running: a short local ack blink — sys-led AND the digital
//     LEDs, from the identify spec persisted with the device profile — so the
//     human gets feedback even when the platform is unreachable.
func (h *CommandHandler) ButtonPress(duration time.Duration) string {
	h.identifyMu.Lock()
	running := h.identifyCancel != nil
	h.identifyMu.Unlock()
	if running {
		h.StopIdentify()
		return "blink_stopped"
	}
	led, err := findSysLED("/sys/class/leds")
	if err != nil {
		return "short"
	}
	var neo hardware.NeoPixel
	color := identifyColor("")
	if st := loadButtonState(); st.IdentifyBackend == "neopixel" && st.IdentifyGPIO > 0 {
		color = identifyColor(st.IdentifyColor)
		// Same ordering as handleIdentify: the indication loop (and any
		// previous blink) must release the driver before this open can claim it.
		h.pauseIndication()
		h.releaseIdentifyNeo()
		if opened, err := hardware.OpenNeoPixel(st.IdentifyGPIO); err == nil {
			neo = opened
		} else {
			h.resumeIndication()
		}
	}
	if err := h.startBlink(led, neo, color, duration); err != nil {
		if neo != nil {
			neo.Close()
		}
		h.resumeIndication()
		return "short"
	}
	return "blink_started"
}

// releaseIdentifyNeo closes a running blink's digital-LED handle (the blink
// itself keeps running sys-led-only until replaced or stopped). Needed before
// any new OpenNeoPixel: the old handle holds the hardware exclusively.
func (h *CommandHandler) releaseIdentifyNeo() {
	h.identifyMu.Lock()
	defer h.identifyMu.Unlock()
	if h.identifyNeo != nil {
		h.identifyNeo.Close()
		h.identifyNeo = nil
	}
}

// StopIdentify cancels a running blink and restores the LED synchronously —
// the shutdown path, where the restore goroutine would otherwise never run
// and the LED stayed dark until reboot.
func (h *CommandHandler) StopIdentify() {
	h.identifyMu.Lock()
	defer h.identifyMu.Unlock()
	if h.identifyCancel != nil {
		h.identifyCancel()
		h.identifyCancel = nil
	}
	h.restoreIdentifyLEDLocked()
	if h.identifyNeo != nil {
		h.identifyNeo.Close()
		h.identifyNeo = nil
	}
	h.resumeIndication()
}

// restoreIdentifyLEDLocked writes the pre-blink state back and marks it
// consumed. Caller holds identifyMu.
func (h *CommandHandler) restoreIdentifyLEDLocked() {
	if !h.identifySavedValid {
		return
	}
	restoreSysLED(h.identifyLED, h.identifySavedTrigger, h.identifySavedBrightness, writeSysfs)
	h.identifySavedValid = false
}

// startBlink replaces any running blink with a fresh one. The pre-blink LED
// state is saved ONCE, at the transition from not-blinking to blinking, and
// restored by whichever blink ends the run — a repeat command must not read
// the mid-blink "none" trigger as the state to restore (that lost the ACT
// LED's real trigger until reboot). Each blink carries a generation; a
// cancelled goroutine's deferred restore is a no-op unless it is still the
// current generation, so a late restore cannot fire into a newer blink.
func (h *CommandHandler) startBlink(led string, neo hardware.NeoPixel, color [3]uint8, duration time.Duration) error {
	h.identifyMu.Lock()
	defer h.identifyMu.Unlock()
	if h.identifyCancel != nil {
		h.identifyCancel()
		h.identifyCancel = nil
	}
	// A replaced blink hands its digital-LED client over: closing it here
	// (not in the dying goroutine) keeps exactly one /dev/pio0 client alive.
	if h.identifyNeo != nil {
		h.identifyNeo.Close()
		h.identifyNeo = nil
	}
	h.identifyNeo = neo

	if !h.identifySavedValid {
		savedTrigger, err := currentLEDTrigger(led)
		if err != nil {
			// Ownership of neo returns to the caller (which closes it once);
			// leaving the field set would point at a handle the caller has
			// already closed, and the BCM2711 Close is not idempotent.
			h.identifyNeo = nil
			return err
		}
		savedBrightness, _ := os.ReadFile(filepath.Join(led, "brightness"))
		h.identifyLED = led
		h.identifySavedTrigger = savedTrigger
		h.identifySavedBrightness = strings.TrimSpace(string(savedBrightness))
		h.identifySavedValid = true
	}

	// Manual toggle under trigger=none rather than the kernel "timer" trigger:
	// timer is a module (ledtrig-timer) not guaranteed present, and a blink
	// that silently does nothing defeats the whole feature.
	if err := writeSysfs(filepath.Join(led, "trigger"), "none"); err != nil {
		h.identifyNeo = nil
		return err
	}

	// Identify owns the digital chain for the blink's duration; the ambient
	// indication loop yields (and resumes from the restore below).
	h.pauseIndication()

	ctx, cancel := context.WithCancel(context.Background())
	h.identifyCancel = cancel
	h.identifyGen++
	gen := h.identifyGen
	go func() {
		defer func() {
			h.identifyMu.Lock()
			defer h.identifyMu.Unlock()
			// Only the blink that still OWNS the LED restores; a replaced one
			// leaves the saved state for its successor.
			if h.identifyGen != gen {
				return
			}
			h.identifyCancel = nil
			h.restoreIdentifyLEDLocked()
			if h.identifyNeo != nil {
				h.identifyNeo.Close()
				h.identifyNeo = nil
			}
			h.resumeIndication()
		}()
		deadline := time.NewTimer(duration)
		defer deadline.Stop()
		tick := time.NewTicker(identifyHalfPeriod)
		defer tick.Stop()
		on := false
		for {
			select {
			case <-ctx.Done():
				return
			case <-deadline.C:
				return
			case <-tick.C:
				// The digital LEDs run in ANTI-phase to the sysfs value on
				// purpose: the blade routes its ACT LED active-low, so writing
				// max brightness turns the green OFF — measured on the device,
				// where the in-phase version blinked green and
				// blue alternately. Every board that pairs a neopixel with the
				// sys-led today is that carrier; if a future board pairs them
				// active-high, this bit belongs in IdentifySpec, not here.
				val := "0"
				r, g, b := color[0], color[1], color[2]
				if !on {
					val = maxLEDBrightness(led)
					r, g, b = 0, 0, 0
				}
				on = !on
				// The digital write happens under identifyMu against the
				// HANDLER's handle, not the captured one: Close() also runs
				// under identifyMu (startBlink / StopIdentify / the defer
				// above), so a write can never race a close — on BCM2711 that
				// race read munmapped MMIO and killed the whole process. The
				// generation check stands the write down once replaced.
				//
				// The sysfs write is under the same lock and checks: a tick
				// that lost the race to a stop or a replace would otherwise
				// write brightness after the restore, and a brightness of 0
				// clears the trigger the restore just put back.
				h.identifyMu.Lock()
				if h.identifyGen == gen && ctx.Err() == nil {
					_ = writeSysfs(filepath.Join(led, "brightness"), val)
					if h.identifyNeo != nil {
						_ = h.identifyNeo.WriteFrame(identifyNeoLEDCount, r, g, b)
					}
				}
				h.identifyMu.Unlock()
			}
		}
	}()
	return nil
}

// findSysLED returns the first candidate LED directory that exists and has a
// writable brightness attribute.
func findSysLED(root string) (string, error) {
	for _, name := range sysLEDCandidates {
		dir := filepath.Join(root, name)
		if _, err := os.Stat(filepath.Join(dir, "brightness")); err == nil {
			return dir, nil
		}
	}
	// Any LED beats no LED: take the first entry with a brightness file.
	entries, err := os.ReadDir(root)
	if err != nil {
		return "", err
	}
	for _, e := range entries {
		dir := filepath.Join(root, e.Name())
		if _, err := os.Stat(filepath.Join(dir, "brightness")); err == nil {
			return dir, nil
		}
	}
	return "", fmt.Errorf("no entries under %s", root)
}

// currentLEDTrigger parses the [bracketed] active trigger from the trigger
// attribute ("none mmc0 [heartbeat] ..." -> "heartbeat").
func currentLEDTrigger(led string) (string, error) {
	raw, err := os.ReadFile(filepath.Join(led, "trigger"))
	if err != nil {
		return "", err
	}
	for _, tok := range strings.Fields(string(raw)) {
		if strings.HasPrefix(tok, "[") && strings.HasSuffix(tok, "]") {
			return strings.Trim(tok, "[]"), nil
		}
	}
	return "none", nil
}

// maxLEDBrightness reads max_brightness, defaulting to "1" (Pi status LEDs
// are on/off anyway).
func maxLEDBrightness(led string) string {
	raw, err := os.ReadFile(filepath.Join(led, "max_brightness"))
	if err != nil {
		return "1"
	}
	if v := strings.TrimSpace(string(raw)); v != "" {
		return v
	}
	return "1"
}

func writeSysfs(path, value string) error {
	return os.WriteFile(path, []byte(value), 0o644)
}
