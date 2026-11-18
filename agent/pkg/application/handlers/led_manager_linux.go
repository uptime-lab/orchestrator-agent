//go:build linux

package handlers

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/warthog618/go-gpiocdev"

	"agent/pkg/infrastructure/hardware"
)

// The LED manager owns the node's steady-state LED behaviour: stealth mode
// (blade GPIO21 transistor cuts every LED except the digital chain), ACT/PWR
// sysfs disable, and the ambient per-LED indication (temperature / load) on
// the digital chain. It persists the applied config so a reboot re-applies it
// with the platform unreachable, and it yields the digital chain to identify:
// a blink preempts indication, and indication resumes when the blink ends.

const (
	// LEDStateFile persists the applied config next to the button state.
	LEDStateFile = "/etc/orchestrator/led-config.json"

	ledIndicationPeriod = 3 * time.Second
)

// ledConfig is the persisted desired state (mirrors ApplyLEDConfigCommand).
type ledConfig struct {
	ConfigHash     string   `json:"config_hash"`
	StealthMode    bool     `json:"stealth_mode,omitempty"`
	ActLEDOff      bool     `json:"act_led_off,omitempty"`
	PwrLEDOff      bool     `json:"pwr_led_off,omitempty"`
	DigitalSources []string `json:"digital_sources,omitempty"`
	// DigitalLEDs is the LED v2 parameterized form; when present it wins over
	// DigitalSources (which older platforms keep sending alone).
	DigitalLEDs []ledSpec `json:"digital_leds,omitempty"`
	DigitalGPIO int       `json:"digital_gpio,omitempty"`
	StealthGPIO int       `json:"stealth_gpio,omitempty"`
}

// effectiveSpecs is the single render input, whichever form the config came
// in: v2 specs win, a bare v1 source list lifts into specs with defaults.
func (c ledConfig) effectiveSpecs() []ledSpec {
	if len(c.DigitalLEDs) > 0 {
		return c.DigitalLEDs
	}
	return specsFromSources(c.DigitalSources)
}

func (c ledConfig) wantsIndication() bool {
	for _, spec := range c.effectiveSpecs() {
		switch spec.Source {
		case "temperature", "load", "ram", "disk":
			return true
		}
	}
	return false
}

func (c ledConfig) isEmpty() bool {
	return !c.StealthMode && !c.ActLEDOff && !c.PwrLEDOff && !c.wantsIndication()
}

// ledManager applies and maintains the config. One per CommandHandler.
type ledManager struct {
	mu      sync.Mutex
	logger  interface{ Info(string, ...any) }
	cfg     ledConfig
	stealth *gpiocdev.Line

	loopCancel chan struct{}
	loopDone   chan struct{}
	paused     bool
	// neo is the indication loop's open driver handle, owned under mu so a
	// pause can close it SYNCHRONOUSLY: identify opens its own handle right
	// after pausing, and on RP1 the loop's still-claimed state machine made
	// that open fail (measured live: "claiming a state machine: operation not
	// permitted"). The loop reopens it lazily on resume.
	neo hardware.NeoPixel
}

// applyLEDConfig converges the device to cfg and persists it. Returns a
// human-readable summary of what was applied.
func (h *CommandHandler) applyLEDConfig(cfg ledConfig) (string, error) {
	h.ledMu.Lock()
	defer h.ledMu.Unlock()
	if h.led == nil {
		h.led = &ledManager{logger: h.logger}
	}
	m := h.led

	var parts []string

	// Stealth transistor first: it is the knob that cannot half-apply.
	if cfg.StealthMode {
		if cfg.StealthGPIO <= 0 {
			return "", fmt.Errorf("stealth mode requested but the device profile declares no stealth GPIO")
		}
		if err := m.setStealth(cfg.StealthGPIO, true); err != nil {
			return "", fmt.Errorf("engaging stealth: %w", err)
		}
		parts = append(parts, "stealth on")
	} else if m.stealth != nil || cfg.StealthGPIO > 0 {
		if err := m.setStealth(cfg.StealthGPIO, false); err != nil {
			return "", fmt.Errorf("releasing stealth: %w", err)
		}
		parts = append(parts, "stealth off")
	}

	// Sysfs LEDs. Under stealth these are dark anyway; the sysfs state is
	// still written so leaving stealth lands on the configured state.
	applySysLED := func(name string, off bool) {
		dir := filepath.Join("/sys/class/leds", name)
		if _, err := os.Stat(filepath.Join(dir, "brightness")); err != nil {
			return // board has no such LED — not an error
		}
		if off {
			_ = writeSysfs(filepath.Join(dir, "trigger"), "none")
			_ = writeSysfs(filepath.Join(dir, "brightness"), "0")
			parts = append(parts, name+" off")
			return
		}
		// Restore the stock trigger. The kernel default differs per LED and
		// per DT; mmc0 (activity) and default-on (power) are the Pi's stock
		// pair and self-correct on the next boot regardless.
		def := "mmc0"
		if name == "PWR" || name == "led1" {
			def = "default-on"
		}
		_ = writeSysfs(filepath.Join(dir, "trigger"), def)
		_ = writeSysfs(filepath.Join(dir, "brightness"), maxLEDBrightness(dir))
	}
	// The previous config decides whether a restore is needed at all — a node
	// that never disabled its LEDs must not have its triggers rewritten.
	if cfg.ActLEDOff || m.cfg.ActLEDOff {
		applySysLED("ACT", cfg.ActLEDOff)
		applySysLED("led0", cfg.ActLEDOff)
	}
	if cfg.PwrLEDOff || m.cfg.PwrLEDOff {
		applySysLED("PWR", cfg.PwrLEDOff)
		applySysLED("led1", cfg.PwrLEDOff)
	}

	// Digital indication loop.
	m.stopLoopLocked()
	if cfg.wantsIndication() && cfg.DigitalGPIO > 0 {
		m.startLoopLocked(cfg)
		parts = append(parts, "indication "+strings.Join(cfg.DigitalSources, "/"))
	} else if cfg.DigitalGPIO > 0 {
		// No ambient sources: blank the chain once so a previous indication
		// (or a stray test frame) does not stay lit forever.
		if neo, err := hardware.OpenNeoPixel(cfg.DigitalGPIO); err == nil {
			_ = neo.WriteFrame(identifyNeoLEDCount, 0, 0, 0)
			_ = neo.Close()
		}
	}

	m.cfg = cfg
	if err := persistLEDConfig(cfg); err != nil {
		return "", fmt.Errorf("persisting led config: %w", err)
	}
	if len(parts) == 0 {
		parts = append(parts, "defaults restored")
	}
	return strings.Join(parts, ", "), nil
}

// setStealth drives (or releases) the stealth transistor line. The line is
// HELD while stealth is on — releasing a chardev line reverts it to input,
// which un-drives the transistor and turns the LEDs back on.
func (m *ledManager) setStealth(gpio int, on bool) error {
	if m.stealth != nil {
		// Drive the release value before closing so the transition is clean.
		_ = m.stealth.SetValue(0)
		_ = m.stealth.Close()
		m.stealth = nil
	}
	if !on {
		return nil
	}
	chip, err := findButtonChip()
	if err != nil {
		return fmt.Errorf("no gpiochip: %w", err)
	}
	line, err := gpiocdev.RequestLine(chip, gpio,
		gpiocdev.AsOutput(1),
		gpiocdev.WithConsumer("orchestrator-stealth"))
	if err != nil {
		return err
	}
	m.stealth = line
	return nil
}

// startLoopLocked launches the ambient indication goroutine. Caller holds
// h.ledMu via applyLEDConfig.
func (m *ledManager) startLoopLocked(cfg ledConfig) {
	cancel := make(chan struct{})
	done := make(chan struct{})
	m.loopCancel = cancel
	m.loopDone = done
	go func() {
		defer close(done)
		defer func() {
			m.mu.Lock()
			if m.neo != nil {
				_ = m.neo.WriteFrame(identifyNeoLEDCount, 0, 0, 0)
				_ = m.neo.Close()
				m.neo = nil
			}
			m.mu.Unlock()
		}()
		tick := time.NewTicker(ledIndicationPeriod)
		defer tick.Stop()
		var prevIdle, prevTotal uint64
		for {
			select {
			case <-cancel:
				return
			case <-tick.C:
			}
			// One render per tick, entirely under mu: pause closes the handle
			// synchronously from its own goroutine, so the loop must never
			// hold the handle outside the lock.
			m.mu.Lock()
			if m.paused {
				m.mu.Unlock()
				continue
			}
			if m.neo == nil {
				opened, err := hardware.OpenNeoPixel(cfg.DigitalGPIO)
				if err != nil {
					m.mu.Unlock()
					continue // driver busy or absent; try again next tick
				}
				m.neo = opened
			}
			colors := renderIndication(cfg.effectiveSpecs(), &prevIdle, &prevTotal)
			// The chain is wired opposite to how an operator counts the
			// blade's edge LEDs, so "LED 1" in the UI drives the LAST chain
			// position (a product decision).
			for i, j := 0, len(colors)-1; i < j; i, j = i+1, j-1 {
				colors[i], colors[j] = colors[j], colors[i]
			}
			if err := m.neo.WritePixels(colors); err != nil {
				_ = m.neo.Close()
				m.neo = nil
			}
			m.mu.Unlock()
		}
	}()
}

func (m *ledManager) stopLoopLocked() {
	if m.loopCancel != nil {
		close(m.loopCancel)
		<-m.loopDone
		m.loopCancel = nil
		m.loopDone = nil
	}
}

// pauseIndication / resumeIndication are the identify handshake. The pause
// RELEASES the loop's driver handle before returning, so the caller can open
// its own immediately after.
func (h *CommandHandler) pauseIndication() {
	h.ledMu.Lock()
	defer h.ledMu.Unlock()
	if h.led != nil {
		h.led.mu.Lock()
		h.led.paused = true
		if h.led.neo != nil {
			_ = h.led.neo.Close()
			h.led.neo = nil
		}
		h.led.mu.Unlock()
	}
}

func (h *CommandHandler) resumeIndication() {
	h.ledMu.Lock()
	defer h.ledMu.Unlock()
	if h.led != nil {
		h.led.mu.Lock()
		h.led.paused = false
		h.led.mu.Unlock()
	}
}

// persistLEDConfig writes (or clears) the local desired state.
func persistLEDConfig(cfg ledConfig) error {
	return persistLEDConfigTo(LEDStateFile, cfg)
}

// persistLEDConfigTo is the path-parameterized body, split out so the
// round-trip test can exercise the isEmpty/remove semantics without root.
func persistLEDConfigTo(path string, cfg ledConfig) error {
	if cfg.isEmpty() {
		err := os.Remove(path)
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	data, err := json.Marshal(cfg)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return atomicWriteFile(path, data, 0o644)
}

func loadLEDConfig() ledConfig {
	return loadLEDConfigFrom(LEDStateFile)
}

func loadLEDConfigFrom(path string) ledConfig {
	var cfg ledConfig
	raw, err := os.ReadFile(path)
	if err != nil {
		return cfg
	}
	_ = json.Unmarshal(raw, &cfg)
	return cfg
}

// StartLEDManager is the composition-root hook: re-applies the persisted LED
// config on agent start, so stealth and indication survive a reboot with the
// platform unreachable. Never fails the caller.
func (h *CommandHandler) StartLEDManager() {
	cfg := loadLEDConfig()
	if cfg.isEmpty() {
		return
	}
	if summary, err := h.applyLEDConfig(cfg); err != nil {
		h.logger.Warn("re-applying persisted led config failed", "error", err)
	} else {
		h.logger.Info("re-applied persisted led config", "state", summary)
	}
}
