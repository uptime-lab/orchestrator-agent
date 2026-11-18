//go:build linux

package handlers

import (
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/warthog618/go-gpiocdev"

	ports "agent/pkg/application/ports/out"
)

// ButtonWatcher watches a physical button line (the blade's edge button on
// GPIO20) and reports presses to the platform as NodeEvents. Which line — if
// any — comes from the device profile the platform applied; it is persisted
// locally (ButtonStateFile) so the watcher survives agent restarts without
// waiting for a re-apply.
//
// The button is hardware in a human's hand: the kernel debounces the contact
// (10 ms), and the watcher additionally refuses to REPORT more than one press
// per second. The platform rate-limits again on its side — this end is a
// courtesy, that end is the guarantee. A press also blinks the local LED for
// two seconds as the immediate ack, so the human gets feedback even when the
// platform is unreachable.
const (
	ButtonStateFile    = "/etc/orchestrator/device-profile.json"
	buttonDebounce     = 10 * time.Millisecond
	buttonReportMinGap = time.Second
	// A press starts the SAME blink the UI's identify does — the button is a
	// rack-side toggle; a second press stops it. The DURATION comes from the
	// account setting persisted with the device profile; this constant is only
	// the fallback for a state file written before the field existed.
	buttonBlinkFallback = 30 * time.Second
	buttonEventType     = "button_press"
	// Press kinds carry the OUTCOME, not just the fact: the UI mirrors real
	// device state instead of parity-guessing (which inverted against reality
	// after any page refresh — measured on the device, both directions).
	buttonPressKindShort   = "short" // legacy / blink could not start
	buttonPressKindStarted = "blink_started"
	buttonPressKindStopped = "blink_stopped"
	// Edge-pair kinds (long/double press semantics). Reported IN
	// ADDITION to the outcome kinds above — the instant ack stays on the
	// falling edge, these describe the gesture once it is measurable.
	buttonPressKindLong   = "long"   // held >= buttonLongPressMin, known at release
	buttonPressKindDouble = "double" // second press within buttonDoubleWindow
)

// Gesture timing. The long threshold is well past any deliberate short press
// (measured presses land under 300 ms); the double window is the usual
// double-click envelope.
const (
	buttonLongPressMin = 1500 * time.Millisecond
	buttonDoubleWindow = 400 * time.Millisecond
)

// buttonState is the persisted desired state (a subset of the applied device
// profile the agent needs across restarts). The identify spec lives here so
// the button's LOCAL ack can render on the digital LEDs — the ack exists for
// exactly the moment the platform is unreachable, so it cannot be asked for
// at press time.
type buttonState struct {
	ButtonGPIO          int    `json:"button_gpio"`
	IdentifyBackend     string `json:"identify_backend,omitempty"`
	IdentifyGPIO        int    `json:"identify_gpio,omitempty"`
	IdentifyColor       string `json:"identify_color,omitempty"`
	IdentifyDurationSec int    `json:"identify_duration_sec,omitempty"`
}

// loadButtonState reads the persisted state; zero value when absent/corrupt.
func loadButtonState() buttonState {
	var st buttonState
	if data, err := os.ReadFile(ButtonStateFile); err == nil {
		_ = json.Unmarshal(data, &st)
	}
	return st
}

type ButtonWatcher struct {
	logger      *slog.Logger
	client      ports.PlatformClient
	nodeID      string
	accountID   string
	uniqueToken string

	// reconfMu serializes Reconfigure callers; mu guards the fields below and
	// is the one onEdge takes. They are separate because Line.Close blocks
	// until a running event handler returns — closing while holding the same
	// mutex onEdge wants is an AB-BA deadlock with a press in flight.
	reconfMu   sync.Mutex
	mu         sync.Mutex
	line       *gpiocdev.Line
	gpio       int
	lastReport time.Time
	// Edge-pair state: when the current press began (falling edge) and when
	// the previous one began, for long/double detection.
	pressStart     time.Time
	prevPressStart time.Time
	ack            func(duration time.Duration) string
}

// NewButtonWatcher builds the watcher; Start (or Reconfigure) arms it.
func NewButtonWatcher(logger *slog.Logger, client ports.PlatformClient, nodeID, accountID, uniqueToken string) *ButtonWatcher {
	return &ButtonWatcher{
		logger:      logger.With("component", "button_watcher"),
		client:      client,
		nodeID:      nodeID,
		accountID:   accountID,
		uniqueToken: uniqueToken,
	}
}

// SetAck wires the local press handler; it returns the outcome kind the
// press event reports.
func (w *ButtonWatcher) SetAck(ack func(duration time.Duration) string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.ack = ack
}

// Start reads the persisted state and arms the watcher if a button is
// declared. Never fails the caller: a device with no button (or no gpiochip)
// simply has no watcher.
func (w *ButtonWatcher) Start() {
	st := loadButtonState()
	if st.ButtonGPIO <= 0 {
		return
	}
	w.Reconfigure(st.ButtonGPIO)
}

// Reconfigure arms the watcher on a line (or disarms it for gpio <= 0),
// replacing any previous line. Called from the apply handler and from Start.
func (w *ButtonWatcher) Reconfigure(gpio int) {
	w.reconfMu.Lock()
	defer w.reconfMu.Unlock()

	// Detach under the state lock, close OUTSIDE it: Close waits for any
	// running onEdge to return, and onEdge's first act is taking w.mu.
	w.mu.Lock()
	old := w.line
	w.line = nil
	w.gpio = gpio
	w.mu.Unlock()
	if old != nil {
		_ = old.Close()
	}

	if gpio <= 0 {
		return
	}
	chip, err := findButtonChip()
	if err != nil {
		w.logger.Warn("no usable gpiochip for the button", "gpio", gpio, "error", err)
		return
	}
	// Pull-up, button to ground: pressed = falling edge.
	line, err := gpiocdev.RequestLine(chip, gpio,
		gpiocdev.AsInput,
		gpiocdev.WithPullUp,
		// Both edges: the falling edge is the press (instant ack), the rising
		// edge is the release that makes the press DURATION measurable.
		gpiocdev.WithBothEdges,
		gpiocdev.WithDebounce(buttonDebounce),
		gpiocdev.WithEventHandler(w.onEdge),
		gpiocdev.WithConsumer("orchestrator-button"),
	)
	if err != nil {
		w.logger.Warn("cannot watch button line", "chip", chip, "gpio", gpio, "error", err)
		return
	}
	w.mu.Lock()
	w.line = line
	w.mu.Unlock()
	w.logger.Info("watching physical button", "chip", chip, "gpio", gpio)
}

func (w *ButtonWatcher) onEdge(ev gpiocdev.LineEvent) {
	if ev.Type == gpiocdev.LineEventRisingEdge {
		w.onRelease()
		return
	}
	w.mu.Lock()
	now := time.Now()
	w.prevPressStart = w.pressStart
	w.pressStart = now
	isDouble := !w.prevPressStart.IsZero() && now.Sub(w.prevPressStart) <= buttonDoubleWindow
	if !isDouble && now.Sub(w.lastReport) < buttonReportMinGap {
		// The 1/s report gate — but a DOUBLE is the one gesture whose second
		// press legitimately lands inside it, so it passes as its own kind
		// instead of being swallowed.
		w.mu.Unlock()
		return
	}
	w.lastReport = now
	ack := w.ack
	w.mu.Unlock()

	if isDouble {
		// The second press of a double already toggled nothing locally (the
		// ack ran on the first); report the gesture and leave the blink as
		// the first press left it.
		if err := w.client.SendNodeEvent(w.nodeID, w.accountID, w.uniqueToken,
			buttonEventType, buttonPressKindDouble); err != nil {
			w.logger.Warn("failed to report button press", "error", err)
		}
		return
	}

	// Local action first: the human at the rack gets the blink (or the stop)
	// even when the platform is unreachable (the send below then drops
	// silently). The outcome rides the event so every browser mirrors what
	// actually happened on the device.
	duration := buttonBlinkFallback
	if st := loadButtonState(); st.IdentifyDurationSec >= 10 && st.IdentifyDurationSec <= 3600 {
		duration = time.Duration(st.IdentifyDurationSec) * time.Second
	}
	kind := buttonPressKindShort
	if ack != nil {
		kind = ack(duration)
	}
	if err := w.client.SendNodeEvent(w.nodeID, w.accountID, w.uniqueToken,
		buttonEventType, kind); err != nil {
		w.logger.Warn("failed to report button press", "error", err)
	}
}

// onRelease closes the edge pair: a press held past the long threshold is
// reported as its own gesture. The instant ack already ran on the falling
// edge — this only names what the hand did once the duration is a fact.
func (w *ButtonWatcher) onRelease() {
	w.mu.Lock()
	start := w.pressStart
	w.mu.Unlock()
	if start.IsZero() {
		return
	}
	if held := time.Since(start); held >= buttonLongPressMin {
		if err := w.client.SendNodeEvent(w.nodeID, w.accountID, w.uniqueToken,
			buttonEventType, buttonPressKindLong); err != nil {
			w.logger.Warn("failed to report button press", "error", err)
		}
	}
}

// StartButtonWatcher is the composition-root hook: builds the watcher, wires
// the local press handler and the apply handler's re-arm callback, and arms
// it from persisted state. Platform-split (no-op stub on !linux) so the
// shared main.go can call it unconditionally.
func StartButtonWatcher(logger *slog.Logger, client ports.PlatformClient, nodeID, accountID, uniqueToken string, h *CommandHandler) {
	w := NewButtonWatcher(logger, client, nodeID, accountID, uniqueToken)
	w.SetAck(h.ButtonPress)
	h.SetButtonReconfigure(w.Reconfigure)
	w.Start()
}

// persistButtonState writes (or clears) the local desired state; called from
// the apply handler with the payload's fields.
func persistButtonState(st buttonState) error {
	if st.ButtonGPIO <= 0 {
		err := os.Remove(ButtonStateFile)
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	data, err := json.Marshal(st)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(ButtonStateFile), 0o755); err != nil {
		return err
	}
	return atomicWriteFile(ButtonStateFile, data, 0o644)
}

// findButtonChip picks the gpiochip that carries the 40-pin header lines: the
// SoC pin controller ("pinctrl-bcm2711" on CM4/Pi 4, "pinctrl-rp1" on Pi 5 /
// CM5). Falls back to gpiochip0 when no label matches — correct on every Pi
// older than the Pi 5 family.
func findButtonChip() (string, error) {
	chips := gpiocdev.Chips()
	for _, name := range chips {
		c, err := gpiocdev.NewChip(name)
		if err != nil {
			continue
		}
		label := strings.ToLower(c.Label)
		_ = c.Close()
		if strings.Contains(label, "pinctrl") {
			return name, nil
		}
	}
	if len(chips) > 0 {
		return chips[0], nil
	}
	return "", os.ErrNotExist
}
