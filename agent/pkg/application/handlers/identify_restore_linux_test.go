//go:build linux

package handlers

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// An identify started while another is blinking must not take the blink's own
// state (trigger none) as the LED's original: whichever blink ends the run puts
// back the trigger the LED had before the FIRST one.
func TestIdentifyRepeatStartRestoresTheOriginalTrigger(t *testing.T) {
	led := t.TempDir()
	for name, content := range map[string]string{
		"trigger":        "none [mmc0] timer heartbeat\n",
		"brightness":     "0\n",
		"max_brightness": "1\n",
	} {
		if err := os.WriteFile(filepath.Join(led, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	h := &CommandHandler{}
	if err := h.startBlink(led, nil, [3]uint8{}, time.Minute); err != nil {
		t.Fatal(err)
	}
	// A plain file reads back "none" now: exactly the mid-blink state.
	if got := readFile(t, filepath.Join(led, "trigger")); strings.TrimSpace(got) != "none" {
		t.Fatalf("blink did not take the LED: trigger %q", got)
	}
	if err := h.startBlink(led, nil, [3]uint8{}, time.Minute); err != nil {
		t.Fatal(err)
	}
	h.StopIdentify()
	if got := readFile(t, filepath.Join(led, "trigger")); strings.TrimSpace(got) != "mmc0" {
		t.Fatalf("trigger after identify = %q, want the original mmc0", got)
	}
}
