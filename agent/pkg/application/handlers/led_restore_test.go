package handlers

import (
	"path/filepath"
	"testing"
)

// fakeKernelLED models the two LED-class rules that make a restore's order
// matter: writing brightness 0 removes the active trigger, and leaving a
// trigger (writing "none" while one is active) sets the brightness to 0.
type fakeKernelLED struct {
	trigger    string
	brightness string
}

func (f *fakeKernelLED) write(path, value string) error {
	switch filepath.Base(path) {
	case "brightness":
		if value == "0" {
			f.trigger = "none"
		}
		f.brightness = value
	case "trigger":
		if value == "none" {
			if f.trigger != "none" {
				f.brightness = "0"
			}
			f.trigger = "none"
			return nil
		}
		f.trigger = value
	}
	return nil
}

// After an identify blink (trigger none, brightness toggled), the restore must
// leave the LED with the trigger it had before — including when the brightness
// saved alongside it was 0, which under the kernel's rules clears a trigger
// written before it.
func TestRestoreSysLEDLeavesTheSavedTrigger(t *testing.T) {
	cases := []struct {
		name               string
		savedTrigger       string
		savedBrightness    string
		wantTrigger        string
		wantBrightness     string
		checkBrightnessToo bool
	}{
		{name: "activity trigger saved while idle", savedTrigger: "mmc0", savedBrightness: "0", wantTrigger: "mmc0"},
		{name: "activity trigger saved while lit", savedTrigger: "mmc0", savedBrightness: "1", wantTrigger: "mmc0"},
		{name: "default-on", savedTrigger: "default-on", savedBrightness: "1", wantTrigger: "default-on"},
		{name: "manual on", savedTrigger: "none", savedBrightness: "1", wantTrigger: "none", wantBrightness: "1", checkBrightnessToo: true},
		{name: "manual off", savedTrigger: "none", savedBrightness: "0", wantTrigger: "none", wantBrightness: "0", checkBrightnessToo: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, blinkPhase := range []string{"0", "1"} {
				led := &fakeKernelLED{trigger: "none", brightness: blinkPhase}
				restoreSysLED("/sys/class/leds/ACT", tc.savedTrigger, tc.savedBrightness, led.write)
				if led.trigger != tc.wantTrigger {
					t.Fatalf("blink phase %s: trigger = %q, want %q", blinkPhase, led.trigger, tc.wantTrigger)
				}
				if tc.checkBrightnessToo && led.brightness != tc.wantBrightness {
					t.Fatalf("blink phase %s: brightness = %q, want %q", blinkPhase, led.brightness, tc.wantBrightness)
				}
			}
		})
	}
}
