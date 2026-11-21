package handlers

import "path/filepath"

// restoreSysLED writes a saved sysfs LED state back. Kept build-tag-free so
// the order is unit tested on every platform.
//
// The kernel's LED class makes the order matter: writing a brightness of 0
// removes the active trigger, and leaving a trigger sets the brightness to 0.
// So a saved trigger is written LAST and alone — it then drives the
// brightness itself, and a snapshot of that value (usually 0 between two
// flashes of disk activity) written after it would clear it again. Only a
// saved "none" has a brightness of its own, written after "none" is in place.
func restoreSysLED(led, trigger, brightness string, write func(path, value string) error) {
	if trigger == "" {
		trigger = "none"
	}
	_ = write(filepath.Join(led, "trigger"), trigger)
	if trigger == "none" && brightness != "" {
		_ = write(filepath.Join(led, "brightness"), brightness)
	}
}
