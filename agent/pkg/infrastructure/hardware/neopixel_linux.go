//go:build linux

package hardware

import (
	"fmt"
	"os"
)

// NeoPixel is one chain of addressable digital LEDs, whatever silicon drives
// it. Both implementations blank the chain on Close.
type NeoPixel interface {
	WriteFrame(count int, r, g, b uint8) error
	// WritePixels sets an individual color per chain position.
	WritePixels(colors [][3]uint8) error
	Close() error
}

// OpenNeoPixel picks the WS2812 driver for the running SoC: the RP1 PIO
// character device on Pi 5 / CM5, the PWM serializer on BCM2711 (Pi 4 / CM4).
// Anything else fails cleanly — callers treat the error as "no digital LEDs
// here" and keep the sys-led blink.
func OpenNeoPixel(gpio int) (NeoPixel, error) {
	// The concrete pointers are unwrapped explicitly so an error never returns
	// a typed-nil pointer inside a non-nil interface.
	if _, err := os.Stat(rp1PioDevice); err == nil {
		w, err := OpenWS2812(gpio)
		if err != nil {
			return nil, err
		}
		return w, nil
	}
	if isBCM2711() {
		w, err := OpenBCM2711WS2812(gpio)
		if err != nil {
			return nil, err
		}
		return w, nil
	}
	return nil, fmt.Errorf("no digital-LED driver for this SoC (neither %s nor a BCM2711)", rp1PioDevice)
}
