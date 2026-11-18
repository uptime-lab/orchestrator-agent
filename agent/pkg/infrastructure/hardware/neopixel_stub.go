//go:build !linux

package hardware

import "fmt"

// NeoPixel mirrors the linux interface so shared structs can carry it; it can
// never be opened on this platform.
type NeoPixel interface {
	WriteFrame(count int, r, g, b uint8) error
	WritePixels(colors [][3]uint8) error
	Close() error
}

func OpenNeoPixel(gpio int) (NeoPixel, error) {
	return nil, fmt.Errorf("digital LEDs are not supported on this platform")
}
