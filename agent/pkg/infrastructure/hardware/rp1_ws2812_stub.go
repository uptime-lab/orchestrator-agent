//go:build !linux

package hardware

import "fmt"

// WS2812 exists on non-Linux builds only so shared structs can carry the
// pointer; it can never be opened.
type WS2812 struct{}

func OpenWS2812(gpio int) (*WS2812, error) {
	return nil, fmt.Errorf("digital LEDs are not supported on this platform")
}

func (w *WS2812) WriteFrame(count int, r, g, b uint8) error { return nil }

func (w *WS2812) WritePixels(colors [][3]uint8) error { return nil }

func (w *WS2812) Close() error { return nil }
