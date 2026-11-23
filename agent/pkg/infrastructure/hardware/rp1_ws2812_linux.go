//go:build linux

package hardware

import (
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Minimal RP1 PIO client for driving WS2812 "neopixel" LEDs on Pi 5 / CM5,
// where the classic DMA+PWM trick from BCM2711 does not exist and the
// official path is the kernel's rp1-pio character device (/dev/pio0).
//
// The ioctl surface is transcribed from the kernel's own uapi
// (include/uapi/misc/rp1_pio_if.h, pulled from the running kernel's
// headers package — struct layouts and numbers are copied, not guessed). The
// PIO program is the canonical pico-examples ws2812 side-set program; its
// four opcodes were re-derived from the PIO instruction encoding and match
// the published compilation ({0x6221, 0x1123, 0x1400, 0xA442}), which is the
// cross-check that the encoding is right.
//
// Scope is deliberately identify-blink narrow: open, claim an SM, load the
// program at origin 0, point it at one GPIO, push frames, close. The driver
// cleans up a client's claims and programs when the fd closes, so teardown
// is the close.

const (
	rp1PioDevice   = "/dev/pio0"
	rp1GPIOFuncPIO = 7

	pioIocMagic = 102

	// RP1 clk_sys is 200 MHz; the ws2812 program spends 10 SM cycles per bit,
	// so a divider of 25 yields the standard 800 kHz bit rate.
	ws2812ClkdivInt = 25

	// wrap bounds of the 4-instruction program, loaded at origin 0.
	ws2812WrapBottom = 0
	ws2812WrapTop    = 3
)

// ws2812Program: .side_set 1; T1=2 T2=5 T3=3.
//
//	bitloop: out x, 1        side 0 [2]  ; 0x6221
//	         jmp !x, do_zero side 1 [1]  ; 0x1123
//	do_one:  jmp bitloop     side 1 [4]  ; 0x1400
//	do_zero: nop             side 0 [4]  ; 0xA442
var ws2812Program = [4]uint16{0x6221, 0x1123, 0x1400, 0xA442}

// C struct mirrors (layouts match rp1_pio_if.h; every field is naturally
// aligned, no hidden padding in the ones used here).

type rp1PioSmConfig struct {
	clkdiv    uint32
	execctrl  uint32
	shiftctrl uint32
	pinctrl   uint32
}

type rp1PioAddProgramArgs struct {
	numInstrs uint16
	origin    uint16
	instrs    [32]uint16
}

type rp1PioSmClaimArgs struct{ mask uint16 }

type rp1PioSmInitArgs struct {
	sm        uint16
	initialPC uint16
	config    rp1PioSmConfig
}

type rp1PioSmSetClkdivArgs struct {
	sm      uint16
	divInt  uint16
	divFrac uint8
	rsvd    uint8
}

type rp1PioSmSetPinsArgs struct {
	sm     uint16
	rsvd   uint16
	values uint32
	mask   uint32
}

type rp1PioSmSetPindirsArgs struct {
	sm   uint16
	rsvd uint16
	dirs uint32
	mask uint32
}

type rp1PioSmSetEnabledArgs struct {
	mask   uint16 // bitmask over SMs, not an index
	enable uint8
	rsvd   uint8
}

type rp1PioSmPutArgs struct {
	sm       uint16
	blocking uint8
	rsvd     uint8
	data     uint32
}

type rp1GpioInitArgs struct{ gpio uint16 }

type rp1GpioSetFunctionArgs struct {
	gpio uint16
	fn   uint16
}

// _IOW(type, nr, size) — write direction is 1<<30 on arm64.
func iow(nr uintptr, size uintptr) uintptr {
	return (1 << 30) | (size << 16) | (pioIocMagic << 8) | nr
}


// WS2812 drives one chain of addressable LEDs from a PIO state machine.
type WS2812 struct {
	f  *os.File
	sm uint16
}

func (w *WS2812) ioctl(req uintptr, arg unsafe.Pointer) (int, error) {
	r1, _, errno := unix.Syscall(unix.SYS_IOCTL, w.f.Fd(), req, uintptr(arg))
	if errno != 0 {
		return 0, errno
	}
	return int(r1), nil
}

// OpenWS2812 claims a state machine on /dev/pio0 and points the ws2812
// program at the given GPIO. Fails cleanly where the device is absent
// (non-RP1 boards) — callers treat that as "no neopixel here".
func OpenWS2812(gpio int) (*WS2812, error) {
	if gpio <= 0 || gpio > 27 {
		return nil, fmt.Errorf("gpio %d is outside the RP1 PIO range", gpio)
	}
	f, err := os.OpenFile(rp1PioDevice, os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("opening %s: %w", rp1PioDevice, err)
	}
	w := &WS2812{f: f}
	fail := func(step string, err error) (*WS2812, error) {
		f.Close()
		return nil, fmt.Errorf("%s: %w", step, err)
	}

	// Claim any free SM (mask over all four); the ioctl returns the index.
	claim := rp1PioSmClaimArgs{mask: 0xf}
	sm, err := w.ioctl(iow(20, unsafe.Sizeof(claim)), unsafe.Pointer(&claim))
	if err != nil {
		return fail("claiming a state machine", err)
	}
	w.sm = uint16(sm)

	// Load at origin 0: the jmp targets in the program are absolute, and the
	// identify blink is the only PIO client on these devices. A refusal here
	// (something else owns the instruction memory) fails the neopixel half
	// only — the sys-led blink still runs.
	prog := rp1PioAddProgramArgs{numInstrs: uint16(len(ws2812Program)), origin: 0}
	copy(prog.instrs[:], ws2812Program[:])
	if _, err := w.ioctl(iow(11, unsafe.Sizeof(prog)), unsafe.Pointer(&prog)); err != nil {
		return fail("loading the ws2812 program", err)
	}

	gpioInit := rp1GpioInitArgs{gpio: uint16(gpio)}
	if _, err := w.ioctl(iow(50, unsafe.Sizeof(gpioInit)), unsafe.Pointer(&gpioInit)); err != nil {
		return fail("initialising the gpio", err)
	}
	setFn := rp1GpioSetFunctionArgs{gpio: uint16(gpio), fn: rp1GPIOFuncPIO}
	if _, err := w.ioctl(iow(51, unsafe.Sizeof(setFn)), unsafe.Pointer(&setFn)); err != nil {
		return fail("routing the gpio to PIO", err)
	}
	pindirs := rp1PioSmSetPindirsArgs{sm: w.sm, dirs: 1 << uint(gpio), mask: 1 << uint(gpio)}
	if _, err := w.ioctl(iow(36, unsafe.Sizeof(pindirs)), unsafe.Pointer(&pindirs)); err != nil {
		return fail("setting the pin direction", err)
	}
	pins := rp1PioSmSetPinsArgs{sm: w.sm, values: 0, mask: 1 << uint(gpio)}
	if _, err := w.ioctl(iow(35, unsafe.Sizeof(pins)), unsafe.Pointer(&pins)); err != nil {
		return fail("clearing the pin", err)
	}

	cfg := rp1PioSmConfig{
		clkdiv: ws2812ClkdivInt << 16,
		// wrap_top<<12 | wrap_bottom<<7 (program sits at origin 0).
		execctrl: ws2812WrapTop<<12 | ws2812WrapBottom<<7,
		// FJOIN_TX (30) deepens the TX FIFO, PULL_THRESH=24 (29:25) autopulls
		// one GRB triplet, AUTOPULL (17); OUT_SHIFTDIR stays 0 = shift left,
		// MSB first — the order the LEDs expect.
		shiftctrl: 1<<30 | 24<<25 | 1<<17,
		// SIDESET_COUNT=1 (31:29), SIDESET_BASE=gpio (14:10).
		pinctrl: 1<<29 | uint32(gpio)<<10,
	}
	smInit := rp1PioSmInitArgs{sm: w.sm, initialPC: 0, config: cfg}
	if _, err := w.ioctl(iow(30, unsafe.Sizeof(smInit)), unsafe.Pointer(&smInit)); err != nil {
		return fail("initialising the state machine", err)
	}
	clkdiv := rp1PioSmSetClkdivArgs{sm: w.sm, divInt: ws2812ClkdivInt, divFrac: 0}
	if _, err := w.ioctl(iow(34, unsafe.Sizeof(clkdiv)), unsafe.Pointer(&clkdiv)); err != nil {
		return fail("setting the clock divider", err)
	}
	enable := rp1PioSmSetEnabledArgs{mask: 1 << w.sm, enable: 1}
	if _, err := w.ioctl(iow(37, unsafe.Sizeof(enable)), unsafe.Pointer(&enable)); err != nil {
		return fail("enabling the state machine", err)
	}
	return w, nil
}

// wireColorWord packs a color for the blade's digital LEDs. The chips take
// RED-GREEN-BLUE byte order, not the classic WS2812 GRB — measured (green
// sent in GRB order renders red) and confirmed against the Compute Blade
// project's compute-blade-agent HAL, which serializes Red, Green, Blue. Blue
// and white look identical in both orders, which is why every earlier visual
// validation missed it. If a future board carries GRB chips, the order
// belongs in IdentifySpec, not here.
func wireColorWord(r, g, b uint8) uint32 {
	return (uint32(r)<<16 | uint32(g)<<8 | uint32(b)) << 8
}

// WriteFrame pushes one color to `count` LEDs. r/g/b are 0-255; the chain
// latches on the idle gap after the last word (any inter-frame pause beyond
// ~50µs, which every blink interval clears by orders of magnitude).
func (w *WS2812) WriteFrame(count int, r, g, b uint8) error {
	word := wireColorWord(r, g, b)
	for i := 0; i < count; i++ {
		put := rp1PioSmPutArgs{sm: w.sm, blocking: 1, data: word}
		if _, err := w.ioctl(iow(41, unsafe.Sizeof(put)), unsafe.Pointer(&put)); err != nil {
			return fmt.Errorf("pushing led %d: %w", i, err)
		}
	}
	return nil
}

// WritePixels pushes an individual color per chain position (index = LED).
func (w *WS2812) WritePixels(colors [][3]uint8) error {
	for i, c := range colors {
		word := wireColorWord(c[0], c[1], c[2])
		put := rp1PioSmPutArgs{sm: w.sm, blocking: 1, data: word}
		if _, err := w.ioctl(iow(41, unsafe.Sizeof(put)), unsafe.Pointer(&put)); err != nil {
			return fmt.Errorf("pushing led %d: %w", i, err)
		}
	}
	return nil
}

// Close blanks the chain and releases everything — the driver frees the
// client's SM claim and program when the fd closes.
func (w *WS2812) Close() error {
	_ = w.WriteFrame(16, 0, 0, 0)
	return w.f.Close()
}
