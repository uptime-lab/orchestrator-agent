//go:build linux

package hardware

import (
	"encoding/binary"
	"fmt"
	"os"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// WS2812 driver for BCM2711 (Pi 4 / CM4), where there is no RP1 and therefore
// no /dev/pio0: the PWM peripheral in serializer mode shifts a pre-encoded
// bitstream out of GPIO18 (PWM0 channel 1, ALT5). Each WS2812 bit becomes
// three PWM sub-bits (1 -> 110, 0 -> 100) at ~2.45 MHz, which lands every
// phase inside the WS2812B timing windows. This is the same electrical trick
// rpi-ws281x uses, minus the DMA engine: a blade front carries a handful of
// LEDs, so a frame is ~22 FIFO words and the CPU feeds them faster than the
// serializer drains (13 µs/word) — a scheduling stall long enough to
// underrun (>50 µs) merely latches the frame early, and the next blink
// half-period rewrites it. Identify-blink cosmetics do not justify a DMA
// controller.
//
// Register access is /dev/mem MMIO. STRICT_DEVMEM allows it (these are device
// ranges, not system RAM), and the agent runs as root. The peripheral base is
// read from the device tree's /proc/device-tree/soc/ranges rather than
// hardcoded, because BCM2711 can run in low- or high-peripheral mode.
//
// One deliberate conflict: PWM0 channel 1 is also the analog-audio path. On a
// headless blade nothing plays audio; if something did, an identify blink
// wins the peripheral for its duration.

const (
	bcm2711Compatible = "bcm2711"

	gpioBlockOffset = 0x200000
	cmBlockOffset   = 0x101000
	pwmBlockOffset  = 0x20C000
	mmioBlockLen    = 4096

	// CM_PWM
	cmPasswd = 0x5A000000
	cmCTLOff = 0xA0 / 4
	cmDIVOff = 0xA4 / 4
	cmSrcOsc = 1
	cmEnab   = 1 << 4
	cmBusy   = 1 << 7
	// BCM2711's crystal is 54 MHz; /22 gives 2.4545 MHz sub-bit clock:
	// T0H 407 ns, T1H 815 ns, bit 1.22 µs — inside the WS2812B windows.
	cmDivi = 22

	// PWM
	pwmCTLOff  = 0x00 / 4
	pwmSTAOff  = 0x04 / 4
	pwmRNG1Off = 0x10 / 4
	pwmFIF1Off = 0x18 / 4
	pwmPWEN1   = 1 << 0
	pwmMODE1   = 1 << 1
	pwmUSEF1   = 1 << 5
	pwmCLRF1   = 1 << 6
	pwmFULL1   = 1 << 0
	pwmEMPT1   = 1 << 1
	pwmErrMask = 0x11C // WERR1|RERR1|GAPO1|BERR

	fifoFeedTimeout = 100 * time.Millisecond
)

// pwmGPIOAlt maps the GPIOs PWM0 channel 1 can reach to their ALT function
// value (GPFSEL 3-bit code). The blade's data line is 18.
var pwmGPIOAlt = map[int]uint32{
	18: 0b010, // ALT5
	12: 0b100, // ALT0
}

// BCM2711WS2812 drives one WS2812 chain from the PWM serializer.
type BCM2711WS2812 struct {
	memFile   *os.File
	gpioMap   []byte
	cmMap     []byte
	pwmMap    []byte
	gpio      []volatileU32
	cm        []volatileU32
	pwm       []volatileU32
	gpioPin   int
	savedFsel uint32
}

// volatileU32 exists to make the MMIO intent explicit at the type level; Go
// has no volatile, but 32-bit aligned loads/stores to mmapped device memory
// are single instructions on arm64 and the compiler cannot elide them across
// the function-call boundaries used here.
type volatileU32 = uint32

// isBCM2711 reports whether the running SoC is a BCM2711 (Pi 4 family).
func isBCM2711() bool {
	compat, err := os.ReadFile("/proc/device-tree/compatible")
	if err != nil {
		return false
	}
	return strings.Contains(string(compat), bcm2711Compatible)
}

// peripheralBase parses /proc/device-tree/soc/ranges for the physical address
// the bus window 0x7E000000 maps to (0xFE000000 in BCM2711's default
// low-peripheral mode). The cell layout varies (1 or 2 parent address cells),
// so it scans for the bus address and takes the first plausible parent.
func peripheralBase() (uint64, error) {
	raw, err := os.ReadFile("/proc/device-tree/soc/ranges")
	if err != nil {
		return 0, fmt.Errorf("reading soc/ranges: %w", err)
	}
	words := make([]uint32, len(raw)/4)
	for i := range words {
		words[i] = binary.BigEndian.Uint32(raw[i*4:])
	}
	for i, w := range words {
		if w != 0x7E000000 {
			continue
		}
		for _, cand := range words[i+1 : min(i+3, len(words))] {
			switch cand {
			case 0xFE000000, 0xF8000000, 0x3F000000, 0x20000000:
				return uint64(cand), nil
			}
		}
	}
	return 0, fmt.Errorf("no peripheral mapping for 0x7e000000 in soc/ranges")
}

// OpenBCM2711WS2812 maps the GPIO/clock/PWM blocks and configures the PWM
// serializer for the given GPIO. Fails cleanly on non-BCM2711 boards.
func OpenBCM2711WS2812(gpioPin int) (*BCM2711WS2812, error) {
	if !isBCM2711() {
		return nil, fmt.Errorf("not a BCM2711 board")
	}
	alt, ok := pwmGPIOAlt[gpioPin]
	if !ok {
		return nil, fmt.Errorf("gpio %d is not reachable by PWM0 channel 1 (need 18 or 12)", gpioPin)
	}
	base, err := peripheralBase()
	if err != nil {
		return nil, err
	}
	f, err := os.OpenFile("/dev/mem", os.O_RDWR|os.O_SYNC, 0)
	if err != nil {
		return nil, fmt.Errorf("opening /dev/mem: %w", err)
	}
	d := &BCM2711WS2812{memFile: f, gpioPin: gpioPin}
	fail := func(step string, err error) (*BCM2711WS2812, error) {
		d.unmapAll()
		f.Close()
		return nil, fmt.Errorf("%s: %w", step, err)
	}
	mmapBlock := func(off uint64) ([]byte, []volatileU32, error) {
		b, err := unix.Mmap(int(f.Fd()), int64(base+off), mmioBlockLen,
			unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
		if err != nil {
			return nil, nil, err
		}
		return b, unsafe.Slice((*volatileU32)(unsafe.Pointer(&b[0])), mmioBlockLen/4), nil
	}
	if d.gpioMap, d.gpio, err = mmapBlock(gpioBlockOffset); err != nil {
		return fail("mapping gpio block", err)
	}
	if d.cmMap, d.cm, err = mmapBlock(cmBlockOffset); err != nil {
		return fail("mapping clock block", err)
	}
	if d.pwmMap, d.pwm, err = mmapBlock(pwmBlockOffset); err != nil {
		return fail("mapping pwm block", err)
	}

	// Stop the PWM before touching its clock.
	d.pwm[pwmCTLOff] = 0
	time.Sleep(10 * time.Microsecond)

	// PWM clock: disable, wait not-busy, set divider, source = crystal, enable.
	d.cm[cmCTLOff] = cmPasswd | (d.cm[cmCTLOff] &^ cmEnab &^ cmPasswd)
	if err := d.waitCM(func(v uint32) bool { return v&cmBusy == 0 }); err != nil {
		return fail("stopping the pwm clock", err)
	}
	d.cm[cmDIVOff] = cmPasswd | cmDivi<<12
	d.cm[cmCTLOff] = cmPasswd | cmSrcOsc
	time.Sleep(10 * time.Microsecond)
	d.cm[cmCTLOff] = cmPasswd | cmSrcOsc | cmEnab
	if err := d.waitCM(func(v uint32) bool { return v&cmBusy != 0 }); err != nil {
		return fail("starting the pwm clock", err)
	}

	// Route the GPIO to the PWM, remembering the previous function.
	fselIdx := gpioPin / 10
	shift := uint((gpioPin % 10) * 3)
	d.savedFsel = d.gpio[fselIdx]
	d.gpio[fselIdx] = (d.savedFsel &^ (0b111 << shift)) | (alt << shift)

	// Serializer mode, FIFO-fed, 32-bit words, MSB first.
	d.pwm[pwmSTAOff] = pwmErrMask
	d.pwm[pwmCTLOff] = pwmCLRF1
	time.Sleep(10 * time.Microsecond)
	d.pwm[pwmRNG1Off] = 32
	d.pwm[pwmCTLOff] = pwmUSEF1 | pwmMODE1 | pwmPWEN1
	return d, nil
}

func (d *BCM2711WS2812) waitCM(done func(uint32) bool) error {
	deadline := time.Now().Add(50 * time.Millisecond)
	for !done(d.cm[cmCTLOff]) {
		if time.Now().After(deadline) {
			return fmt.Errorf("clock manager did not settle")
		}
		time.Sleep(10 * time.Microsecond)
	}
	return nil
}

// WriteFrame pushes one color to `count` LEDs, followed by the >50 µs low
// tail that latches the chain.
func (d *BCM2711WS2812) WriteFrame(count int, r, g, b uint8) error {
	colors := make([][3]uint8, count)
	for i := range colors {
		colors[i] = [3]uint8{r, g, b}
	}
	return d.WritePixels(colors)
}

// WritePixels pushes an individual color per chain position (index = LED).
func (d *BCM2711WS2812) WritePixels(colors [][3]uint8) error {
	var words []uint32
	var acc uint32
	bits := 0
	push := func(sub uint32, n int) {
		for i := n - 1; i >= 0; i-- {
			acc = acc<<1 | (sub>>uint(i))&1
			bits++
			if bits == 32 {
				words = append(words, acc)
				acc, bits = 0, 0
			}
		}
	}
	for _, c := range colors {
		// RGB byte order — the blade's chips, matching the RP1 driver's
		// wireColorWord (see the comment there for the evidence).
		rgb := uint32(c[0])<<16 | uint32(c[1])<<8 | uint32(c[2])
		for i := 23; i >= 0; i-- {
			if rgb>>uint(i)&1 == 1 {
				push(0b110, 3)
			} else {
				push(0b100, 3)
			}
		}
	}
	if bits > 0 {
		words = append(words, acc<<uint(32-bits))
	}
	// Latch tail: four zero words = 128 sub-bits ≈ 52 µs of line-low.
	words = append(words, 0, 0, 0, 0)

	deadline := time.Now().Add(fifoFeedTimeout)
	for _, w := range words {
		for d.pwm[pwmSTAOff]&pwmFULL1 != 0 {
			if time.Now().After(deadline) {
				return fmt.Errorf("pwm fifo did not drain")
			}
			// The FIFO drains a word every ~13 µs; yielding keeps a stopped
			// serializer from turning the timeout into a 100 ms one-core spin.
			time.Sleep(2 * time.Microsecond)
		}
		d.pwm[pwmFIF1Off] = w
	}
	return nil
}

// Close blanks the chain, releases the PWM and restores the GPIO function.
func (d *BCM2711WS2812) Close() error {
	_ = d.WriteFrame(identifyBlankLEDCount, 0, 0, 0)
	// Let the FIFO drain so the blank actually reaches the LEDs.
	deadline := time.Now().Add(fifoFeedTimeout)
	for d.pwm[pwmSTAOff]&pwmEMPT1 == 0 && time.Now().Before(deadline) {
		time.Sleep(100 * time.Microsecond)
	}
	time.Sleep(time.Millisecond)
	d.pwm[pwmCTLOff] = 0
	// Restore only OUR pin's 3 fsel bits: writing the whole Open-time snapshot
	// back would clobber whatever the other nine GPIOs in the register were
	// reconfigured to in between.
	fselIdx := d.gpioPin / 10
	shift := uint((d.gpioPin % 10) * 3)
	saved := (d.savedFsel >> shift) & 0b111
	d.gpio[fselIdx] = (d.gpio[fselIdx] &^ (0b111 << shift)) | (saved << shift)
	d.cm[cmCTLOff] = cmPasswd | (d.cm[cmCTLOff] &^ cmEnab &^ cmPasswd)
	d.unmapAll()
	return d.memFile.Close()
}

// identifyBlankLEDCount mirrors the RP1 driver's blank-on-close width.
const identifyBlankLEDCount = 16

func (d *BCM2711WS2812) unmapAll() {
	for _, m := range [][]byte{d.gpioMap, d.cmMap, d.pwmMap} {
		if m != nil {
			_ = unix.Munmap(m)
		}
	}
	d.gpioMap, d.cmMap, d.pwmMap = nil, nil, nil
	d.gpio, d.cm, d.pwm = nil, nil, nil
}
