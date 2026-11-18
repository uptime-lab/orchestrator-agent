//go:build linux

package handlers

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// rtcSeedTolerance is how far the hardware clock may sit from the system clock
// before we rewrite it. A second is the RTC's own resolution, so anything
// tighter would rewrite the chip on every check for no gain.
const rtcSeedTolerance = 2 * time.Second

// rtcKeeperRecheck is the idle cadence after a successful seed. The kernel
// rewrites rtc0 itself every ~11 minutes once the clock is disciplined
// (CONFIG_RTC_SYSTOHC), so this is a backstop for kernels and distributions
// where it is not configured — not a second implementation of it.
const rtcKeeperRecheck = 6 * time.Hour

// rtcKeeperSyncWait bounds the wait for an NTP client to discipline the clock.
// An agent that never sees a synchronized clock must stop asking rather than
// poll for the life of the process.
const rtcKeeperSyncWait = 15 * time.Minute

// StartRTCKeeper keeps a plug-in hardware clock holding a correct time, so the
// time survives a power cut.
//
// This is NOT the kernel's 11-minute write-back repeated — it is the FIRST
// write. Measured on a CM4 blade: the boot that
// first sees a freshly plugged DS3231 reads 2000-01-01 out of it and sets the
// system clock to that, 26 years backwards, so every TLS dial fails with
// "certificate is not yet valid" until an NTP client steps the clock — the same
// failure the recovery bootstrap's build-date clock once produced. Until
// something writes the module, that repeats on every boot, and a device powered
// off inside the kernel's 11-minute window boots into 2000-01-01 again. Seeding
// as soon as the clock is disciplined closes both.
func (h *CommandHandler) StartRTCKeeper() {
	dev, ok := externalRTCDevice()
	if !ok {
		return
	}
	go func() {
		// Deadline arithmetic on time.Time is monotonic in Go, which matters
		// more here than anywhere else in the agent: the clock this loop waits
		// for is about to be stepped by decades, and a wall-clock deadline
		// would expire the instant the step it is waiting for arrived.
		deadline := time.Now().Add(rtcKeeperSyncWait)
		for !systemClockSynchronized() {
			if time.Now().After(deadline) {
				h.logger.Warn("rtc keeper: system clock never became synchronized, leaving the hardware clock alone",
					"device", dev, "waited", rtcKeeperSyncWait.String())
				return
			}
			time.Sleep(30 * time.Second)
		}
		for {
			h.seedRTCOnce(dev)
			time.Sleep(rtcKeeperRecheck)
		}
	}()
}

// seedRTCOnce writes the system clock into the RTC when the two disagree. It
// refuses an undisciplined system clock: replacing a possibly-good hardware
// time with a definitely-bad one is worse than leaving the drift.
func (h *CommandHandler) seedRTCOnce(dev string) {
	if !systemClockSynchronized() {
		return
	}
	drift, err := rtcDrift(dev, time.Now())
	if err != nil {
		h.logger.Warn("rtc keeper: cannot read the hardware clock", "device", dev, "error", err)
		return
	}
	if !rtcNeedsSeeding(drift) {
		return
	}
	now := time.Now()
	if err := writeRTC(dev, now); err != nil {
		h.logger.Warn("rtc keeper: cannot set the hardware clock", "device", dev, "error", err)
		return
	}
	// Read back rather than trusting the write: a clone module that ACKs writes
	// it does not apply would otherwise look seeded forever, and the next power
	// cut is where that shows up.
	after, err := rtcDrift(dev, time.Now())
	if err != nil {
		h.logger.Warn("rtc keeper: cannot verify the hardware clock", "device", dev, "error", err)
		return
	}
	if rtcNeedsSeeding(after) {
		h.logger.Error("rtc keeper: the hardware clock did not take the write — the module will not keep time across a power cut",
			"device", dev, "drift_after_write", after.String())
		return
	}
	h.logger.Info("rtc keeper: hardware clock seeded from the system clock",
		"device", dev, "drift_before", drift.String(), "set_to", now.UTC().Format(time.RFC3339))
}

// rtcNeedsSeeding is the whole decision, kept separate so it is testable
// without an RTC: a drift in EITHER direction past the tolerance.
func rtcNeedsSeeding(drift time.Duration) bool {
	if drift < 0 {
		drift = -drift
	}
	return drift > rtcSeedTolerance
}

// externalRTCDevice reports the /dev/rtcN of a clock attached over I2C — the
// shape every plug-in module has. A board's BUILT-IN RTC (a Pi 5's
// "rpi-rtc soc@107c000000:rpi_rtc") is a platform device and is deliberately
// not matched: this keeper exists for the modules a device profile declares,
// and widening it would have every agent start rewriting the clock of hardware
// nobody asked us to manage.
func externalRTCDevice() (string, bool) {
	entries, err := os.ReadDir("/sys/class/rtc")
	if err != nil {
		return "", false
	}
	for _, e := range entries {
		name := e.Name()
		if !strings.HasPrefix(name, "rtc") {
			continue
		}
		target, err := filepath.EvalSymlinks("/sys/class/rtc/" + name + "/device/subsystem")
		if err != nil || filepath.Base(target) != "i2c" {
			continue
		}
		dev := "/dev/" + name
		if _, err := os.Stat(dev); err != nil {
			continue
		}
		return dev, true
	}
	return "", false
}

// systemClockSynchronized reports what timedatectl calls "System clock
// synchronized": the kernel's own view, set by whichever NTP client is running,
// rather than a guess from which daemon happens to be installed.
func systemClockSynchronized() bool {
	var tx unix.Timex
	state, err := unix.Adjtimex(&tx)
	if err != nil || state == unix.TIME_ERROR {
		return false
	}
	return tx.Status&unix.STA_UNSYNC == 0
}

// rtcInLocalTime reports whether this system keeps the RTC in local time. Then
// the RTC's fields are not UTC and both the comparison and the write below
// would be wrong by the UTC offset, so the keeper stands down instead.
// An absent /etc/adjtime means UTC, the Debian and Ubuntu default.
func rtcInLocalTime() bool {
	raw, err := os.ReadFile("/etc/adjtime")
	if err != nil {
		return false
	}
	return adjtimeSaysLocal(string(raw))
}

// adjtimeSaysLocal reads the third line of hwclock's adjtime file, which is
// literally "UTC" or "LOCAL".
func adjtimeSaysLocal(content string) bool {
	for _, line := range strings.Split(content, "\n") {
		if strings.EqualFold(strings.TrimSpace(line), "LOCAL") {
			return true
		}
	}
	return false
}

// rtcDrift returns now minus the hardware clock's reading.
func rtcDrift(dev string, now time.Time) (time.Duration, error) {
	hw, err := readRTC(dev)
	if err != nil {
		return 0, err
	}
	return now.Sub(hw), nil
}

func readRTC(dev string) (time.Time, error) {
	if rtcInLocalTime() {
		return time.Time{}, fmt.Errorf("this system keeps the hardware clock in local time; not touching it")
	}
	f, err := os.OpenFile(dev, os.O_RDONLY, 0)
	if err != nil {
		return time.Time{}, err
	}
	defer f.Close()
	t, err := unix.IoctlGetRTCTime(int(f.Fd()))
	if err != nil {
		return time.Time{}, err
	}
	return rtcTimeToTime(t), nil
}

func writeRTC(dev string, at time.Time) error {
	if rtcInLocalTime() {
		return fmt.Errorf("this system keeps the hardware clock in local time; not touching it")
	}
	f, err := os.OpenFile(dev, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	rt := timeToRTCTime(at)
	return unix.IoctlSetRTCTime(int(f.Fd()), &rt)
}

// rtcTimeToTime and timeToRTCTime convert the kernel's struct rtc_time, whose
// year is an offset from 1900 and whose month is zero-based — the two fields
// every hand-rolled conversion of this struct gets wrong.
func rtcTimeToTime(t *unix.RTCTime) time.Time {
	return time.Date(int(t.Year)+1900, time.Month(t.Mon+1), int(t.Mday),
		int(t.Hour), int(t.Min), int(t.Sec), 0, time.UTC)
}

func timeToRTCTime(at time.Time) unix.RTCTime {
	// Rounded, not truncated: the RTC holds whole seconds, and truncating
	// would bias every seed half a second slow.
	u := at.UTC().Round(time.Second)
	return unix.RTCTime{
		Sec:   int32(u.Second()),
		Min:   int32(u.Minute()),
		Hour:  int32(u.Hour()),
		Mday:  int32(u.Day()),
		Mon:   int32(u.Month() - 1),
		Year:  int32(u.Year() - 1900),
		Wday:  int32(u.Weekday()),
		Yday:  int32(u.YearDay() - 1),
		Isdst: 0,
	}
}
