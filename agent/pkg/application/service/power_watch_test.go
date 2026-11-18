package service

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"
)

// A recorder for the two functions the watch drives, so the test asserts on what
// it DID rather than on how it is wired.
type throttleFake struct {
	mu      sync.Mutex
	samples []struct {
		flags uint32
		ok    bool
	}
	next      int
	reports   int
	reportErr error
}

func (f *throttleFake) read(context.Context) (uint32, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.next >= len(f.samples) {
		// Hold the last value forever, so a test that over-ticks does not fall
		// off the end and invent a change.
		last := f.samples[len(f.samples)-1]
		return last.flags, last.ok
	}
	s := f.samples[f.next]
	f.next++
	return s.flags, s.ok
}

func (f *throttleFake) report(context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reports++
	return f.reportErr
}

func (f *throttleFake) reportCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.reports
}

func sample(flags uint32) struct {
	flags uint32
	ok    bool
} {
	return struct {
		flags uint32
		ok    bool
	}{flags, true}
}

func unreadable() struct {
	flags uint32
	ok    bool
} {
	return struct {
		flags uint32
		ok    bool
	}{0, false}
}

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// runWatch drives the loop until it has consumed its samples, then stops it.
func runWatch(t *testing.T, f *throttleFake) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	done := make(chan struct{})
	go func() {
		watchThrottling(ctx, f.read, f.report, time.Millisecond, quietLogger())
		close(done)
	}()

	deadline := time.After(time.Second)
	for {
		f.mu.Lock()
		consumed := f.next >= len(f.samples)
		f.mu.Unlock()
		if consumed {
			break
		}
		select {
		case <-deadline:
			t.Fatal("the watch never consumed its samples")
		case <-done:
			return
		case <-time.After(time.Millisecond):
		}
	}
	// Let a couple more ticks run so a spurious extra report would show up.
	time.Sleep(20 * time.Millisecond)
	cancel()
	<-done
}

// A healthy node must send NOTHING extra for its whole uptime. This is what
// makes a 60-second poll affordable: the cost is one vcgencmd fork a minute, not
// a system_info report a minute.
func TestPowerWatchIsSilentWhileTheMaskIsUnchanged(t *testing.T) {
	f := &throttleFake{samples: []struct {
		flags uint32
		ok    bool
	}{sample(0), sample(0), sample(0), sample(0)}}
	runWatch(t, f)

	if got := f.reportCount(); got != 0 {
		t.Errorf("reports = %d, want 0 — an unchanged mask must not re-report", got)
	}
}

// The case the whole thing exists for: a node that sags an hour into its uptime,
// on a connection that never breaks. Before this, the sticky bits sat set on the
// device and the platform kept showing the 0 captured at connect.
func TestPowerWatchReportsWhenUnderVoltageAppears(t *testing.T) {
	f := &throttleFake{samples: []struct {
		flags uint32
		ok    bool
	}{sample(0), sample(0), sample(0x50000), sample(0x50000), sample(0x50000)}}
	runWatch(t, f)

	if got := f.reportCount(); got != 1 {
		t.Errorf("reports = %d, want exactly 1 — reported on the change, silent while it persists", got)
	}
}

// Sticky bits only ever go up within a boot, so a sagging node produces a
// handful of reports, not a stream.
func TestPowerWatchReportsEachDistinctChange(t *testing.T) {
	f := &throttleFake{samples: []struct {
		flags uint32
		ok    bool
	}{sample(0), sample(0x1), sample(0x10001), sample(0x10001), sample(0x50001)}}
	runWatch(t, f)

	if got := f.reportCount(); got != 3 {
		t.Errorf("reports = %d, want 3", got)
	}
}

// The first reading is the baseline afterConnect already sent. Seeding from it
// is what stops every agent start from re-reporting once for nothing.
func TestPowerWatchTreatsTheFirstReadingAsABaseline(t *testing.T) {
	f := &throttleFake{samples: []struct {
		flags uint32
		ok    bool
	}{sample(0x50000), sample(0x50000), sample(0x50000)}}
	runWatch(t, f)

	if got := f.reportCount(); got != 0 {
		t.Errorf("reports = %d, want 0 — a node that was already throttled at connect has not changed", got)
	}
}

// Hardware that cannot answer must stop the watch outright: polling a command
// that will never exist is pure noise, and it is the normal state on anything
// that is not a Raspberry Pi.
func TestPowerWatchStopsWhenTheDeviceCannotAnswer(t *testing.T) {
	f := &throttleFake{samples: []struct {
		flags uint32
		ok    bool
	}{unreadable()}}

	done := make(chan struct{})
	go func() {
		watchThrottling(context.Background(), f.read, f.report, time.Millisecond, quietLogger())
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("the watch kept polling a device that cannot answer")
	}
	if got := f.reportCount(); got != 0 {
		t.Errorf("reports = %d, want 0", got)
	}
}

// A failed report must not be retried on the next tick: a disconnected node
// would then re-report every minute for as long as it is away, and its reconnect
// re-reports everything anyway.
func TestPowerWatchDoesNotRetryAFailedReport(t *testing.T) {
	f := &throttleFake{
		samples: []struct {
			flags uint32
			ok    bool
		}{sample(0), sample(0x50000), sample(0x50000), sample(0x50000), sample(0x50000)},
		reportErr: errors.New("not connected"),
	}
	runWatch(t, f)

	if got := f.reportCount(); got != 1 {
		t.Errorf("reports = %d, want 1 — the baseline advances even when the report fails", got)
	}
}

// A read that fails mid-run is skipped, not treated as a change to zero. The
// opposite would report "the supply recovered" every time vcgencmd hiccuped.
func TestPowerWatchIgnoresUnreadableSamplesMidRun(t *testing.T) {
	f := &throttleFake{samples: []struct {
		flags uint32
		ok    bool
	}{sample(0x50000), unreadable(), unreadable(), sample(0x50000)}}
	runWatch(t, f)

	if got := f.reportCount(); got != 0 {
		t.Errorf("reports = %d, want 0 — a failed read is not a change", got)
	}
}
