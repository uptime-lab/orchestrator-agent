package handlers

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// fakeLockClock drives packageLockWait on simulated time: the lock is held by
// `holder` until `releaseAt` (zero: forever), and every sleep advances the
// clock.
type fakeLockClock struct {
	now       time.Time
	releaseAt time.Time
	holder    string
	reports   []time.Time
	messages  []string
	attempts  int
}

func (f *fakeLockClock) wait() *packageLockWait {
	return &packageLockWait{
		holder: func() string {
			if f.releaseAt.IsZero() || f.now.Before(f.releaseAt) {
				return f.holder
			}
			return ""
		},
		now:   func() time.Time { return f.now },
		sleep: func(d time.Duration) { f.now = f.now.Add(d) },
		report: func(details string) {
			f.reports = append(f.reports, f.now)
			f.messages = append(f.messages, details)
		},
		max:         packageLockWaitMax,
		poll:        packageLockPoll,
		reportEvery: packageLockReportEvery,
	}
}

// longestSilence is the largest gap between consecutive progress reports,
// counted from the start of the wait.
func (f *fakeLockClock) longestSilence(start time.Time) time.Duration {
	var longest time.Duration
	prev := start
	for _, at := range append(f.reports, f.now) {
		if gap := at.Sub(prev); gap > longest {
			longest = gap
		}
		prev = at
	}
	return longest
}

// The platform fails a command it has not heard from in 30 minutes; a lock
// wait reports far more often than that, and every report names the holder.
const commandSilenceSweep = 30 * time.Minute

// A first upgrade run on a fresh OS can hold the lock for many minutes. A wait
// of that length ends in an install, with progress reported all along.
func TestPackageLockWaitOutlastsALongHolder(t *testing.T) {
	start := time.Unix(0, 0)
	f := &fakeLockClock{now: start, releaseAt: start.Add(18 * time.Minute), holder: "unattended-upgrade (pid 42)"}
	err := f.wait().run(func() (bool, error) {
		f.attempts++
		return false, nil
	})
	if err != nil {
		t.Fatalf("wait for an 18-minute holder failed: %v", err)
	}
	if f.attempts != 1 {
		t.Fatalf("attempts = %d; the operation must not run while the lock is visibly held", f.attempts)
	}
	if s := f.longestSilence(start); s > packageLockReportEvery+packageLockPoll || s >= commandSilenceSweep {
		t.Fatalf("longest silence %s while waiting", s)
	}
	for _, m := range f.messages {
		if !strings.Contains(m, "unattended-upgrade (pid 42)") {
			t.Fatalf("progress report does not name the holder: %q", m)
		}
	}
}

// A holder that never lets go ends the wait at the bound, with a message that
// names it and tells the operator to retry — and the holder is left alone.
func TestPackageLockWaitGivesUpAtTheBoundNamingTheHolder(t *testing.T) {
	start := time.Unix(0, 0)
	f := &fakeLockClock{now: start, holder: "unattended-upgrade (pid 42)"}
	err := f.wait().run(func() (bool, error) {
		f.attempts++
		return true, errors.New("dpkg frontend lock was locked")
	})
	var timeout *packageLockTimeoutError
	if !errors.As(err, &timeout) {
		t.Fatalf("err = %v, want a lock timeout", err)
	}
	if f.attempts != 0 {
		t.Fatalf("attempts = %d while the lock was held", f.attempts)
	}
	if waited := f.now.Sub(start); waited < packageLockWaitMax || waited > packageLockWaitMax+packageLockPoll {
		t.Fatalf("gave up after %s, want %s", waited, packageLockWaitMax)
	}
	for _, want := range []string{"unattended-upgrade (pid 42)", "retry", packageLockWaitMax.String()} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("final message %q does not contain %q", err, want)
		}
	}
	if s := f.longestSilence(start); s > packageLockReportEvery+packageLockPoll {
		t.Fatalf("longest silence %s while waiting", s)
	}
}

// A failure that is not the lock is returned at once; nothing waits on it.
func TestPackageLockWaitReturnsOtherFailuresAtOnce(t *testing.T) {
	start := time.Unix(0, 0)
	f := &fakeLockClock{now: start, releaseAt: start}
	want := errors.New("unable to locate package")
	if err := f.wait().run(func() (bool, error) { f.attempts++; return false, want }); !errors.Is(err, want) {
		t.Fatalf("err = %v, want %v", err, want)
	}
	if f.attempts != 1 || !f.now.Equal(start) || len(f.reports) != 0 {
		t.Fatalf("attempts=%d slept=%s reports=%d", f.attempts, f.now.Sub(start), len(f.reports))
	}
}

// The probe can miss a holder that takes the lock between the probe and the
// attempt; the attempt's own lock error sends the loop round again.
func TestPackageLockWaitRetriesALostRace(t *testing.T) {
	start := time.Unix(0, 0)
	f := &fakeLockClock{now: start, releaseAt: start}
	err := f.wait().run(func() (bool, error) {
		f.attempts++
		if f.attempts == 1 {
			return true, errors.New("Could not get lock /var/lib/dpkg/lock-frontend")
		}
		return false, nil
	})
	if err != nil || f.attempts != 2 {
		t.Fatalf("err=%v attempts=%d", err, f.attempts)
	}
	if len(f.messages) != 1 || !strings.Contains(f.messages[0], "another process") {
		t.Fatalf("reports = %q", f.messages)
	}
}

// Steps of one command (apt-get update, then install) share one budget, so
// the command as a whole waits at most the bound.
func TestPackageLockWaitBudgetIsPerCommand(t *testing.T) {
	start := time.Unix(0, 0)
	f := &fakeLockClock{now: start, releaseAt: start.Add(20 * time.Minute), holder: "apt-get (pid 7)"}
	w := f.wait()
	if err := w.run(func() (bool, error) { return false, nil }); err != nil {
		t.Fatal(err)
	}
	f.releaseAt = time.Time{} // held again, for good
	err := w.run(func() (bool, error) { return false, nil })
	var timeout *packageLockTimeoutError
	if !errors.As(err, &timeout) {
		t.Fatalf("err = %v, want a lock timeout", err)
	}
	if total := f.now.Sub(start); total > packageLockWaitMax+packageLockPoll {
		t.Fatalf("command waited %s in total, bound is %s", total, packageLockWaitMax)
	}
}

func TestDescribeLockHolder(t *testing.T) {
	for _, tc := range []struct {
		pid     int
		cmdline string
		want    string
	}{
		{42, "/usr/bin/python3\x00/usr/bin/unattended-upgrade\x00--download-only\x00", "unattended-upgrade (pid 42)"},
		{42, "/usr/bin/python3.14\x00-u\x00/usr/bin/unattended-upgrade\x00", "unattended-upgrade (pid 42)"},
		{7, "/usr/bin/apt-get\x00install\x00-y\x00", "apt-get (pid 7)"},
		{7, "dpkg\x00--configure\x00-a\x00", "dpkg (pid 7)"},
		// Inline code is not a script name: the interpreter names the holder,
		// and nothing of the code reaches the report.
		{9, "python3\x00-c\x00import fcntl, time; f = open('/var/lib/dpkg/lock-frontend', 'w')\x00", "python3 (pid 9)"},
		{9, "/usr/bin/python3\x00-Bc\x00import time; time.sleep(60)\x00", "python3 (pid 9)"},
		{9, "/bin/sh\x00-c\x00apt-get install -y curl\x00", "sh (pid 9)"},
		{9, "/bin/bash\x00-ec\x00apt-get update\x00", "bash (pid 9)"},
		{9, "python3\x00-m\x00unattended_upgrade\x00", "unattended_upgrade (pid 9)"},
		{5, "", "process 5"},
		{0, "", "another process"},
		{-1, "x", "another process"},
	} {
		if got := describeLockHolder(tc.pid, []byte(tc.cmdline)); got != tc.want {
			t.Errorf("describeLockHolder(%d, %q) = %q, want %q", tc.pid, tc.cmdline, got, tc.want)
		}
	}
}
