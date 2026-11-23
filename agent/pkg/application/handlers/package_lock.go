package handlers

import (
	"bytes"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// How long a package operation waits for another package manager to let go of
// the dpkg lock, and how it reports while it waits. Build-tag-free so the loop
// is unit tested on every platform with a fake clock and a fake lock.
//
// The bound is long because the usual holder is the distro's own first
// unattended-upgrades run on a freshly installed OS, which upgrades the whole
// image and can run well past the few minutes a later, incremental run takes.
// It is still a bound: the agent runs commands on ONE goroutine, so every
// minute here holds back every other command for the node. Progress is
// reported once a minute, so the platform's silence sweep (which fails a
// command it has not heard from in 30 minutes) never mistakes the wait for a
// lost command. The holder is never killed: it may be halfway through
// unpacking, and interrupting dpkg there is what breaks a system.
const (
	packageLockWaitMax     = 25 * time.Minute
	packageLockPoll        = 10 * time.Second
	packageLockReportEvery = time.Minute
)

// packageLockWait retries a package operation while the dpkg lock is held.
// One value serves one command: a command that runs several package steps
// (apt-get update, then install) shares a single budget across them.
type packageLockWait struct {
	// holder describes the process holding the lock ("unattended-upgrade
	// (pid 1234)"), "" when the lock is free.
	holder func() string
	now    func() time.Time
	sleep  func(time.Duration)
	// report receives an in_progress message; it must reach the platform.
	report func(details string)

	max, poll, reportEvery time.Duration

	// locks and progress belong to the step being waited for: the lock files
	// the production probe inspects, and the percentage its reports carry.
	locks    []string
	progress int32

	started bool
	start   time.Time
}

// run calls attempt until it succeeds, fails for a reason other than the lock,
// or the lock is still held at the bound. attempt reports whether its failure
// was the lock. While the probe sees the lock held, attempt is not called at
// all; when attempt still loses a race for it, the loop simply goes round.
func (w *packageLockWait) run(attempt func() (lockBusy bool, err error)) error {
	if !w.started {
		w.start, w.started = w.now(), true
	}
	var lastReport time.Time
	reported := false
	var lastErr error
	for {
		holder := w.holder()
		if holder == "" {
			busy, err := attempt()
			if err == nil || !busy {
				return err
			}
			lastErr = err
			if holder = w.holder(); holder == "" {
				holder = "another process"
			}
		}
		waited := w.now().Sub(w.start)
		if waited >= w.max {
			return &packageLockTimeoutError{holder: holder, waited: w.max, last: lastErr}
		}
		if !reported || w.now().Sub(lastReport) >= w.reportEvery {
			w.report(fmt.Sprintf("Waiting for the package manager lock, held by %s: %s so far, at most %s",
				holder, waited.Truncate(time.Second), w.max))
			lastReport = w.now()
			reported = true
		}
		w.sleep(w.poll)
	}
}

// packageLockTimeoutError is the final word on a wait that ran out: it names
// the holder and tells the operator to retry, since nothing was installed.
type packageLockTimeoutError struct {
	holder string
	waited time.Duration
	last   error
}

func (e *packageLockTimeoutError) Error() string {
	msg := fmt.Sprintf("the package manager lock was still held by %s after %s, so nothing was installed; "+
		"retry once it has finished (on a freshly installed OS this is usually the first automatic upgrade run)",
		e.holder, e.waited)
	if e.last != nil {
		msg += fmt.Sprintf(" (last attempt: %v)", e.last)
	}
	return msg
}

func (e *packageLockTimeoutError) Unwrap() error { return e.last }

// describeLockHolder names a process from its /proc/<pid>/cmdline: the script
// when the program is an interpreter (unattended-upgrade runs as python3), the
// module for `python3 -m`, the program otherwise. Code given inline (`-c`) is
// not a name: the holder is then the interpreter, and no part of the code is
// reported.
func describeLockHolder(pid int, cmdline []byte) string {
	if pid <= 0 {
		return "another process"
	}
	args := strings.Split(string(bytes.TrimRight(cmdline, "\x00")), "\x00")
	name := ""
	if len(args) > 0 && args[0] != "" {
		name = filepath.Base(args[0])
		if isInterpreter(name) {
			name = interpreterScriptName(name, args[1:])
		}
	}
	if name == "" {
		return "process " + strconv.Itoa(pid)
	}
	return fmt.Sprintf("%s (pid %d)", name, pid)
}

// interpreterScriptName returns what an interpreter invocation runs: the base
// name of its script, the module after `-m`, or the interpreter itself when
// the code comes inline from a `-c` option (alone or in a bundle such as
// `-ec`) or there is no script at all.
func interpreterScriptName(interpreter string, args []string) string {
	for i, a := range args {
		if a == "" {
			continue
		}
		if a == "--" {
			if i+1 < len(args) && args[i+1] != "" {
				return filepath.Base(args[i+1])
			}
			return interpreter
		}
		if strings.HasPrefix(a, "-") {
			if !strings.HasPrefix(a, "--") && strings.Contains(a[1:], "c") {
				return interpreter
			}
			if a == "-m" {
				if i+1 < len(args) && args[i+1] != "" {
					return filepath.Base(args[i+1])
				}
				return interpreter
			}
			continue
		}
		return filepath.Base(a)
	}
	return interpreter
}

func isInterpreter(name string) bool {
	for _, p := range []string{"python", "perl", "sh", "bash", "dash"} {
		if name == p || strings.HasPrefix(name, p) && strings.Trim(name[len(p):], "0123456789.") == "" {
			return true
		}
	}
	return false
}
