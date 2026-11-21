//go:build linux

package handlers

import (
	"fmt"
	"os"
	"syscall"
	"time"
)

// dpkgLockFiles are the locks a package install needs: the frontend lock apt
// and unattended-upgrades hold for a whole run, and dpkg's own database lock.
// aptListsLockFiles adds the one `apt-get update` needs.
var (
	dpkgLockFiles     = []string{"/var/lib/dpkg/lock-frontend", "/var/lib/dpkg/lock"}
	aptListsLockFiles = append([]string{"/var/lib/apt/lists/lock"}, dpkgLockFiles...)
)

// packageLockHolder describes the process holding any of paths, "" when none
// is held. It asks with F_GETLK, which reports the holder without taking
// the lock, so probing never competes with the package manager it waits for.
// A lock the probe cannot inspect counts as free: the attempt that follows
// then reports the real state.
func packageLockHolder(paths []string) string {
	for _, path := range paths {
		if pid, held := fcntlLockHolder(path); held {
			cmdline, _ := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
			return describeLockHolder(pid, cmdline)
		}
	}
	return ""
}

func fcntlLockHolder(path string) (pid int, held bool) {
	f, err := os.Open(path)
	if err != nil {
		return 0, false
	}
	defer f.Close()
	lk := syscall.Flock_t{Type: syscall.F_WRLCK, Whence: 0, Start: 0, Len: 0}
	if err := syscall.FcntlFlock(f.Fd(), syscall.F_GETLK, &lk); err != nil {
		return 0, false
	}
	if lk.Type == syscall.F_UNLCK {
		return 0, false
	}
	return int(lk.Pid), true
}

// packageLockWaitFor is the production wait for one command: the real locks,
// the real clock, progress reported on the command. The caller sets locks and
// progress for each step before running it.
func (h *CommandHandler) packageLockWaitFor(commandID string) *packageLockWait {
	w := &packageLockWait{
		now:         time.Now,
		sleep:       time.Sleep,
		max:         packageLockWaitMax,
		poll:        packageLockPoll,
		reportEvery: packageLockReportEvery,
		locks:       dpkgLockFiles,
	}
	w.holder = func() string { return packageLockHolder(w.locks) }
	w.report = func(details string) {
		h.logger.Info("package manager lock is held, waiting", "command_id", commandID, "status", details)
		h.reportCommandStatus(commandID, "in_progress", w.progress, details)
	}
	return w
}
