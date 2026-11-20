package handlers

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Revoking or locking a managed user ends what that user already has running.
// Expiry, the nologin shell and the emptied key files stop NEW logins only: an
// open SSH session, a nohup'd process and a lingering `systemd --user` manager
// with its services all outlive them, so a revocation that stops there is not
// one.

// teardownSweeps bounds how often the remaining processes are swept. A process
// that forks between the listing and the kill is caught by the next sweep;
// one that is still there after the last sweep is reported, not chased forever.
const teardownSweeps = 5

// userTeardownOps are the host operations endUserSessions needs, injected so
// the policy is testable without a live logind.
type userTeardownOps struct {
	loginctl func(args ...string) error
	listPIDs func(uid int) []int
	kill     func(pid int) error
	settle   func()
}

// userTeardownResult is what one teardown did, for the command result.
type userTeardownResult struct {
	Killed   int
	Warnings []string
}

// endUserSessions disables the user's linger (so logind does not restart the
// user manager), terminates their sessions, then kills every process still
// owned by their uid. It refuses a system account outright — uid 0 above all —
// whatever the caller passed: this is the one place a mistake ends the host.
func endUserSessions(username string, uid int, ops userTeardownOps) (userTeardownResult, error) {
	var res userTeardownResult
	if username == "" || username == "root" || uid < minManagedUID {
		return res, fmt.Errorf("refusing to end the sessions of %q (uid %d): not a managed account", username, uid)
	}
	if err := ops.loginctl("disable-linger", username); err != nil {
		res.Warnings = append(res.Warnings, fmt.Sprintf("disable-linger: %v", err))
	}
	if err := ops.loginctl("terminate-user", username); err != nil {
		res.Warnings = append(res.Warnings, fmt.Sprintf("terminate-user: %v", err))
	}
	signalled := map[int]bool{}
	for sweep := 0; sweep < teardownSweeps; sweep++ {
		pids := ops.listPIDs(uid)
		if len(pids) == 0 {
			res.Killed = len(signalled)
			return res, nil
		}
		for _, pid := range pids {
			if err := ops.kill(pid); err == nil {
				signalled[pid] = true
			}
		}
		ops.settle()
	}
	res.Killed = len(signalled)
	if left := ops.listPIDs(uid); len(left) > 0 {
		return res, fmt.Errorf("%d process(es) of %s survived %d kill sweeps", len(left), username, teardownSweeps)
	}
	return res, nil
}

// pidsOwnedBy lists the live processes under procRoot whose real, effective,
// saved or filesystem uid is uid. self is never listed, and neither is a
// zombie: it holds no resources and cannot be signalled further.
func pidsOwnedBy(procRoot string, uid int, self int) []int {
	entries, err := os.ReadDir(procRoot)
	if err != nil {
		return nil
	}
	var pids []int
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid <= 1 || pid == self {
			continue
		}
		owned, zombie := procStatusOwnedBy(filepath.Join(procRoot, e.Name(), "status"), uid)
		if owned && !zombie {
			pids = append(pids, pid)
		}
	}
	return pids
}

// procStatusOwnedBy reads a /proc/<pid>/status file and reports whether any of
// its Uid fields is uid, and whether the process is a zombie.
func procStatusOwnedBy(path string, uid int) (owned, zombie bool) {
	f, err := os.Open(path)
	if err != nil {
		return false, false
	}
	defer f.Close()
	want := strconv.Itoa(uid)
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		switch {
		case strings.HasPrefix(line, "State:"):
			fields := strings.Fields(strings.TrimPrefix(line, "State:"))
			zombie = len(fields) > 0 && (fields[0] == "Z" || fields[0] == "X")
		case strings.HasPrefix(line, "Uid:"):
			for _, id := range strings.Fields(strings.TrimPrefix(line, "Uid:")) {
				if id == want {
					owned = true
				}
			}
		}
	}
	return owned, zombie
}
