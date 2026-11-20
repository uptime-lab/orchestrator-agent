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

// endSessionsOnce runs end for a locked user unless a previous apply already
// completed it for this lock, and records completion: an access apply repeats
// (self-healing, fleet re-dispatch), and the teardown belongs to the
// transition into the lock, not to every pass over a user who stays locked.
// An incomplete teardown is retried on the next apply. Unlocking clears the
// record, so the next lock tears down again.
func endSessionsOnce(st *accessUserState, end func() (killed int, done bool)) int {
	if st.SessionsEnded {
		return 0
	}
	killed, done := end()
	st.SessionsEnded = done
	return killed
}

// teardownScope decides which of a uid's processes belong to the host's user
// of that uid. A numeric uid is not an identity across namespaces: a container
// whose image runs as uid 1001 shows uid 1001 in the host's /proc, and it is not
// the managed user 1001. So a process is a candidate only when it is
//   - in the agent's own PID AND user namespace,
//   - not inside a container runtime's cgroup (a container sharing the host's
//     namespaces is still a container), and
//   - where systemd manages the host, inside the user's own slice
//     (user-<uid>.slice: their sessions and their user manager) — a positive
//     match, so a process of that uid somewhere else is left alone.
//
// Without systemd the namespace and container tests are all there is.
type teardownScope struct {
	procRoot string
	self     int
	systemd  bool
}

// pidsOwnedBy lists the live processes under procRoot whose real, effective,
// saved or filesystem uid is uid and that the scope attributes to the host's
// user. self is never listed, and neither is a zombie: it holds no resources
// and cannot be signalled further.
func (sc teardownScope) pidsOwnedBy(uid int) []int {
	entries, err := os.ReadDir(sc.procRoot)
	if err != nil {
		return nil
	}
	selfPID, selfUser := sc.namespaces(sc.self)
	var pids []int
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid <= 1 || pid == sc.self {
			continue
		}
		owned, zombie := procStatusOwnedBy(filepath.Join(sc.procRoot, e.Name(), "status"), uid)
		if !owned || zombie {
			continue
		}
		// An unreadable namespace (the process just exited, or the kernel has
		// no ns files) is not a match: the host's user is never assumed.
		pidNS, userNS := sc.namespaces(pid)
		if pidNS == "" || userNS == "" || pidNS != selfPID || userNS != selfUser {
			continue
		}
		if !sc.cgroupBelongsToUser(pid, uid) {
			continue
		}
		pids = append(pids, pid)
	}
	return pids
}

// namespaces returns the PID and user namespace identities of pid ("" when
// unreadable).
func (sc teardownScope) namespaces(pid int) (pidNS, userNS string) {
	dir := filepath.Join(sc.procRoot, strconv.Itoa(pid), "ns")
	pidNS, _ = os.Readlink(filepath.Join(dir, "pid"))
	userNS, _ = os.Readlink(filepath.Join(dir, "user"))
	return pidNS, userNS
}

// containerCgroupMarkers name the cgroup path components container runtimes
// create (docker-<id>.scope, cri-containerd-<id>.scope, kubepods.slice,
// libpod-<id>.scope, lxc.payload.<name>, crio-<id>.scope, machine.slice).
var containerCgroupMarkers = []string{"docker", "containerd", "kubepods", "libpod", "lxc", "crio", "machine.slice"}

// cgroupBelongsToUser reads /proc/<pid>/cgroup (v1 or v2). Any container
// runtime component rules the process out. Under systemd the process must also
// sit in user-<uid>.slice; an unreadable file is then not a match.
func (sc teardownScope) cgroupBelongsToUser(pid, uid int) bool {
	raw, err := os.ReadFile(filepath.Join(sc.procRoot, strconv.Itoa(pid), "cgroup"))
	if err != nil {
		return !sc.systemd
	}
	userSlice := "user-" + strconv.Itoa(uid) + ".slice"
	inUserSlice := false
	for _, line := range strings.Split(string(raw), "\n") {
		// hierarchy-ID:controllers:path — the path may itself hold ':'.
		parts := strings.SplitN(line, ":", 3)
		if len(parts) != 3 {
			continue
		}
		for _, comp := range strings.Split(parts[2], "/") {
			lc := strings.ToLower(comp)
			for _, m := range containerCgroupMarkers {
				if strings.Contains(lc, m) {
					return false
				}
			}
			if comp == userSlice {
				inUserSlice = true
			}
		}
	}
	return inUserSlice || !sc.systemd
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
