package handlers

import (
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
)

// fakeHost is a process table the teardown can see and shrink.
type fakeHost struct {
	procs    map[int]int // pid -> uid
	loginctl [][]string
	respawn  int // processes the user manager starts again after the first kill
}

func (f *fakeHost) ops() userTeardownOps {
	return userTeardownOps{
		loginctl: func(args ...string) error {
			f.loginctl = append(f.loginctl, args)
			return nil
		},
		listPIDs: func(uid int) []int {
			var out []int
			for pid, owner := range f.procs {
				if owner == uid {
					out = append(out, pid)
				}
			}
			sort.Ints(out)
			return out
		},
		kill: func(pid int) error {
			uid := f.procs[pid]
			delete(f.procs, pid)
			if f.respawn > 0 {
				f.respawn--
				f.procs[9000+pid] = uid
			}
			return nil
		},
		settle: func() {},
	}
}

// A revoked user's lingering manager, sessions and orphan processes all end;
// nobody else's do.
func TestEndUserSessionsKillsEverythingTheUserOwns(t *testing.T) {
	host := &fakeHost{procs: map[int]int{
		100: 1001, // systemd --user
		101: 1001, // a user service
		102: 1001, // an orphaned nohup process
		200: 1002, // another user
		300: 0,    // root
	}, respawn: 1}

	res, err := endUserSessions("contractor", 1001, host.ops())
	if err != nil {
		t.Fatal(err)
	}
	want := [][]string{{"disable-linger", "contractor"}, {"terminate-user", "contractor"}}
	if !reflect.DeepEqual(host.loginctl, want) {
		t.Fatalf("loginctl calls = %v, want %v", host.loginctl, want)
	}
	for pid, uid := range host.procs {
		if uid == 1001 {
			t.Fatalf("process %d of the revoked user survived", pid)
		}
	}
	if _, ok := host.procs[200]; !ok {
		t.Fatal("another user's process was killed")
	}
	if _, ok := host.procs[300]; !ok {
		t.Fatal("a root process was killed")
	}
	if res.Killed != 4 { // three, plus the one respawned between sweeps
		t.Fatalf("killed = %d, want 4", res.Killed)
	}
}

// Root and system accounts are never torn down, whatever the caller passes.
func TestEndUserSessionsRefusesSystemAccounts(t *testing.T) {
	for _, tc := range []struct {
		name string
		uid  int
	}{{"root", 0}, {"daemon", 1}, {"svc", minManagedUID - 1}, {"root", 1500}} {
		host := &fakeHost{procs: map[int]int{1: tc.uid, 50: tc.uid}}
		if _, err := endUserSessions(tc.name, tc.uid, host.ops()); err == nil {
			t.Fatalf("%s (uid %d): teardown was not refused", tc.name, tc.uid)
		}
		if len(host.procs) != 2 || len(host.loginctl) != 0 {
			t.Fatalf("%s (uid %d): refused teardown still acted", tc.name, tc.uid)
		}
	}
}

// fakeProc is a fabricated /proc tree: status, ns links and cgroup per pid.
type fakeProc struct {
	t    *testing.T
	root string
}

const (
	hostPIDNS  = "pid:[4026531836]"
	hostUserNS = "user:[4026531837]"
	userCgroup = "0::/user.slice/user-1001.slice/session-3.scope\n"
)

func newFakeProc(t *testing.T) *fakeProc {
	return &fakeProc{t: t, root: t.TempDir()}
}

func (f *fakeProc) add(pid, state, uids, pidNS, userNS, cgroup string) {
	f.t.Helper()
	dir := filepath.Join(f.root, pid)
	if err := os.MkdirAll(filepath.Join(dir, "ns"), 0o755); err != nil {
		f.t.Fatal(err)
	}
	body := "Name:\tx\nState:\t" + state + "\nUid:\t" + uids + "\nGid:\t0\t0\t0\t0\n"
	if err := os.WriteFile(filepath.Join(dir, "status"), []byte(body), 0o644); err != nil {
		f.t.Fatal(err)
	}
	if pidNS != "" {
		if err := os.Symlink(pidNS, filepath.Join(dir, "ns", "pid")); err != nil {
			f.t.Fatal(err)
		}
	}
	if userNS != "" {
		if err := os.Symlink(userNS, filepath.Join(dir, "ns", "user")); err != nil {
			f.t.Fatal(err)
		}
	}
	if cgroup != "" {
		if err := os.WriteFile(filepath.Join(dir, "cgroup"), []byte(cgroup), 0o644); err != nil {
			f.t.Fatal(err)
		}
	}
}

func (f *fakeProc) pids(systemd bool) []int {
	got := teardownScope{procRoot: f.root, self: 14, systemd: systemd}.pidsOwnedBy(1001)
	sort.Ints(got)
	return got
}

func TestPidsOwnedByReadsEveryUidFieldAndSkipsZombies(t *testing.T) {
	proc := newFakeProc(t)
	all := "1001\t1001\t1001\t1001"
	proc.add("10", "S (sleeping)", all, hostPIDNS, hostUserNS, userCgroup)
	proc.add("11", "R (running)", "0\t1001\t0\t1001", hostPIDNS, hostUserNS, userCgroup) // setuid-style: effective uid only
	proc.add("12", "Z (zombie)", all, hostPIDNS, hostUserNS, userCgroup)
	proc.add("13", "S (sleeping)", "1002\t1002\t1002\t1002", hostPIDNS, hostUserNS, "0::/user.slice/user-1002.slice/session-4.scope\n")
	proc.add("14", "S (sleeping)", all, hostPIDNS, hostUserNS, "0::/system.slice/orchestrator-agent.service\n") // the agent itself
	if err := os.MkdirAll(filepath.Join(proc.root, "self"), 0o755); err != nil {
		t.Fatal(err)
	}

	for _, systemd := range []bool{true, false} {
		if got := proc.pids(systemd); !reflect.DeepEqual(got, []int{10, 11}) {
			t.Fatalf("systemd=%v: pids = %v, want [10 11]", systemd, got)
		}
	}
}

// A process that merely shares the uid number is not the host's user: one in
// another PID or user namespace, or in a container runtime's cgroup, is never
// listed; under systemd, neither is one outside the user's own slice.
func TestPidsOwnedBySkipsContainersAndOtherNamespaces(t *testing.T) {
	proc := newFakeProc(t)
	all := "1001\t1001\t1001\t1001"
	proc.add("14", "S (sleeping)", "0\t0\t0\t0", hostPIDNS, hostUserNS, "0::/system.slice/orchestrator-agent.service\n")
	proc.add("20", "S (sleeping)", all, hostPIDNS, hostUserNS, userCgroup)                                                               // a login session
	proc.add("21", "S (sleeping)", all, hostPIDNS, hostUserNS, "0::/user.slice/user-1001.slice/user@1001.service/app.slice/x.service\n") // their user manager's service (a unit name; publication-guard: allow email-domain)
	proc.add("30", "S (sleeping)", all, "pid:[4026532200]", hostUserNS, "0::/system.slice/docker-abc.scope\n")                           // a container's own PID namespace
	proc.add("31", "S (sleeping)", all, hostPIDNS, "user:[4026532300]", userCgroup)                                                      // another user namespace
	proc.add("32", "S (sleeping)", all, hostPIDNS, hostUserNS, "0::/system.slice/docker-abc.scope\n")                                    // --pid=host container
	proc.add("33", "S (sleeping)", all, hostPIDNS, hostUserNS, "0::/kubepods.slice/kubepods-besteffort.slice/cri-containerd-1.scope\n")
	proc.add("34", "S (sleeping)", all, hostPIDNS, hostUserNS, "12:pids:/lxc.payload.c1\n0::/lxc.payload.c1\n") // cgroup v1 lines too
	proc.add("35", "S (sleeping)", all, hostPIDNS, hostUserNS, "0::/machine.slice/libpod-def.scope/container\n")
	proc.add("36", "S (sleeping)", all, "", "", userCgroup)                                              // namespaces unreadable
	proc.add("40", "S (sleeping)", all, hostPIDNS, hostUserNS, "0::/system.slice/some-daemon.service\n") // a system service running as that uid
	proc.add("41", "S (sleeping)", all, hostPIDNS, hostUserNS, "")                                       // no cgroup file

	if got, want := proc.pids(true), []int{20, 21}; !reflect.DeepEqual(got, want) {
		t.Fatalf("systemd: pids = %v, want %v", got, want)
	}
	// Without systemd there is no user slice to match; the namespace and
	// container tests still hold.
	if got, want := proc.pids(false), []int{20, 21, 40, 41}; !reflect.DeepEqual(got, want) {
		t.Fatalf("no systemd: pids = %v, want %v", got, want)
	}
}

// The teardown belongs to the transition into the lock: a user who stays
// locked across applies is not torn down again, an incomplete teardown is
// retried, and a new lock after an unlock tears down again.
func TestEndSessionsOnceRunsOncePerLock(t *testing.T) {
	var st accessUserState
	calls := 0
	done := false
	end := func() (int, bool) { calls++; return 2, done }

	if n := endSessionsOnce(&st, end); n != 2 || calls != 1 || st.SessionsEnded {
		t.Fatalf("incomplete teardown: n=%d calls=%d ended=%v", n, calls, st.SessionsEnded)
	}
	done = true
	if endSessionsOnce(&st, end); calls != 2 || !st.SessionsEnded {
		t.Fatalf("incomplete teardown was not retried: calls=%d ended=%v", calls, st.SessionsEnded)
	}
	for i := 0; i < 3; i++ {
		if n := endSessionsOnce(&st, end); n != 0 {
			t.Fatalf("a user who stayed locked was torn down again")
		}
	}
	if calls != 2 {
		t.Fatalf("calls = %d, want 2", calls)
	}
	st.SessionsEnded = false // what an unlock records
	if endSessionsOnce(&st, end); calls != 3 {
		t.Fatalf("a new lock did not tear down")
	}
}
