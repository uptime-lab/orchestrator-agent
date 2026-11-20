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

func TestPidsOwnedByReadsEveryUidFieldAndSkipsZombies(t *testing.T) {
	proc := t.TempDir()
	write := func(pid, state, uids string) {
		t.Helper()
		dir := filepath.Join(proc, pid)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		body := "Name:\tx\nState:\t" + state + "\nUid:\t" + uids + "\nGid:\t0\t0\t0\t0\n"
		if err := os.WriteFile(filepath.Join(dir, "status"), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("10", "S (sleeping)", "1001\t1001\t1001\t1001")
	write("11", "R (running)", "0\t1001\t0\t1001") // setuid-style: effective uid only
	write("12", "Z (zombie)", "1001\t1001\t1001\t1001")
	write("13", "S (sleeping)", "1002\t1002\t1002\t1002")
	write("14", "S (sleeping)", "1001\t1001\t1001\t1001") // the agent itself
	if err := os.MkdirAll(filepath.Join(proc, "self"), 0o755); err != nil {
		t.Fatal(err)
	}

	got := pidsOwnedBy(proc, 1001, 14)
	sort.Ints(got)
	if !reflect.DeepEqual(got, []int{10, 11}) {
		t.Fatalf("pids = %v, want [10 11]", got)
	}
}
