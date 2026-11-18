//go:build linux

package handlers

import (
	"archive/tar"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// protectedNamed refuses any path whose base name is in the set — a stand-in
// for checkProtectedNames with the platform's list, which the handler wires.
func protectedNamed(names ...string) func(string) error {
	return func(p string) error {
		for _, n := range names {
			if filepath.Base(p) == n {
				return errors.New(p + " is managed by the platform")
			}
		}
		return nil
	}
}

func TestExtractionRefusesAProtectedDescendant(t *testing.T) {
	dest := filepath.Join(t.TempDir(), "etc")
	r := tarBytes(t, func(tw *tar.Writer) {
		_ = tw.WriteHeader(&tar.Header{Name: "motd", Mode: 0o644, Size: 2, Typeflag: tar.TypeReg})
		_, _ = tw.Write([]byte("hi"))
		_ = tw.WriteHeader(&tar.Header{Name: "shadow", Mode: 0o600, Size: 4, Typeflag: tar.TypeReg})
		_, _ = tw.Write([]byte("evil"))
	})
	rootFD, err := openOrCreateDirNoSymlinks(dest)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(rootFD)
	err = extractTarInto(rootFD, r, "x.tar", dest, protectedNamed("shadow"))
	if err == nil || !strings.Contains(err.Error(), "shadow") {
		t.Fatalf("a protected descendant was extracted: %v", err)
	}
	if _, serr := os.Stat(filepath.Join(dest, "shadow")); serr == nil {
		t.Fatal("shadow was written before the policy refused it")
	}
}

func TestExtractionRefusesAHardlinkToAProtectedSource(t *testing.T) {
	dest := filepath.Join(t.TempDir(), "etc")
	if err := os.MkdirAll(dest, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dest, "shadow"), []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	r := tarBytes(t, func(tw *tar.Writer) {
		_ = tw.WriteHeader(&tar.Header{Name: "alias", Mode: 0o644, Typeflag: tar.TypeLink, Linkname: "shadow"})
	})
	rootFD, err := openOrCreateDirNoSymlinks(dest)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(rootFD)
	if err := extractTarInto(rootFD, r, "x.tar", dest, protectedNamed("shadow")); err == nil {
		t.Fatal("a hardlink to a protected file was created")
	}
	if _, serr := os.Lstat(filepath.Join(dest, "alias")); serr == nil {
		t.Fatal("the alias exists")
	}
}

func TestOwnershipWalkSkipsProtectedNames(t *testing.T) {
	requireRoot(t)
	dest := filepath.Join(t.TempDir(), "etc")
	if err := os.MkdirAll(dest, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"shadow", "motd"} {
		if err := os.WriteFile(filepath.Join(dest, n), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	rootFD, err := openOrCreateDirNoSymlinks(dest)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(rootFD)
	applyOwnerRecursiveAt(rootFD, dest, "12345:12345", protectedNamed("shadow"), discardHandler())
	if uid, _ := ownerOf(t, filepath.Join(dest, "shadow")); uid == chownTestUID {
		t.Fatal("a protected file was handed to the archive's owner")
	}
	if uid, _ := ownerOf(t, filepath.Join(dest, "motd")); uid != chownTestUID {
		t.Fatal("the ordinary file was not chowned")
	}
}

func TestOpenOrCreateDirNoSymlinksCreatesMissingComponentsAndRefusesLinks(t *testing.T) {
	root := t.TempDir()
	fd, err := openOrCreateDirNoSymlinks(filepath.Join(root, "a", "b", "c"))
	if err != nil {
		t.Fatalf("creating a nested destination: %v", err)
	}
	_ = unix.Close(fd)
	if st, err := os.Lstat(filepath.Join(root, "a", "b", "c")); err != nil || !st.IsDir() {
		t.Fatalf("nested directories were not created: %v", err)
	}
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	if fd, err := openOrCreateDirNoSymlinks(filepath.Join(root, "link", "deeper")); err == nil {
		_ = unix.Close(fd)
		t.Fatal("a destination below a symlinked component was opened")
	}
	if _, err := os.Stat(filepath.Join(outside, "deeper")); err == nil {
		t.Fatal("a directory was created through the symlink")
	}
}

// The helper returns within its advertised timeout even when a
// descendant keeps the output pipe, kills the whole group on timeout, and
// bounds what it keeps.
func TestRunWithEnvReturnsWhenAGrandchildHoldsTheOutput(t *testing.T) {
	// Control: the shape the helper had — CombinedOutput with no WaitDelay —
	// waits for the grandchild's copy of the pipe, i.e. the whole sleep.
	ctrlStart := time.Now()
	ctrl := exec.Command("sh", "-c", "sleep 6 & echo done; exit 0")
	_, _ = ctrl.CombinedOutput()
	if waited := time.Since(ctrlStart); waited < 5*time.Second {
		t.Fatalf("control: expected the old shape to wait for the grandchild, it returned after %s", waited)
	}

	start := time.Now()
	out, err := runWithEnv(nil, 30*time.Second, "sh", "-c", "sleep 20 & echo done; exit 0")
	if err != nil {
		t.Fatalf("a child that exited cleanly was reported failed: %v (%q)", err, out)
	}
	if elapsed := time.Since(start); elapsed > 10*time.Second {
		t.Fatalf("the helper waited %s for a grandchild's pipe", elapsed)
	}
	if !strings.Contains(out, "done") {
		t.Fatalf("output lost: %q", out)
	}
}

func TestRunWithEnvKillsTheProcessGroupOnTimeout(t *testing.T) {
	// The background child records its OWN pid before exec'ing the sleeper
	// (exec keeps the pid), so the test holds the exact process to look for.
	// The earlier version searched `pgrep -f` for a marker in the script's
	// path — which `exec sleep 300` had already replaced in the command line,
	// so the search found nothing whether or not the sleeper had died.
	// The pid is asserted alive BEFORE the timeout fires
	// and gone after it, and killed by the test itself if the helper failed
	// to, so a red run leaves no sleeper behind.
	pidFile := filepath.Join(t.TempDir(), "child.pid")
	script := filepath.Join(t.TempDir(), "child.sh")
	if err := os.WriteFile(script, []byte("#!/bin/sh\necho $$ > "+pidFile+"\nexec sleep 300\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	done := make(chan error, 1)
	go func() {
		_, err := runWithEnv(nil, 3*time.Second, "sh", "-c", "sh "+script+" & sleep 300; exit 0")
		done <- err
	}()

	var childPID int
	deadline := time.Now().Add(2 * time.Second)
	for childPID == 0 {
		if time.Now().After(deadline) {
			t.Fatal("the background child never recorded its pid")
		}
		if raw, err := os.ReadFile(pidFile); err == nil {
			childPID, _ = strconv.Atoi(strings.TrimSpace(string(raw)))
		}
		time.Sleep(20 * time.Millisecond)
	}
	// Independent cleanup takes the whole process GROUP the helper created
	// (the wrapper's own `sleep 300` included, not only the recorded child),
	// so a regression in the group kill leaves no sleeper behind.
	if pgid, err := syscall.Getpgid(childPID); err == nil && pgid > 1 {
		t.Cleanup(func() { _ = syscall.Kill(-pgid, syscall.SIGKILL) })
	}
	t.Cleanup(func() { _ = syscall.Kill(childPID, syscall.SIGKILL) })
	if err := syscall.Kill(childPID, 0); err != nil {
		t.Fatalf("the sleeper (pid %d) is not alive before the timeout: %v", childPID, err)
	}

	err := <-done
	if err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("expected a timeout, got %v", err)
	}
	if elapsed := time.Since(start); elapsed > 10*time.Second {
		t.Fatalf("timeout took %s", elapsed)
	}
	// Gone, or at most a zombie waiting for init to reap it; never a live
	// sleeper. Bounded poll: the group kill is asynchronous to Run returning.
	alive := func() bool {
		if err := syscall.Kill(childPID, 0); err != nil {
			return false
		}
		stat, err := os.ReadFile("/proc/" + strconv.Itoa(childPID) + "/stat")
		if err != nil {
			return false
		}
		// The state field follows the parenthesised command name.
		if i := strings.LastIndexByte(string(stat), ')'); i >= 0 && len(stat) > i+2 {
			return stat[i+2] != 'Z'
		}
		return true
	}
	for waitUntil := time.Now().Add(2 * time.Second); alive(); {
		if time.Now().After(waitUntil) {
			t.Fatalf("the background sleeper (pid %d) survived the group kill", childPID)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestRunWithEnvBoundsItsOutput(t *testing.T) {
	out, err := runWithEnv(nil, 30*time.Second, "sh", "-c", "yes | head -c 3000000")
	if err != nil {
		t.Fatalf("%v", err)
	}
	if !strings.Contains(out, "[output truncated]") {
		t.Fatalf("3 MB of output was kept whole (%d bytes)", len(out))
	}
	if len(out) > 1<<21 {
		t.Fatalf("kept %d bytes", len(out))
	}
}
