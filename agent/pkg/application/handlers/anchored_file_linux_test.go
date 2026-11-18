//go:build linux

package handlers

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// The checks and the operations were about different things: the
// resolve returned a path STRING and every caller re-walked it, so an
// unprivileged local user who could swap a parent component between the two
// retargeted a root-owned delete or write. The platform manufactures such users
// — a non-sudo access entry is exactly one.

// The property that matters: once anchored, renaming the parent CANNOT retarget
// the operation. The fd keeps pointing at the directory that was checked,
// whatever it is now called, and whatever now occupies the old name.
func TestRenamingTheParentCannotRetargetAnAnchoredDelete(t *testing.T) {
	root := t.TempDir()
	realDir := filepath.Join(root, "real")
	victimDir := filepath.Join(root, "victim")
	for _, d := range []string{realDir, victimDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	target := filepath.Join(realDir, "target.conf")
	if err := os.WriteFile(target, []byte("the file the command named"), 0o644); err != nil {
		t.Fatal(err)
	}
	decoy := filepath.Join(victimDir, "target.conf")
	if err := os.WriteFile(decoy, []byte("a file the command never named"), 0o644); err != nil {
		t.Fatal(err)
	}

	anchored, err := openAnchored(target)
	if err != nil {
		t.Fatalf("openAnchored: %v", err)
	}
	defer anchored.Close()

	// The race: after the check, swap what the path string means. `real` becomes
	// `moved`, and `victim` takes the name `real` — so the STRING now resolves
	// to the decoy.
	if err := os.Rename(realDir, filepath.Join(root, "moved")); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(victimDir, realDir); err != nil {
		t.Fatal(err)
	}

	if err := anchored.Unlink(); err != nil {
		t.Fatalf("Unlink through the anchor: %v", err)
	}

	// The file the command actually named is gone...
	if _, err := os.Lstat(filepath.Join(root, "moved", "target.conf")); !os.IsNotExist(err) {
		t.Error("the anchored delete did not remove the file it was pointed at")
	}
	// ...and the file that took its place in the path string is untouched.
	if _, err := os.Lstat(filepath.Join(realDir, "target.conf")); err != nil {
		t.Errorf("the delete followed the renamed path and hit the wrong file: %v", err)
	}
}

// The same property for the write side, which is the more dangerous half: a
// retargeted write is arbitrary root-owned content at a path of the attacker's
// choosing.
func TestRenamingTheParentCannotRetargetAnAnchoredWrite(t *testing.T) {
	root := t.TempDir()
	realDir := filepath.Join(root, "real")
	victimDir := filepath.Join(root, "victim")
	for _, d := range []string{realDir, victimDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	target := filepath.Join(realDir, "app.conf")
	if err := os.WriteFile(target, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	const decoyBody = "must not be overwritten"
	decoy := filepath.Join(victimDir, "app.conf")
	if err := os.WriteFile(decoy, []byte(decoyBody), 0o600); err != nil {
		t.Fatal(err)
	}

	anchored, err := openAnchored(target)
	if err != nil {
		t.Fatal(err)
	}
	defer anchored.Close()

	if err := os.Rename(realDir, filepath.Join(root, "moved")); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(victimDir, realDir); err != nil {
		t.Fatal(err)
	}

	if err := anchored.AtomicWrite([]byte("written by the platform"), 0o600); err != nil {
		t.Fatalf("AtomicWrite: %v", err)
	}

	got, err := os.ReadFile(filepath.Join(root, "moved", "app.conf"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "written by the platform" {
		t.Errorf("the anchored write did not land on its target: %q", got)
	}
	stillDecoy, err := os.ReadFile(filepath.Join(realDir, "app.conf"))
	if err != nil {
		t.Fatal(err)
	}
	if string(stillDecoy) != decoyBody {
		t.Errorf("the write followed the renamed path and clobbered another file: %q", stillDecoy)
	}
}

// The mode must survive the rename-into-place, or an applied edit silently turns
// a 0600 secret into a world-readable file while reporting success.
func TestAnAnchoredWritePreservesTheModeItIsGiven(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "secret.conf")
	if err := os.WriteFile(target, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	anchored, err := openAnchored(target)
	if err != nil {
		t.Fatal(err)
	}
	defer anchored.Close()

	if err := anchored.AtomicWrite([]byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(target)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("mode after the write = %o, want 600 — a secret was just published", perm)
	}
}

// A pre-planted symlink at the backup name must fail the create rather than be
// written through as root.
func TestWriteSiblingRefusesAPrePlantedSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "app.conf")
	if err := os.WriteFile(target, []byte("body"), 0o644); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "elsewhere")
	if err := os.WriteFile(outside, []byte("untouched"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "app.conf.orchestrator.bak")); err != nil {
		t.Fatal(err)
	}

	anchored, err := openAnchored(target)
	if err != nil {
		t.Fatal(err)
	}
	defer anchored.Close()

	if err := anchored.WriteSibling("app.conf.orchestrator.bak", []byte("backup"), 0o644); err == nil {
		t.Fatal("writing through a pre-planted symlink succeeded")
	}
	got, err := os.ReadFile(outside)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "untouched" {
		t.Errorf("the symlink target was written through: %q", got)
	}
}

// The anchored Lstat must report the same facts the unanchored one did, or the
// mode/owner preservation built on it changes behaviour.
func TestAnchoredLstatMatchesTheOrdinaryOne(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "f")
	if err := os.WriteFile(target, []byte("0123456789"), 0o640); err != nil {
		t.Fatal(err)
	}
	anchored, err := openAnchored(target)
	if err != nil {
		t.Fatal(err)
	}
	defer anchored.Close()

	got, err := anchored.Lstat()
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.Lstat(target)
	if err != nil {
		t.Fatal(err)
	}
	if got.Mode().Perm() != want.Mode().Perm() {
		t.Errorf("perm %o vs %o", got.Mode().Perm(), want.Mode().Perm())
	}
	if got.IsDir() != want.IsDir() || got.Mode().IsRegular() != want.Mode().IsRegular() {
		t.Errorf("type disagrees: %v vs %v", got.Mode(), want.Mode())
	}
	if got.Size() != want.Size() {
		t.Errorf("size %d vs %d", got.Size(), want.Size())
	}
	gs, ok1 := got.Sys().(*syscall.Stat_t)
	ws, ok2 := want.Sys().(*syscall.Stat_t)
	if ok1 && ok2 && (gs.Uid != ws.Uid || gs.Gid != ws.Gid) {
		t.Errorf("ownership disagrees: %d:%d vs %d:%d", gs.Uid, gs.Gid, ws.Uid, ws.Gid)
	}
}

// A symlinked FINAL component of the parent must not be followed by the anchor.
func TestOpenAnchoredRefusesASymlinkedParent(t *testing.T) {
	root := t.TempDir()
	real := filepath.Join(root, "real")
	if err := os.MkdirAll(real, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	if _, err := openAnchored(filepath.Join(link, "f")); err == nil {
		t.Fatal("a symlinked parent was accepted as the anchor")
	}
}

// Absence must be distinguishable from failure: delete reports "already absent"
// as a success, and must not do that because of an unrelated error.
func TestExistsDistinguishesAbsenceFromError(t *testing.T) {
	dir := t.TempDir()
	anchored, err := openAnchored(filepath.Join(dir, "not-there"))
	if err != nil {
		t.Fatal(err)
	}
	defer anchored.Close()

	exists, err := anchored.Exists()
	if err != nil {
		t.Fatalf("a missing file reported an error: %v", err)
	}
	if exists {
		t.Error("a missing file reported as present")
	}
}
