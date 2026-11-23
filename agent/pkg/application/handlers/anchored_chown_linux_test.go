//go:build linux

package handlers

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// Descriptor anchoring made the KERNEL OBJECT the identity of a file operation,
// but two ownership calls and one read kept re-walking the path STRING next to
// it. On this product an unprivileged local user is a manufactured artefact —
// a non-sudo access entry is exactly one — and such a user owning the parent
// directory of a tracked file turns a root-run chown(2) into "give me
// /etc/shadow".

const (
	chownTestUID = 12345
	chownTestGID = 12345
)

// requireRoot skips when ownership cannot be changed at all. The agent runs as
// root on a device and the agent test image runs as root; a developer shell
// does not, and a test that silently passes there would be worse than absent.
func requireRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("changing file ownership needs root; this test runs in the agent test image")
	}
}

func ownerOf(t *testing.T, path string) (int, int) {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatalf("no stat for %s", path)
	}
	return int(st.Uid), int(st.Gid)
}

func discardHandler() *CommandHandler {
	return &CommandHandler{logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
}

// write_file's tail used to end with os.Chown(path, …) — chown(2), which
// follows a final symlink — even though it held an anchored target two lines
// away. Anyone able to swap the target name between the write and that call had
// the root agent chown whatever they pointed it at.
func TestWriteFileOwnershipDoesNotFollowASymlinkSwappedInAtTheTargetName(t *testing.T) {
	requireRoot(t)

	dir := t.TempDir()
	targetPath := filepath.Join(dir, "target.conf")
	victim := filepath.Join(dir, "victim")
	if err := os.WriteFile(targetPath, []byte("content"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(victim, []byte("someone else's file"), 0o600); err != nil {
		t.Fatal(err)
	}

	target, err := openAnchored(targetPath)
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()

	// The swap the attacker performs between the write and the ownership call.
	if err := os.Remove(targetPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, targetPath); err != nil {
		t.Fatal(err)
	}

	applyOwnerAnchored(target, "12345:12345", discardHandler())

	if uid, gid := ownerOf(t, victim); uid == chownTestUID || gid == chownTestGID {
		t.Fatalf("the symlink was followed: victim is now owned by %d:%d", uid, gid)
	}
	if uid, _ := ownerOf(t, targetPath); uid != chownTestUID {
		t.Fatalf("the link itself should have been chowned, got uid %d", uid)
	}
}

// download_file with extract=true needs no race at all: filepath.Walk lstats,
// so it hands back symlinks as symlinks, and os.Chown then followed one planted
// in the extraction destination at any earlier time.
func TestExtractedTreeOwnershipDoesNotFollowAPlantedSymlink(t *testing.T) {
	requireRoot(t)

	root := t.TempDir()
	dest := filepath.Join(root, "dest")
	if err := os.MkdirAll(dest, 0o755); err != nil {
		t.Fatal(err)
	}
	regular := filepath.Join(dest, "app.conf")
	if err := os.WriteFile(regular, []byte("unpacked"), 0o644); err != nil {
		t.Fatal(err)
	}
	victim := filepath.Join(root, "victim")
	if err := os.WriteFile(victim, []byte("someone else's file"), 0o600); err != nil {
		t.Fatal(err)
	}
	planted := filepath.Join(dest, "planted")
	if err := os.Symlink(victim, planted); err != nil {
		t.Fatal(err)
	}

	applyOwnerRecursive(dest, "12345:12345", discardHandler())

	if uid, gid := ownerOf(t, victim); uid == chownTestUID || gid == chownTestGID {
		t.Fatalf("the planted symlink was followed: victim is now owned by %d:%d", uid, gid)
	}
	if uid, _ := ownerOf(t, regular); uid != chownTestUID {
		t.Fatalf("the real unpacked file should have been chowned, got uid %d", uid)
	}
}

// The backup write_file takes before it replaces a file used readFileBounded on
// the path string while an anchored target for the same file was in scope. A
// parent rename between the anchor and that read therefore decided what the
// "safety copy" preserved — the property the anchor exists to remove.
func TestBackupContentIsReadThroughTheAnchorNotThePathString(t *testing.T) {
	root := t.TempDir()
	realDir := filepath.Join(root, "real")
	decoyDir := filepath.Join(root, "decoy")
	for _, d := range []string{realDir, decoyDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	named := filepath.Join(realDir, "target.conf")
	if err := os.WriteFile(named, []byte("the file the command named"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(decoyDir, "target.conf"), []byte("a file the command never named"), 0o644); err != nil {
		t.Fatal(err)
	}

	target, err := openAnchored(named)
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()

	// The parent swap. Nothing about the path string changes; what it resolves
	// to does.
	if err := os.Rename(realDir, filepath.Join(root, "moved")); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(decoyDir, realDir); err != nil {
		t.Fatal(err)
	}

	data, rerr := target.ReadBounded(8 * 1024 * 1024)
	if rerr != nil {
		t.Fatal(rerr)
	}
	if string(data) != "the file the command named" {
		t.Fatalf("the anchored read was retargeted: got %q", data)
	}

	// The contrast, so the property is stated rather than assumed: the path
	// string now names a different file entirely.
	viaPath, _, perr := readFileBounded(named, 8*1024*1024)
	if perr != nil {
		t.Fatal(perr)
	}
	if viaPath != "a file the command never named" {
		t.Fatalf("expected the path string to resolve to the decoy, got %q", viaPath)
	}
}

// An oversize file must fail the backup rather than come back empty: the caller
// refuses to proceed when the backup cannot be WRITTEN, so a silent empty read
// would let it overwrite the original while reporting a safety copy exists.
func TestBackupReadRefusesOversizeRatherThanReturningNothing(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "big.conf")
	if err := os.WriteFile(path, []byte("0123456789"), 0o644); err != nil {
		t.Fatal(err)
	}
	target, err := openAnchored(path)
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()

	if data, err := target.ReadBounded(4); err == nil {
		t.Fatalf("expected an oversize refusal, got %d bytes and no error", len(data))
	}
}

// A pin, not a regression proof: this test PASSED against the string-path
// walk too (filepath.Walk lstats and never descends a link), and is kept so
// the anchored rewrite is shown to preserve the property. What the rewrite
// actually closes — a directory swapped for a symlink between the lstat of
// one step and the chown of the next, which the path re-walk followed — is a
// race no unit test can force deterministically; the proof there is
// structural: every entry is chowned relative to a descriptor opened once
// with O_NOFOLLOW, and no path string is walked twice.
func TestExtractedTreeOwnershipDoesNotDescendIntoAPlantedDirectoryLink(t *testing.T) {
	requireRoot(t)

	root := t.TempDir()
	dest := filepath.Join(root, "dest")
	if err := os.MkdirAll(filepath.Join(dest, "real"), 0o755); err != nil {
		t.Fatal(err)
	}
	inside := filepath.Join(dest, "real", "a.conf")
	if err := os.WriteFile(inside, []byte("unpacked"), 0o644); err != nil {
		t.Fatal(err)
	}
	victimDir := filepath.Join(root, "victim-dir")
	if err := os.MkdirAll(victimDir, 0o755); err != nil {
		t.Fatal(err)
	}
	victim := filepath.Join(victimDir, "secret")
	if err := os.WriteFile(victim, []byte("someone else's file"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victimDir, filepath.Join(dest, "planted-dir")); err != nil {
		t.Fatal(err)
	}

	applyOwnerRecursive(dest, "12345:12345", discardHandler())

	if uid, gid := ownerOf(t, victim); uid == chownTestUID || gid == chownTestGID {
		t.Fatalf("the walk descended through a planted directory link: victim is now %d:%d", uid, gid)
	}
	if uid, gid := ownerOf(t, victimDir); uid == chownTestUID || gid == chownTestGID {
		t.Fatalf("the planted link's target directory was chowned: %d:%d", uid, gid)
	}
	for _, p := range []string{dest, filepath.Join(dest, "real"), inside} {
		if uid, _ := ownerOf(t, p); uid != chownTestUID {
			t.Fatalf("%s should have been chowned, got uid %d", p, uid)
		}
	}
}
