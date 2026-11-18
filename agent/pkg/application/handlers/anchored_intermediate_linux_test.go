//go:build linux

package handlers

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	proto "agent/pkg/infrastructure/grpc/proto"

	"golang.org/x/sys/unix"
)

// The anchor closed the "rename the parent after the open"
// race, but the OPEN of the parent was itself a single string walk: open(dir,
// O_NOFOLLOW) refuses a symlink at dir's last component only, and the kernel
// follows whatever the components above it point at NOW. resolveForFileOp had
// resolved them with EvalSymlinks a moment earlier — and a local user who owns
// any directory on the way can swap a real directory for a symlink in that
// moment. The tests here perform exactly that swap between the resolve and the
// anchor and require the anchor to refuse.

// swappedTree builds /root/home/u/a/b/target with the attacker owning `a`, plus
// a decoy tree the swap points at. It returns the RESOLVED path the policy
// checked (what resolveForFileOp would have returned before the swap), the
// decoy path, and a function that performs the swap: `a` is moved aside and a
// symlink named `a` now points at the decoy tree, so the string
// /root/home/u/a/b/target names the decoy.
func swappedTree(t *testing.T) (resolved, decoy string, swap func()) {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	realB := filepath.Join(root, "home", "u", "a", "b")
	decoyB := filepath.Join(root, "victim", "b")
	for _, d := range []string{realB, decoyB} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	resolved = filepath.Join(realB, "target.conf")
	decoy = filepath.Join(decoyB, "target.conf")
	if err := os.WriteFile(resolved, []byte("the file the policy checked"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(decoy, []byte("the file the policy never saw"), 0o644); err != nil {
		t.Fatal(err)
	}
	swap = func() {
		a := filepath.Join(root, "home", "u", "a")
		if err := os.Rename(a, a+".moved"); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(filepath.Join(root, "victim"), a); err != nil {
			t.Fatal(err)
		}
	}
	return resolved, decoy, swap
}

// The anchor is what write_file, delete_file, download_file and patch_file all
// take right after the resolve; if it opens the swapped tree, every one of them
// operates on the decoy as root.
func TestAnchorRefusesASymlinkSwappedIntoAnIntermediateComponent(t *testing.T) {
	resolved, decoy, swap := swappedTree(t)
	swap()

	anchored, err := openAnchored(resolved)
	if err == nil {
		anchored.Close()
		t.Fatalf("openAnchored followed a symlink planted in an intermediate component of %s", resolved)
	}
	if !unlinkedOK(t, decoy) {
		t.Fatal("test setup: decoy vanished")
	}
}

// The read side has its own opener and used to open the string directly, so a
// swapped component handed back the decoy's bytes — the adoption file, given
// the right link.
func TestBoundedReadRefusesASymlinkSwappedIntoAnIntermediateComponent(t *testing.T) {
	resolved, _, swap := swappedTree(t)
	swap()

	content, _, err := readFileBounded(resolved, DefaultReadMaxBytes)
	if err == nil {
		t.Fatalf("readFileBounded read through a swapped intermediate component and returned %q", content)
	}
}

// openAnchorDir is the anchor for provisioning a home directory; the same rule
// applies to it.
func TestAnchorDirRefusesASymlinkAtAnyComponent(t *testing.T) {
	resolved, _, swap := swappedTree(t)
	swap()

	fd, err := openAnchorDir(filepath.Dir(resolved))
	if err == nil {
		_ = unix.Close(fd)
		t.Fatalf("openAnchorDir followed a symlink planted in an intermediate component of %s", filepath.Dir(resolved))
	}
}

// The ordinary case must keep working: a symlink-free resolved path anchors
// and the operations land where the policy looked.
func TestAnchorStillOpensAnUnchangedResolvedPath(t *testing.T) {
	resolved, _, _ := swappedTree(t)

	anchored, err := openAnchored(resolved)
	if err != nil {
		t.Fatalf("openAnchored on an unchanged path: %v", err)
	}
	defer anchored.Close()
	data, err := anchored.ReadBounded(DefaultReadMaxBytes)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "the file the policy checked" {
		t.Errorf("anchored read returned %q", string(data))
	}
	content, _, err := readFileBounded(resolved, DefaultReadMaxBytes)
	if err != nil || content != "the file the policy checked" {
		t.Errorf("readFileBounded = %q, %v", content, err)
	}
}

// A legitimately symlinked ANCESTOR under which the target's directory does
// not yet exist: resolveForFileOp cannot resolve a missing parent, so it hands
// back the raw string, and the anchor walk would refuse the link. write_file
// creates the directory, resolves again, and the write lands where the link
// points — the behaviour it had before the walk, kept by the re-resolve.
func TestWriteFileStillWorksUnderASymlinkedAncestorWhenTheParentIsNew(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	real := filepath.Join(root, "real")
	if err := os.MkdirAll(real, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	// The directory `new` does not exist yet, so the parent of the target
	// cannot be resolved before the write creates it.
	requested := filepath.Join(link, "new", "app.conf")

	h := NewCommandHandler(slog.New(slog.NewTextHandler(io.Discard, nil)),
		silentPlatformClient{}, "node", "account", "token")
	if err := h.handleWriteFile("cmd-w", &proto.WriteFileCommand{Path: requested, Content: "hello"}); err != nil {
		t.Fatalf("write_file under a symlinked ancestor: %v", err)
	}
	body, err := os.ReadFile(filepath.Join(real, "new", "app.conf"))
	if err != nil {
		t.Fatalf("the file did not land under the link's target: %v", err)
	}
	if string(body) != "hello" {
		t.Errorf("content = %q", string(body))
	}
}

// download_file stages and renames through the same anchor; a swap between the
// resolve and the anchor must fail the download rather than deliver it into
// the decoy tree. The handler resolves for itself, so the swap is applied to
// the anchor primitive it uses — the handler-level ordinary case is covered by
// the download tests next door.
func TestDownloadStagingRefusesASwappedIntermediateComponent(t *testing.T) {
	resolved, decoy, swap := swappedTree(t)
	swap()

	dest, err := openAnchored(resolved)
	if err == nil {
		name, f, cerr := dest.CreateTemp()
		if cerr == nil {
			_ = f.Close()
			dest.RemoveTemp(name)
		}
		dest.Close()
		t.Fatalf("the download anchor opened the swapped tree; a temp would have been staged beside %s", decoy)
	}
}

func unlinkedOK(t *testing.T, path string) bool {
	t.Helper()
	_, err := os.Lstat(path)
	return err == nil
}
