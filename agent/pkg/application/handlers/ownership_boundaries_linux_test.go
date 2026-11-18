//go:build linux

package handlers

import (
	"archive/tar"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

// Why these tests exist. The name policy taught the
// ownership walk to leave a protected NAME alone, but the walk chowned each
// directory before it looked at that directory's children — so an extraction
// aimed at /etc kept /etc/shadow root-owned while handing /etc itself to the
// archive's owner, who can then replace the directory entry. And the policy
// was names only: a hardlink or a mount inside the tree that aliases an
// object elsewhere was chowned by the name it happened to carry.

func TestGovernsProtectedPathIsDerivedFromTheProtectedLists(t *testing.T) {
	governs := []string{"/", "/etc", "/ETC", "/etc/ssh", "/etc/sudoers.d", "/boot", "/boot/firmware", "/usr/bin", "/usr/local/bin", "/lib/systemd/system", "/etc/systemd/system.conf.d", "/var", "/var/run/.."}
	for _, p := range governs {
		if !governsProtectedPath(p, "") {
			t.Errorf("%s governs a protected name and was not recognised", p)
		}
	}
	notGoverning := []string{"/etc/motd", "/opt", "/opt/app", "/home/user", "/etc/shadow", "/etc/ssh/authorized_keys.d", "/srv/data/etc"}
	for _, p := range notGoverning {
		if governsProtectedPath(p, "") {
			t.Errorf("%s does not govern a protected name and was refused", p)
		}
	}
	// The adoption file's ancestors count too, wherever it lives.
	if !governsProtectedPath("/var/lib/orchestrator", "/var/lib/orchestrator/adoption.txt") {
		t.Error("the adoption file's directory was not recognised")
	}
	if governsProtectedPath("/var/lib/orchestrator", "") {
		t.Error("with no adoption file that directory governs nothing")
	}
}

func TestOwnershipWalkKeepsTheOwnerOfDirectoriesGoverningProtectedNames(t *testing.T) {
	requireRoot(t)
	dest := filepath.Join(t.TempDir(), "etc")
	for _, d := range []string{"app", "ssh"} {
		if err := os.MkdirAll(filepath.Join(dest, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	files := map[string]string{
		filepath.Join(dest, "app", "app.conf"): "unpacked",
		filepath.Join(dest, "ssh", "banner"):   "unpacked too",
		filepath.Join(dest, "shadow"):          "protected",
	}
	for p, c := range files {
		if err := os.WriteFile(p, []byte(c), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	rootFD, err := openOrCreateDirNoSymlinks(dest)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(rootFD)
	// Stand-ins for the platform's derivation: dest plays /etc, dest/ssh
	// plays /etc/ssh, dest/shadow plays /etc/shadow.
	governing := map[string]bool{dest: true, filepath.Join(dest, "ssh"): true}
	applyOwnerRecursiveWith(rootFD, dest, "12345:12345", ownershipPolicy{
		protected: protectedNamed("shadow"),
		governs:   func(p string) bool { return governing[p] },
	}, discardHandler())

	for _, kept := range []string{dest, filepath.Join(dest, "ssh"), filepath.Join(dest, "shadow")} {
		if uid, _ := ownerOf(t, kept); uid == chownTestUID {
			t.Fatalf("%s governs (or is) a protected name and was handed to the archive's owner", kept)
		}
	}
	for _, chowned := range []string{filepath.Join(dest, "app"), filepath.Join(dest, "app", "app.conf"), filepath.Join(dest, "ssh", "banner")} {
		if uid, _ := ownerOf(t, chowned); uid != chownTestUID {
			t.Fatalf("%s is the application's own and was not chowned (uid %d)", chowned, uid)
		}
	}
}

func TestOwnershipWalkSkipsHardlinkAliasesItDidNotCreate(t *testing.T) {
	requireRoot(t)
	root := t.TempDir()
	dest := filepath.Join(root, "dest")
	if err := os.MkdirAll(dest, 0o755); err != nil {
		t.Fatal(err)
	}
	// An object outside the tree, aliased by a name inside it.
	secret := filepath.Join(root, "secret")
	if err := os.WriteFile(secret, []byte("someone else's"), 0o600); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(dest, "alias")
	if err := os.Link(secret, alias); err != nil {
		t.Fatal(err)
	}
	// The archive's own hardlink pair, and a plain file.
	a, b, plain := filepath.Join(dest, "a"), filepath.Join(dest, "b"), filepath.Join(dest, "plain")
	if err := os.WriteFile(a, []byte("ours"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(a, b); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(plain, []byte("ours"), 0o644); err != nil {
		t.Fatal(err)
	}
	rootFD, err := openOrCreateDirNoSymlinks(dest)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(rootFD)

	applyOwnerRecursiveWith(rootFD, dest, "12345:12345", ownershipPolicy{
		created: map[string]struct{}{a: {}, b: {}, plain: {}},
	}, discardHandler())

	if uid, _ := ownerOf(t, secret); uid == chownTestUID {
		t.Fatal("the object behind a pre-existing hardlink alias was chowned")
	}
	for _, ours := range []string{a, b, plain} {
		if uid, _ := ownerOf(t, ours); uid != chownTestUID {
			t.Fatalf("%s was created by the extraction and was not chowned (uid %d)", ours, uid)
		}
	}

	// With no record of what was created, every multi-link file is an alias.
	if err := os.Chown(a, 0, 0); err != nil {
		t.Fatal(err)
	}
	applyOwnerRecursiveWith(rootFD, dest, "12345:12345", ownershipPolicy{}, discardHandler())
	if uid, _ := ownerOf(t, a); uid == chownTestUID {
		t.Fatal("with no creation record a multi-link file was chowned")
	}
	if uid, _ := ownerOf(t, plain); uid != chownTestUID {
		t.Fatal("a single-link file must still be chowned without a creation record")
	}
}

func TestOwnershipWalkDoesNotCrossAMountPoint(t *testing.T) {
	requireRoot(t)
	root := t.TempDir()
	dest := filepath.Join(root, "dest")
	mnt := filepath.Join(dest, "mnt")
	if err := os.MkdirAll(mnt, 0o755); err != nil {
		t.Fatal(err)
	}
	elsewhere := t.TempDir()
	if err := os.WriteFile(filepath.Join(elsewhere, "secret"), []byte("someone else's"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mount(elsewhere, mnt, "", unix.MS_BIND, ""); err != nil {
		if errors.Is(err, unix.EPERM) || errors.Is(err, unix.ENOSYS) {
			t.Skipf("bind mounts are not permitted here: %v", err)
		}
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Unmount(mnt, unix.MNT_DETACH) })
	if err := os.WriteFile(filepath.Join(dest, "app.conf"), []byte("ours"), 0o644); err != nil {
		t.Fatal(err)
	}
	rootFD, err := openOrCreateDirNoSymlinks(dest)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(rootFD)

	applyOwnerRecursiveWith(rootFD, dest, "12345:12345", ownershipPolicy{}, discardHandler())

	if uid, _ := ownerOf(t, filepath.Join(elsewhere, "secret")); uid == chownTestUID {
		t.Fatal("the walk crossed a bind mount and chowned a file that lives elsewhere")
	}
	if uid, _ := ownerOf(t, elsewhere); uid == chownTestUID {
		t.Fatal("the mount point's underlying directory was chowned")
	}
	if uid, _ := ownerOf(t, filepath.Join(dest, "app.conf")); uid != chownTestUID {
		t.Fatal("the application's own file beside the mount was not chowned")
	}
}

// End to end through the download handler: an archive carrying an internal
// hardlink pair is handed over whole, while a pre-existing alias in the
// destination keeps its owner — the created set travels from the extraction
// to the ownership walk.
func TestDownloadExtractHandsOverItsOwnHardlinksOnly(t *testing.T) {
	requireRoot(t)
	root := t.TempDir()
	dest := filepath.Join(root, "unpacked")
	if err := os.MkdirAll(dest, 0o755); err != nil {
		t.Fatal(err)
	}
	secret := filepath.Join(root, "secret")
	if err := os.WriteFile(secret, []byte("someone else's"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(secret, filepath.Join(dest, "alias")); err != nil {
		t.Fatal(err)
	}
	archive := tarBytes(t, func(tw *tar.Writer) {
		_ = tw.WriteHeader(&tar.Header{Name: "a", Mode: 0o644, Size: 4, Typeflag: tar.TypeReg})
		_, _ = tw.Write([]byte("ours"))
		_ = tw.WriteHeader(&tar.Header{Name: "b", Mode: 0o644, Typeflag: tar.TypeLink, Linkname: "a"})
	})
	rootFD, err := openOrCreateDirNoSymlinks(dest)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(rootFD)
	created, err := extractTarIntoTracked(rootFD, archive, "x.tar", dest, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	applyOwnerRecursiveWith(rootFD, dest, "12345:12345", ownershipPolicy{created: created}, discardHandler())
	for _, ours := range []string{filepath.Join(dest, "a"), filepath.Join(dest, "b")} {
		if uid, _ := ownerOf(t, ours); uid != chownTestUID {
			t.Fatalf("%s came from the archive and was not chowned (uid %d)", ours, uid)
		}
	}
	if uid, _ := ownerOf(t, secret); uid == chownTestUID {
		t.Fatal("the pre-existing alias handed its target to the archive's owner")
	}
}
