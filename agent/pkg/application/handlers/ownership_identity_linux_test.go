//go:build linux

package handlers

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	proto "agent/pkg/infrastructure/grpc/proto"

	"golang.org/x/sys/unix"
)

// The governing test was a string test on
// the resolved path, so a bind-mount ALIAS of a governing directory
// (`mount --bind /etc /srv/etc`) passed resolveForFileOp, had its `shadow`
// entry unlinked and recreated through the alias, and the root's own chown
// handed /etc to the archive's owner. And a TypeLink entry could name a
// pre-existing file in the destination, land in the created set by name and
// be chowned as the archive's own.

// bindMount mounts src onto dst or skips the test where that is not allowed.
func bindMount(t *testing.T, src, dst string) {
	t.Helper()
	if err := unix.Mount(src, dst, "", unix.MS_BIND, ""); err != nil {
		if errors.Is(err, unix.EPERM) || errors.Is(err, unix.ENOSYS) {
			t.Skipf("bind mounts are not permitted here: %v", err)
		}
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Unmount(dst, unix.MNT_DETACH) })
}

func TestGoverningIdentityRecognisesABindMountAlias(t *testing.T) {
	requireRoot(t)
	root := t.TempDir()
	etc := filepath.Join(root, "etc")
	alias := filepath.Join(root, "srv-etc")
	for _, d := range []string{etc, alias} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	bindMount(t, etc, alias)
	ids := directoryIdentities([]string{etc})

	fd, err := openOrCreateDirNoSymlinks(alias)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	if got := governingObjectOf(fd, ids); got != etc {
		t.Fatalf("the alias was not recognised as %s (got %q)", etc, got)
	}
	if err := refuseGoverningAlias(fd, alias, ids); err == nil || !strings.Contains(err.Error(), etc) {
		t.Fatalf("an extraction root that aliases a governing directory was not refused by name: %v", err)
	}
	// Under its OWN name the directory is not an alias: allowed, owner kept
	// by the walk.
	own, err := openOrCreateDirNoSymlinks(etc)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(own)
	if err := refuseGoverningAlias(own, etc, ids); err != nil {
		t.Fatalf("a governing directory under its own name was refused: %v", err)
	}
}

func TestOwnershipWalkKeepsTheOwnerOfAGoverningDirectoryReachedByAlias(t *testing.T) {
	requireRoot(t)
	root := t.TempDir()
	etc := filepath.Join(root, "etc")
	alias := filepath.Join(root, "srv-etc")
	if err := os.MkdirAll(filepath.Join(etc, "app"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(alias, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(etc, "app", "app.conf"), []byte("ours"), 0o644); err != nil {
		t.Fatal(err)
	}
	bindMount(t, etc, alias)
	rootFD, err := openOrCreateDirNoSymlinks(alias)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(rootFD)
	// No name governs here (the alias is not an ancestor of anything); only
	// the object identity says this root is the governing directory.
	applyOwnerRecursiveWith(rootFD, alias, "12345:12345", ownershipPolicy{
		governingIDs: directoryIdentities([]string{etc}),
	}, discardHandler())
	if uid, _ := ownerOf(t, etc); uid == chownTestUID {
		t.Fatal("the governing directory was handed to the archive's owner through its alias")
	}
	if uid, _ := ownerOf(t, filepath.Join(etc, "app", "app.conf")); uid != chownTestUID {
		t.Fatal("the application's own file below it was not chowned")
	}
}

// End to end through the handler. The adoption file is the one governing
// name a test can place: its directory governs, so a bind-mount alias of that
// directory is refused as an extraction root, its `shadow` untouched and its
// owner kept.
func TestDownloadExtractRefusesABindMountAliasOfAGoverningDirectory(t *testing.T) {
	requireRoot(t)
	root := t.TempDir()
	etc := filepath.Join(root, "etc")
	alias := filepath.Join(root, "srv-etc")
	for _, d := range []string{etc, alias} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	shadow := filepath.Join(etc, "shadow")
	if err := os.WriteFile(shadow, []byte("root:!:19000::::::\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	bindMount(t, etc, alias)

	archive, err := io.ReadAll(tarBytes(t, func(tw *tar.Writer) {
		_ = tw.WriteHeader(&tar.Header{Name: "shadow", Mode: 0o644, Size: 4, Typeflag: tar.TypeReg})
		_, _ = tw.Write([]byte("evil"))
	}))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(archive)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(archive) }))
	defer srv.Close()

	h := downloadTestHandler()
	h.SetAdoptionFilePath(filepath.Join(etc, "adoption.txt"))
	err = h.handleDownloadFile("cmd", &proto.DownloadFileCommand{
		Url: srv.URL + "/bundle.tar", DestPath: alias, Extract: true, Owner: "12345:12345",
		Checksum: hex.EncodeToString(sum[:]),
	})
	if err == nil || !strings.Contains(err.Error(), etc) {
		t.Fatalf("an extraction into a bind-mount alias of a governing directory was not refused by name: %v", err)
	}
	if got, _ := os.ReadFile(shadow); string(got) != "root:!:19000::::::\n" {
		t.Fatalf("shadow was rewritten through the alias: %q", got)
	}
	if uid, _ := ownerOf(t, etc); uid == chownTestUID {
		t.Fatal("the governing directory was handed to the archive's owner through its alias")
	}
	if uid, _ := ownerOf(t, shadow); uid == chownTestUID {
		t.Fatal("shadow was handed to the archive's owner through its alias")
	}
}

func TestExtractionRefusesAHardlinkToAFileTheArchiveDidNotCreate(t *testing.T) {
	dest := filepath.Join(t.TempDir(), "unpacked")
	if err := os.MkdirAll(dest, 0o755); err != nil {
		t.Fatal(err)
	}
	existing := filepath.Join(dest, "existing")
	if err := os.WriteFile(existing, []byte("was here"), 0o600); err != nil {
		t.Fatal(err)
	}
	r := tarBytes(t, func(tw *tar.Writer) {
		_ = tw.WriteHeader(&tar.Header{Name: "alias", Mode: 0o644, Typeflag: tar.TypeLink, Linkname: "existing"})
	})
	rootFD, err := openOrCreateDirNoSymlinks(dest)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(rootFD)
	created, err := extractTarIntoTracked(rootFD, r, "x.tar", dest, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "not a member") {
		t.Fatalf("a hardlink to a pre-existing file was accepted: %v", err)
	}
	if _, serr := os.Lstat(filepath.Join(dest, "alias")); serr == nil {
		t.Fatal("the alias was created")
	}
	if _, ours := created[filepath.Join(dest, "alias")]; ours {
		t.Fatal("the refused alias was recorded as created")
	}
	// Control: a link to the archive's own member is still allowed.
	ok := tarBytes(t, func(tw *tar.Writer) {
		_ = tw.WriteHeader(&tar.Header{Name: "a", Mode: 0o644, Size: 4, Typeflag: tar.TypeReg})
		_, _ = tw.Write([]byte("ours"))
		_ = tw.WriteHeader(&tar.Header{Name: "b", Mode: 0o644, Typeflag: tar.TypeLink, Linkname: "a"})
	})
	if _, err := extractTarIntoTracked(rootFD, ok, "x.tar", dest, nil, nil); err != nil {
		t.Fatalf("an internal hardlink was refused: %v", err)
	}
}

// A governing directory bind-mounted BELOW a legitimate destination: the root
// passes (it is nobody's alias), but the entry `cfg/shadow` crosses `cfg`,
// which IS /etc by identity, so the walk must refuse it before any unlink —
// the name check would otherwise have judged `<dest>/cfg/shadow`, not
// `/etc/shadow`. Both the unit walk and the handler are driven.
func TestExtractionRefusesAnEntryCrossingABindMountAliasOfAGoverningDirectory(t *testing.T) {
	requireRoot(t)
	root := t.TempDir()
	etc := filepath.Join(root, "etc")
	dest := filepath.Join(root, "dest")
	cfg := filepath.Join(dest, "cfg")
	for _, d := range []string{etc, cfg} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	shadow := filepath.Join(etc, "shadow")
	const original = "root:!:19000::::::\n"
	if err := os.WriteFile(shadow, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}
	bindMount(t, etc, cfg)
	ids := directoryIdentities([]string{etc})

	archive, err := io.ReadAll(tarBytes(t, func(tw *tar.Writer) {
		_ = tw.WriteHeader(&tar.Header{Name: "cfg/shadow", Mode: 0o644, Size: 4, Typeflag: tar.TypeReg})
		_, _ = tw.Write([]byte("evil"))
	}))
	if err != nil {
		t.Fatal(err)
	}

	rootFD, err := openOrCreateDirNoSymlinks(dest)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(rootFD)
	if err := refuseGoverningAlias(rootFD, dest, ids); err != nil {
		t.Fatalf("premise broken: the destination itself must pass (%v)", err)
	}
	_, err = extractTarIntoTracked(rootFD, bytes.NewReader(archive), "x.tar", dest, nil, ids)
	if err == nil || !strings.Contains(err.Error(), etc) {
		t.Fatalf("an entry crossing a bind-mount alias of a governing directory was not refused by name: %v", err)
	}
	if got, _ := os.ReadFile(shadow); string(got) != original {
		t.Fatalf("shadow was rewritten through the alias: %q", got)
	}
	// Control: without the identity set the same entry lands, which is what
	// the string checks alone allowed.
	if _, err := extractTarIntoTracked(rootFD, bytes.NewReader(archive), "x.tar", dest, nil, nil); err != nil {
		t.Fatalf("control: %v", err)
	}
	if got, _ := os.ReadFile(shadow); string(got) != "evil" {
		t.Fatalf("control: the entry did not land through the alias (%q)", got)
	}
	if err := os.WriteFile(shadow, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}

	// Through the handler, with the adoption file making `etc` governing.
	sum := sha256.Sum256(archive)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(archive) }))
	defer srv.Close()
	h := downloadTestHandler()
	h.SetAdoptionFilePath(filepath.Join(etc, "adoption.txt"))
	err = h.handleDownloadFile("cmd", &proto.DownloadFileCommand{
		Url: srv.URL + "/bundle.tar", DestPath: dest, Extract: true, Owner: "12345:12345",
		Checksum: hex.EncodeToString(sum[:]),
	})
	if err == nil || !strings.Contains(err.Error(), etc) {
		t.Fatalf("the handler did not refuse the crossing entry by name: %v", err)
	}
	if got, _ := os.ReadFile(shadow); string(got) != original {
		t.Fatalf("shadow was rewritten through the alias by the handler: %q", got)
	}
	if uid, _ := ownerOf(t, etc); uid == chownTestUID {
		t.Fatal("the governing directory was handed to the archive's owner through its alias")
	}
}
