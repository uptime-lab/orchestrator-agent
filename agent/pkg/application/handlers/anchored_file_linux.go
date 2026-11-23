//go:build linux

package handlers

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// The path checks and the operations were about different things.
//
// resolveForFileOp returns a path STRING, and every caller then re-walks that
// string with a fresh syscall — three re-walks in handleDeleteFile, four in
// handleWriteFile. Between the check and the use, any unprivileged local user
// who can rename a parent component points the operation at a different file,
// and the platform manufactures such users: a non-sudo access entry is exactly
// one.
//
// WHY NOT openat2/RESOLVE_NO_SYMLINKS, which is the obvious answer: it would
// refuse Ubuntu's merged-/usr paths, including
// /lib/systemd/system/orchestrator-agent.service — which is on the agent's own
// protected list, so the hardening would break the thing it protects. It also
// imposes a kernel-version floor, and the netboot initramfs is a Buildroot build
// where that is not a given.
//
// The fix is to make the KERNEL OBJECT the identity rather than the string:
// open the resolved parent once, then perform every subsequent operation
// through that descriptor with the *at() syscalls. A rename after the open
// cannot retarget them — the fd keeps pointing at the directory that was
// checked, whatever it is now called.
//
// The open of the parent ITSELF is the second half. A single
// open(dir, O_NOFOLLOW) refuses a symlink only at dir's LAST component; the
// components above it are resolved by the kernel, following whatever is there
// NOW — and between resolveForFileOp's EvalSymlinks and this open, a local user
// who owns any directory on the way can swap a real directory for a symlink.
// openDirNoSymlinks walks the resolved path one component at a time with
// openat(O_NOFOLLOW), so a symlink at ANY depth fails the anchor instead of
// being followed. That gives the RESOLVE_NO_SYMLINKS guarantee without the
// openat2 kernel floor, and without breaking merged-/usr paths: EvalSymlinks
// already turned /lib/... into /usr/lib/..., so a correctly resolved path has
// no symlink left in it and the walk only ever refuses a path that changed
// after it was checked.

// anchoredTarget is a file identified by (parent directory fd, final component)
// rather than by a path string. Callers must Close it.
type anchoredTarget struct {
	// dirFD is the resolved parent, opened O_PATH|O_DIRECTORY|O_NOFOLLOW.
	// O_PATH because this fd is only ever used as the anchor of an *at() call,
	// never read or written itself — it needs no read permission and cannot be
	// used to do anything but resolve relative to.
	dirFD int
	// name is the final path component. Guaranteed to contain no separator, so
	// it cannot walk anywhere from the anchor.
	name string
	// path is the resolved path as a string, for reporting and logging ONLY.
	// Nothing may perform an operation with it — that is the bug this type
	// exists to close.
	path string
	// ownsFD says whether Close should release dirFD. False for a target built
	// on a caller-held anchor (anchoredIn), where several targets share one
	// directory fd and the caller closes it once.
	ownsFD bool
}

// openAnchored opens the parent of resolved and returns a target anchored to it.
//
// resolved must already have been through the protected-path checks; this adds
// no policy, only the guarantee that the operations land on what was checked.
func openAnchored(resolved string) (*anchoredTarget, error) {
	dir := filepath.Dir(resolved)
	base := filepath.Base(resolved)
	if base == "." || base == string(filepath.Separator) || base == "" {
		return nil, fmt.Errorf("%s does not name a file", resolved)
	}

	// Component by component, refusing a symlink at ANY depth — not only the
	// last one. The earlier components were resolved by EvalSymlinks in
	// resolveForFileOp; a link among them now means the tree changed after the
	// check, and the anchor must fail rather than land where
	// the link points.
	fd, err := openDirNoSymlinks(dir)
	if err != nil {
		return nil, fmt.Errorf("opening parent directory %s: %w", dir, err)
	}
	return &anchoredTarget{dirFD: fd, name: base, path: resolved, ownsFD: true}, nil
}

// openAnchorDir opens a directory to anchor operations on entries INSIDE it,
// refusing to follow a symlink at any component of the path.
//
// The caller owns the returned fd and must close it. Use it with anchoredIn
// when several entries in one directory are operated on together: opening the
// parent once and working through that descriptor is what makes "the directory
// I checked" and "the directory I wrote into" the same kernel object. The path
// must be symlink-free (through EvalSymlinks) or the walk refuses it.
func openAnchorDir(path string) (int, error) {
	fd, err := openDirNoSymlinks(path)
	if err != nil {
		return -1, fmt.Errorf("opening directory %s: %w", path, err)
	}
	return fd, nil
}

// openDirNoSymlinks opens an absolute directory path as an O_PATH anchor by
// walking it from / one component at a time, each step an
// openat(parent, component, O_NOFOLLOW|O_DIRECTORY). A symlink at ANY step
// fails the open, which is the property a plain open(path, O_NOFOLLOW) does
// not have: there the kernel resolves every component but the last, following
// links freely.
//
// The caller must pass a path that has already been through EvalSymlinks (or
// one it knows to be symlink-free). On such a path the walk succeeds unless the
// tree changed after the resolve — which is exactly the race this exists to
// turn into a refusal. A missing component surfaces as ENOENT
// inside an *os.PathError, so errIsNotExist keeps working for callers that
// treat "already gone" as success.
func openDirNoSymlinks(dir string) (int, error) {
	if !filepath.IsAbs(dir) {
		return -1, fmt.Errorf("%s is not an absolute path", dir)
	}
	dir = filepath.Clean(dir)
	fd, err := unix.Open("/", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, &os.PathError{Op: "open", Path: "/", Err: err}
	}
	walked := "/"
	for _, comp := range strings.Split(strings.TrimPrefix(dir, "/"), "/") {
		if comp == "" {
			continue
		}
		next, err := unix.Openat(fd, comp, unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			// O_PATH|O_NOFOLLOW opens a symlink AS the link, and O_DIRECTORY
			// then rejects it with ENOTDIR — indistinguishable from a regular
			// file in the way. Name the link explicitly: an operator reading
			// the failure needs to know the path is not what it was.
			var st unix.Stat_t
			if err == unix.ENOTDIR && unix.Fstatat(fd, comp, &st, unix.AT_SYMLINK_NOFOLLOW) == nil &&
				st.Mode&unix.S_IFMT == unix.S_IFLNK {
				_ = unix.Close(fd)
				return -1, fmt.Errorf("%s is a symlink; the path changed after it was checked and the operation was refused",
					filepath.Join(walked, comp))
			}
			_ = unix.Close(fd)
			return -1, &os.PathError{Op: "openat", Path: filepath.Join(walked, comp), Err: err}
		}
		_ = unix.Close(fd)
		fd = next
		walked = filepath.Join(walked, comp)
	}
	return fd, nil
}

// anchoredIn names an entry inside an already-open anchor. It does NOT take
// ownership of dirFD.
func anchoredIn(dirFD int, name, displayDir string) (*anchoredTarget, error) {
	if filepath.Base(name) != name || name == "." || name == ".." || name == "" {
		return nil, fmt.Errorf("%q must be a bare file name", name)
	}
	return &anchoredTarget{dirFD: dirFD, name: name, path: filepath.Join(displayDir, name)}, nil
}

// Close releases the anchor, unless the target borrows a caller-held one.
func (t *anchoredTarget) Close() {
	if t != nil && t.ownsFD && t.dirFD >= 0 {
		_ = unix.Close(t.dirFD)
		t.dirFD = -1
	}
}

// displayPath is a path string that may only be printed. It is a DISTINCT type
// so that `os.Chown(t.Path(), …)` and friends fail to compile: the comment
// below used to be the only thing saying so, and a later hardening pass missed
// a sibling call two lines from one it converted.
type displayPath string

func (p displayPath) String() string { return string(p) }

// Path returns the resolved path for REPORTING. Never use it to perform an
// operation — that reintroduces the re-walk this type removes.
func (t *anchoredTarget) Path() displayPath { return displayPath(t.path) }

// Lstat stats the target without following a final symlink, through the anchor.
func (t *anchoredTarget) Lstat() (os.FileInfo, error) {
	var st unix.Stat_t
	if err := unix.Fstatat(t.dirFD, t.name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return nil, &os.PathError{Op: "lstat", Path: t.path, Err: err}
	}
	return &anchoredFileInfo{name: t.name, st: st}, nil
}

// Exists reports whether the target is present, distinguishing absence from an
// error the caller must not paper over.
func (t *anchoredTarget) Exists() (bool, error) {
	_, err := t.Lstat()
	if err == nil {
		return true, nil
	}
	if errIsNotExist(err) {
		return false, nil
	}
	return false, err
}

// Unlink removes the target through the anchor.
func (t *anchoredTarget) Unlink() error {
	if err := unix.Unlinkat(t.dirFD, t.name, 0); err != nil {
		return &os.PathError{Op: "unlink", Path: t.path, Err: err}
	}
	return nil
}

// RenameTo renames the target to another name IN THE SAME DIRECTORY. Same
// directory on purpose: both ends stay anchored to the descriptor that was
// checked, and a backup that could land elsewhere would be a second path to
// vet.
func (t *anchoredTarget) RenameTo(newName string) error {
	if filepath.Base(newName) != newName {
		return fmt.Errorf("rename target %q must be a bare file name", newName)
	}
	if err := unix.Renameat(t.dirFD, t.name, t.dirFD, newName); err != nil {
		return &os.PathError{Op: "rename", Path: t.path, Err: err}
	}
	return nil
}

// SiblingExists reports whether a name exists alongside the target, used for the
// "a backup is already there" check without re-walking the parent by string.
func (t *anchoredTarget) SiblingExists(name string) (bool, error) {
	var st unix.Stat_t
	err := unix.Fstatat(t.dirFD, name, &st, unix.AT_SYMLINK_NOFOLLOW)
	if err == nil {
		return true, nil
	}
	if err == unix.ENOENT {
		return false, nil
	}
	return false, &os.PathError{Op: "lstat", Path: filepath.Join(filepath.Dir(t.path), name), Err: err}
}

// WriteSibling creates a file next to the target and writes content to it,
// refusing to follow a symlink or clobber an existing entry. Used for backups.
func (t *anchoredTarget) WriteSibling(name string, content []byte, mode os.FileMode) error {
	if filepath.Base(name) != name {
		return fmt.Errorf("sibling %q must be a bare file name", name)
	}
	// O_EXCL|O_NOFOLLOW: a pre-planted symlink at this name must fail the create,
	// not be written through as root.
	fd, err := unix.Openat(t.dirFD, name,
		unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, uint32(mode.Perm()))
	if err != nil {
		return &os.PathError{Op: "openat", Path: name, Err: err}
	}
	f := os.NewFile(uintptr(fd), name)
	defer f.Close()
	if _, err := f.Write(content); err != nil {
		return err
	}
	return f.Sync()
}

// AtomicWrite replaces the target's content by writing a fresh inode next to it
// and renaming it into place, entirely through the anchor.
//
// The temp file is created with O_EXCL under a random name: a predictable name
// opened without O_EXCL is a local privilege escalation the moment arbitrary
// paths are writable, because anyone who can create entries in the directory
// pre-plants it as a symlink and the root agent writes through it.
func (t *anchoredTarget) AtomicWrite(content []byte, mode os.FileMode) error {
	tmpName, fd, err := t.createTemp()
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(fd), tmpName)
	cleanup := func() {
		_ = f.Close()
		_ = unix.Unlinkat(t.dirFD, tmpName, 0)
	}

	// Chmod through the fd, not the name: the name could be swapped between the
	// create and the chmod, and fchmod cannot be.
	if err := f.Chmod(mode.Perm()); err != nil {
		cleanup()
		return err
	}
	if _, err := f.Write(content); err != nil {
		cleanup()
		return err
	}
	if err := f.Sync(); err != nil {
		cleanup()
		return err
	}
	if err := f.Close(); err != nil {
		_ = unix.Unlinkat(t.dirFD, tmpName, 0)
		return err
	}
	if err := unix.Renameat(t.dirFD, tmpName, t.dirFD, t.name); err != nil {
		_ = unix.Unlinkat(t.dirFD, tmpName, 0)
		return &os.PathError{Op: "rename", Path: t.path, Err: err}
	}
	// Durability of the rename itself: without this the entry can be lost on a
	// power cut even though the data was fsynced, and these devices lose power.
	t.syncDir()
	return nil
}

// ReadBounded reads the target's content through the anchor, refusing a
// non-regular file and anything larger than max.
//
// Oversize is an ERROR rather than a short read: the only caller makes a backup
// out of what comes back, and a silently truncated backup is worse than no
// backup at all — it looks like a safety copy and restores a half file.
func (t *anchoredTarget) ReadBounded(max int64) ([]byte, error) {
	// O_NONBLOCK so opening a FIFO that nobody writes cannot park the agent's
	// single command goroutine forever.
	fd, err := unix.Openat(t.dirFD, t.name,
		unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, &os.PathError{Op: "openat", Path: t.path, Err: err}
	}
	f := os.NewFile(uintptr(fd), t.path)
	defer func() { _ = f.Close() }()

	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", t.path)
	}
	// One byte past the cap, so a file that grew between the stat and the read is
	// refused rather than cut in half.
	data, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > max {
		return nil, fmt.Errorf("%s is larger than %d bytes", t.path, max)
	}
	return data, nil
}

// Chown sets ownership through the anchor, not following a final symlink.
func (t *anchoredTarget) Chown(uid, gid int) error {
	if err := unix.Fchownat(t.dirFD, t.name, uid, gid, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return &os.PathError{Op: "chown", Path: t.path, Err: err}
	}
	return nil
}

// EnsureDir creates the target as a directory through the anchor and reports
// whether what is there now really is one.
//
// The refusal is the point. os.MkdirAll stats THROUGH a symlink: pointed at a
// link to /etc it sees a directory, returns nil, and every operation that
// follows lands on /etc as root. Mkdirat cannot be redirected that way, and the
// EEXIST case is re-checked with AT_SYMLINK_NOFOLLOW so an entry that is a link
// is refused rather than worked through.
func (t *anchoredTarget) EnsureDir(mode os.FileMode) error {
	err := unix.Mkdirat(t.dirFD, t.name, uint32(mode.Perm()))
	if err == nil {
		return nil
	}
	if err != unix.EEXIST {
		return &os.PathError{Op: "mkdir", Path: t.path, Err: err}
	}
	info, statErr := t.Lstat()
	if statErr != nil {
		return statErr
	}
	if !info.IsDir() {
		return fmt.Errorf("%s exists and is not a directory (mode %s); refusing to write through it", t.path, info.Mode())
	}
	return nil
}

// Chmod sets the mode through the anchor without following a final symlink.
//
// There is no fchmodat AT_SYMLINK_NOFOLLOW on Linux, so this opens the target
// O_PATH|O_NOFOLLOW first and chmods THAT descriptor via /proc/self/fd — which
// is what refusing to chmod a symlink's destination actually requires.
func (t *anchoredTarget) Chmod(mode os.FileMode) error {
	fd, err := unix.Openat(t.dirFD, t.name, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return &os.PathError{Op: "openat", Path: t.path, Err: err}
	}
	defer func() { _ = unix.Close(fd) }()
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return &os.PathError{Op: "fstat", Path: t.path, Err: err}
	}
	if st.Mode&unix.S_IFMT == unix.S_IFLNK {
		return fmt.Errorf("%s is a symlink; refusing to change its target's mode", t.path)
	}
	if err := unix.Chmod(fmt.Sprintf("/proc/self/fd/%d", fd), uint32(mode.Perm())); err != nil {
		return &os.PathError{Op: "chmod", Path: t.path, Err: err}
	}
	return nil
}

// createTemp makes an exclusively-created temp entry in the anchored directory
// and returns its name and fd.
//
// O_RDWR, not O_WRONLY: download_file writes, hashes and then EXTRACTS from
// this one descriptor, rewound — the same-descriptor rule is what makes the
// checksum cover the bytes that are unpacked. A write-only descriptor seeks
// fine and then fails its first read with EBADF, which breaks every
// extract=true download.
// AtomicWrite only writes and is indifferent to the mode.
func (t *anchoredTarget) createTemp() (string, int, error) {
	for attempt := 0; attempt < 10; attempt++ {
		name := fmt.Sprintf(".orchestrator-%d-%d.tmp", os.Getpid(), randomSuffix())
		fd, err := unix.Openat(t.dirFD, name,
			unix.O_RDWR|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
		if err == nil {
			return name, fd, nil
		}
		if err != unix.EEXIST {
			return "", -1, &os.PathError{Op: "openat", Path: name, Err: err}
		}
	}
	return "", -1, fmt.Errorf("could not create a temporary file in %s", filepath.Dir(t.path))
}

// syncDir flushes the directory entry. Best-effort: the write already succeeded,
// and failing the command because the metadata flush did would be the wrong way
// round.
func (t *anchoredTarget) syncDir() {
	// A second, writable-for-sync handle: an O_PATH fd cannot be fsynced. Taken
	// THROUGH the anchor ("." relative to dirFD), not by re-walking the path
	// string — a re-walk here would fsync whatever directory the string names
	// now, which after a rename is not the one the write landed in.
	if fd, err := unix.Openat(t.dirFD, ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0); err == nil {
		_ = unix.Fsync(fd)
		_ = unix.Close(fd)
	}
}

// OpenRead opens the target for reading through the anchor: O_NOFOLLOW so a
// final symlink is refused, O_NONBLOCK so a FIFO nobody writes cannot park the
// caller. The caller owns the file and must Close it.
func (t *anchoredTarget) OpenRead() (*os.File, error) {
	fd, err := unix.Openat(t.dirFD, t.name,
		unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: t.path, Err: err}
	}
	return os.NewFile(uintptr(fd), t.path), nil
}

// CreateTemp creates an exclusively-owned temp entry next to the target and
// hands back its bare name and an open *os.File. Pair it with ReplaceWithTemp
// or RemoveTemp; the name never leaves the anchored directory.
func (t *anchoredTarget) CreateTemp() (string, *os.File, error) {
	name, fd, err := t.createTemp()
	if err != nil {
		return "", nil, err
	}
	return name, os.NewFile(uintptr(fd), name), nil
}

// ReplaceWithTemp renames a temp entry created by CreateTemp over the target,
// entirely through the anchor, and syncs the directory entry.
func (t *anchoredTarget) ReplaceWithTemp(tmpName string) error {
	if filepath.Base(tmpName) != tmpName {
		return fmt.Errorf("temp entry %q must be a bare file name", tmpName)
	}
	if err := unix.Renameat(t.dirFD, tmpName, t.dirFD, t.name); err != nil {
		return &os.PathError{Op: "rename", Path: t.path, Err: err}
	}
	t.syncDir()
	return nil
}

// RemoveTemp unlinks a temp entry created by CreateTemp. Best-effort cleanup;
// an absent entry is not an error.
func (t *anchoredTarget) RemoveTemp(tmpName string) {
	if filepath.Base(tmpName) == tmpName {
		_ = unix.Unlinkat(t.dirFD, tmpName, 0)
	}
}

// anchoredFileInfo adapts a unix.Stat_t to os.FileInfo so callers keep using the
// mode/permission helpers they already use.
type anchoredFileInfo struct {
	name string
	st   unix.Stat_t
}

func (f *anchoredFileInfo) Name() string { return f.name }
func (f *anchoredFileInfo) Size() int64  { return f.st.Size }
func (f *anchoredFileInfo) IsDir() bool  { return f.Mode().IsDir() }
func (f *anchoredFileInfo) Sys() any {
	return &syscall.Stat_t{Uid: f.st.Uid, Gid: f.st.Gid, Mode: f.st.Mode, Size: f.st.Size}
}

func (f *anchoredFileInfo) Mode() os.FileMode {
	mode := os.FileMode(f.st.Mode & 0o777)
	switch f.st.Mode & unix.S_IFMT {
	case unix.S_IFDIR:
		mode |= os.ModeDir
	case unix.S_IFLNK:
		mode |= os.ModeSymlink
	case unix.S_IFIFO:
		mode |= os.ModeNamedPipe
	case unix.S_IFSOCK:
		mode |= os.ModeSocket
	case unix.S_IFBLK:
		mode |= os.ModeDevice
	case unix.S_IFCHR:
		mode |= os.ModeDevice | os.ModeCharDevice
	}
	return mode
}

func (f *anchoredFileInfo) ModTime() time.Time {
	return time.Unix(f.st.Mtim.Sec, f.st.Mtim.Nsec)
}

// errIsNotExist unwraps the *os.PathError the helpers above return.
func errIsNotExist(err error) bool {
	var pe *os.PathError
	if errors.As(err, &pe) {
		return pe.Err == unix.ENOENT
	}
	return os.IsNotExist(err)
}

// randomSuffix gives the temp name unpredictability. crypto/rand because the
// point is that a local attacker cannot guess the name before O_EXCL sees it.
func randomSuffix() uint32 {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		// Failing closed here would make a write impossible on a device with a
		// starved entropy pool; the O_EXCL retry loop is what actually
		// guarantees correctness, and this only makes guessing harder.
		return uint32(time.Now().UnixNano())
	}
	return binary.LittleEndian.Uint32(b[:])
}

// unixFchownatSibling sets ownership on a name next to the target, through the
// anchor. A small helper rather than exposing the fd, so no caller outside this
// file can perform an unanchored operation with it.
func unixFchownatSibling(t *anchoredTarget, name string, uid, gid int) error {
	if filepath.Base(name) != name {
		return fmt.Errorf("sibling %q must be a bare file name", name)
	}
	return unix.Fchownat(t.dirFD, name, uid, gid, unix.AT_SYMLINK_NOFOLLOW)
}
