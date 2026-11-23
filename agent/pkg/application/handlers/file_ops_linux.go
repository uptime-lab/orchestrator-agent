//go:build linux

package handlers

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"unicode/utf8"

	"golang.org/x/sys/unix"

	"agent/pkg/domain/refusal"
	proto "agent/pkg/infrastructure/grpc/proto"
)

// DefaultReadMaxBytes bounds a tracked-file read. It is BOTH the default (when
// the platform names no limit) and the hard CEILING (when it names one): the
// content travels as a proto string inside the node's single command stream,
// and an oversized frame does not fail the command — it tears down the stream
// and takes the node offline. It matches the platform's node-file content cap.
//
// The ceiling is the part that matters for safety. read_file's max_bytes is
// caller-supplied (the generic command API, workflow blocks); an unbounded value
// would make readFileBounded pull a multi-GB file fully into memory — an OOM in
// the RAM-rooted recovery initramfs — because the size check compares against
// that very number. The platform clamps at dispatch too, but the
// device must not depend on the platform bounding the device's own memory.
const DefaultReadMaxBytes = 512 * 1024

// refusedReadPrefixes is the read side of the same rule. Declared once and
// shared, because the two lists drifting apart lets a path refused for writing
// be read (or the reverse): a single list means a new prefix cannot be added to one half only.
//
// The read side is a SUPERSET only in wording: the access reconciler's key,
// principal and sudoers files are editable-but-protected files that reads are
// allowed to see, so they belong to the write list alone.
var refusedReadPrefixes = []string{
	"/proc/",
	"/sys/",
	"/dev/",
	"/run/",
	"/var/run/",
	"/var/lock/",
}

// resolveForFileOp canonicalises a path for a file operation and refuses the
// ones no command may touch.
//
// The parent directory is resolved with EvalSymlinks before the check: a plain
// string comparison is defeated by a symlinked parent (/opt/app/etc -> /etc) or
// a bind mount, both of which name a protected file without looking like one.
//
// Every error it returns is a refusal: the path policy turned the command away.
func (h *CommandHandler) resolveForFileOp(path string, adoptionFile string) (_ string, err error) {
	defer func() { err = refusal.Wrap(err) }()
	if path == "" {
		return "", fmt.Errorf("path is required")
	}
	if !filepath.IsAbs(path) {
		return "", fmt.Errorf("path must be absolute")
	}
	if strings.ContainsRune(path, 0) {
		return "", fmt.Errorf("path contains a null byte")
	}
	clean := filepath.Clean(path)

	parent, err := filepath.EvalSymlinks(filepath.Dir(clean))
	if err != nil {
		// An unresolvable parent (missing directory, ELOOP, a component that is
		// not a directory) must still go through the checks — returning early
		// here handed back a completely unvetted path.
		if perr := checkProtectedNames(clean, adoptionFile); perr != nil {
			return "", perr
		}
		return clean, nil
	}
	resolved := filepath.Join(parent, filepath.Base(clean))

	// Identity, not spelling. /boot/firmware is vfat and case-insensitive, so
	// "/boot/firmware/CONFIG.TXT" is the same file as the protected path and
	// matches no string in the list; a bind mount does the same thing with a
	// different name, and EvalSymlinks cannot see through one. Comparing the
	// device and inode catches all three.
	if same, what := sameFileAsProtected(resolved, adoptionFile); same {
		return "", fmt.Errorf("%s is the same file as %s, which is managed by the platform", path, what)
	}

	for _, candidate := range []string{clean, resolved} {
		if err := checkProtectedNames(candidate, adoptionFile); err != nil {
			return "", err
		}
	}
	return resolved, nil
}

// readRefusedFiles are the paths no command may READ, whatever else it may do
// with them. Deliberately a different, much shorter list than protectedFiles:
// that one answers "what would strand the device if deleted", and config.txt,
// watchdog.conf and passwd are all on it while being exactly the files the
// tracked-file editor exists to show. What must never leave the device is
// credential material — above all the adoption file, whose unique_token is the
// ability to impersonate this node.
var readRefusedFiles = []string{
	"/etc/shadow",
	"/etc/shadow-",
	"/etc/gshadow",
	"/etc/gshadow-",
}

// readRefusedSuffixes catch private key material wherever it lives. The .pub
// counterparts are absent on purpose — a public key is fine to read.
var readRefusedSuffixes = []string{".pem", ".key", ".p12", ".pfx"}

// looksLikeSSHPrivateKey catches the two shapes the suffix list misses, and they
// are the two that matter most on these devices.
//
// OpenSSH private keys carry no extension: /etc/ssh/ssh_host_ed25519_key and
// ~/.ssh/id_ed25519 end in "_key" and in nothing at all, so neither matched
// ".key". The BACKEND's ValidateTrackPath has refused both since it was written
// — and that function's own comment says the agent must not depend on its
// caller, which is exactly what was happening: a read_file dispatched by any
// other path could lift a host key into a workflow output.
//
// The rules mirror the backend's deliberately, including the .pub exemption: a
// public key is fine to read, and an operator reading one is a real thing to
// want.
func looksLikeSSHPrivateKey(path string) bool {
	lower := strings.ToLower(path)
	base := filepath.Base(lower)
	if strings.HasSuffix(base, ".pub") {
		return false
	}
	// Host keys: /etc/ssh/ssh_host_<type>_key, and the _key suffix generally,
	// which is what OpenSSH names every private key it generates.
	if strings.HasPrefix(base, "ssh_host_") && strings.HasSuffix(base, "_key") {
		return true
	}
	// User keys: ~/.ssh/id_* with no .pub. Keyed on the directory as well as the
	// name, because "id_" alone would refuse ordinary files elsewhere.
	if strings.HasPrefix(base, "id_") && strings.Contains(lower, "/.ssh/") {
		return true
	}
	return false
}

// resolveForFileRead canonicalises a path for a READ and refuses the ones whose
// content must not leave the device.
//
// The read path had no agent-side enforcement at all: readFileBounded's
// O_NOFOLLOW refuses a symlinked FINAL component, but a symlinked PARENT walked
// straight through, so a directory link was enough to hand back the adoption
// file. The backend's path policy was the only thing in the way, and the agent
// must not depend on its caller for that.
//
// Every error it returns is a refusal, as for resolveForFileOp.
func (h *CommandHandler) resolveForFileRead(path string, adoptionFile string) (_ string, err error) {
	defer func() { err = refusal.Wrap(err) }()
	if path == "" {
		return "", fmt.Errorf("path is required")
	}
	if !filepath.IsAbs(path) {
		return "", fmt.Errorf("path must be absolute")
	}
	if strings.ContainsRune(path, 0) {
		return "", fmt.Errorf("path contains a null byte")
	}
	clean := filepath.Clean(path)

	resolved := clean
	if parent, err := filepath.EvalSymlinks(filepath.Dir(clean)); err == nil {
		resolved = filepath.Join(parent, filepath.Base(clean))
	}

	// Identity, not spelling: a bind mount or a case-insensitive vfat name
	// reaches the adoption file without matching any string.
	if adoptionFile != "" {
		if ti, err := os.Lstat(resolved); err == nil {
			if ai, aerr := os.Lstat(filepath.Clean(adoptionFile)); aerr == nil && os.SameFile(ti, ai) {
				return "", fmt.Errorf("%s is this node's adoption file", path)
			}
		}
	}

	for _, candidate := range []string{clean, resolved} {
		lower := strings.ToLower(candidate)
		if adoptionFile != "" && strings.EqualFold(candidate, filepath.Clean(adoptionFile)) {
			return "", fmt.Errorf("%s is this node's adoption file", candidate)
		}
		for _, p := range readRefusedFiles {
			if strings.EqualFold(candidate, p) {
				return "", fmt.Errorf("%s holds credentials and cannot be read", candidate)
			}
		}
		for _, suffix := range readRefusedSuffixes {
			if strings.HasSuffix(lower, suffix) {
				return "", fmt.Errorf("%s looks like private key material and cannot be read", candidate)
			}
		}
		if looksLikeSSHPrivateKey(candidate) {
			return "", fmt.Errorf("%s is an SSH private key and cannot be read", candidate)
		}
		for _, prefix := range refusedReadPrefixes {
			if strings.HasPrefix(lower, prefix) {
				return "", fmt.Errorf("%s is under %s, which is not a readable file", candidate, strings.TrimSuffix(prefix, "/"))
			}
		}
	}
	return resolved, nil
}

// protectedAncestors is every PROPER ancestor of a protected name — of the
// files, of the prefixes' own directories, up to "/" — lower-cased. Derived
// from the two lists above on first use, never written out as a third list
// that could drift from them.
var (
	protectedAncestorsOnce sync.Once
	protectedAncestors     map[string]struct{}
)

// ancestorsOf lists the proper ancestors of a clean absolute path, nearest
// first, ending with "/".
func ancestorsOf(clean string) []string {
	var out []string
	for d := filepath.Dir(clean); ; d = filepath.Dir(d) {
		out = append(out, d)
		if d == "/" || d == "." {
			return out
		}
	}
}

// governingDirectories is the derived set as a list: every proper ancestor of
// a protected file or prefix, plus the adoption file's when one is given.
func governingDirectories(adoptionFile string) []string {
	protectedAncestorsOnce.Do(func() {
		protectedAncestors = map[string]struct{}{}
		names := append([]string{}, protectedFiles...)
		for _, p := range protectedPrefixes {
			names = append(names, strings.TrimSuffix(p, "/"))
		}
		for _, n := range names {
			for _, a := range ancestorsOf(filepath.Clean(n)) {
				protectedAncestors[strings.ToLower(a)] = struct{}{}
			}
		}
	})
	out := make([]string, 0, len(protectedAncestors)+4)
	for a := range protectedAncestors {
		out = append(out, a)
	}
	if adoptionFile != "" {
		out = append(out, ancestorsOf(filepath.Clean(adoptionFile))...)
	}
	return out
}

// governsProtectedPath reports whether candidate is a directory that GOVERNS
// a protected name: "/", "/etc", "/etc/ssh", "/boot/firmware", … — a proper
// ancestor of one of the protected files or prefixes, or of the adoption
// file. The ownership walk keeps such a directory's owner even when an
// extraction is aimed at it: keeping /etc/shadow
// root-owned protects nothing once /etc itself belongs to the archive's
// owner, who can then replace the directory entry. Case-insensitive like the
// name check, for the same vfat reason. This is the NAME half; the object
// half is governingDirectoryIdentities below.
func governsProtectedPath(candidate, adoptionFile string) bool {
	clean := filepath.Clean(candidate)
	for _, a := range governingDirectories(adoptionFile) {
		if strings.EqualFold(a, clean) {
			return true
		}
	}
	return false
}

// fileIdentity is a filesystem object: device and inode.
type fileIdentity struct{ dev, ino uint64 }

// directoryIdentities stats each path and maps its identity to the path;
// paths that do not exist are skipped.
func directoryIdentities(paths []string) map[fileIdentity]string {
	ids := make(map[fileIdentity]string, len(paths))
	for _, p := range paths {
		var st unix.Stat_t
		if unix.Stat(p, &st) != nil {
			continue
		}
		ids[fileIdentity{uint64(st.Dev), uint64(st.Ino)}] = p
	}
	return ids
}

// governingDirectoryIdentities is the OBJECT half of governsProtectedPath:
// the identity of every governing directory that exists, derived from the
// same lists. A bind mount (`mount --bind /etc /srv/etc`) gives /etc a second
// name that no string test recognises, and the resolved path of such a
// destination compares only against protected FILES — so the root's own
// chown handed /etc to the archive's owner, and an archive entry `shadow`
// was unlinked and recreated through the alias.
// Stat'ed once per use, not cached: mounts change.
func governingDirectoryIdentities(adoptionFile string) map[fileIdentity]string {
	return directoryIdentities(governingDirectories(adoptionFile))
}

// governingObjectOf reports the governing directory that fd IS, by identity,
// or "" when it is none of them.
func governingObjectOf(fd int, ids map[fileIdentity]string) string {
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil {
		return ""
	}
	return ids[fileIdentity{uint64(st.Dev), uint64(st.Ino)}]
}

// refuseGoverningAlias refuses an extraction root that is a governing
// directory under ANOTHER name — a bind-mount alias of /etc, say. An archive
// aimed at /etc by name is an operator's deliberate (if unusual) choice and
// the walk keeps the directory's owner; one aimed at an alias of it is never
// legitimate, and the name checks on its entries would all be answered
// against the alias's spelling.
func refuseGoverningAlias(rootFD int, display string, ids map[fileIdentity]string) error {
	if governed, alias := governingAliasOf(rootFD, display, ids); alias {
		return fmt.Errorf("%s is the same directory as %s, which governs platform-managed files; refusing to extract into it under another name", display, governed)
	}
	return nil
}

// governingAliasOf reports whether the directory open at fd is a governing
// directory under a name OTHER than its own — the identity matches, the
// spelling does not.
func governingAliasOf(fd int, display string, ids map[fileIdentity]string) (string, bool) {
	governed := governingObjectOf(fd, ids)
	if governed == "" || strings.EqualFold(filepath.Clean(governed), filepath.Clean(display)) {
		return "", false
	}
	return governed, true
}

// sameFileAsProtected reports whether target is the same inode as a protected
// file under any name.
func sameFileAsProtected(target, adoptionFile string) (bool, string) {
	ti, err := os.Lstat(target)
	if err != nil {
		return false, ""
	}
	candidates := append([]string{}, protectedFiles...)
	if adoptionFile != "" {
		candidates = append(candidates, filepath.Clean(adoptionFile))
	}
	for _, p := range candidates {
		pi, perr := os.Lstat(p)
		if perr != nil {
			continue
		}
		if os.SameFile(ti, pi) {
			return true, p
		}
	}
	return false, ""
}

// readFileBounded opens a path without following a final symlink, refuses
// anything that is not a regular file, and reads at most max bytes.
//
// os.ReadFile would happily block forever on a FIFO under /run, allocate a
// machine's worth of memory on /proc/kcore, and hand back bytes that are not
// valid UTF-8 — which the proto marshal then rejects, killing the stream the
// result was travelling on.
func readFileBounded(path string, max int64) (content string, meta map[string]string, err error) {
	meta = map[string]string{}
	// Both defaulted (unset) and CAPPED (a caller-supplied max above the
	// ceiling): see DefaultReadMaxBytes. Without the cap a huge requested
	// max_bytes lets the ReadAll below allocate that much.
	if max <= 0 || max > DefaultReadMaxBytes {
		max = DefaultReadMaxBytes
	}

	// Through an anchor, never a string open. os.OpenFile with
	// O_NOFOLLOW refused a symlink at the FINAL component only; a component
	// above it swapped for a link after the caller's resolve was followed by the
	// kernel, so a read policy checked against /home/user/a/b/f could read whatever
	// /home/user/a pointed at by the time this ran. The anchor walk refuses a link
	// at any depth, and the open is relative to the directory it verified.
	target, err := openAnchored(path)
	if err != nil {
		return "", nil, err
	}
	defer target.Close()
	f, err := target.OpenRead()
	if err != nil {
		return "", nil, err
	}
	defer func() { _ = f.Close() }()

	info, err := f.Stat()
	if err != nil {
		return "", nil, err
	}
	if !info.Mode().IsRegular() {
		return "", nil, fmt.Errorf("%s is not a regular file", path)
	}

	meta["size"] = strconv.FormatInt(info.Size(), 10)
	meta["mode"] = fmt.Sprintf("%04o", info.Mode().Perm())
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		meta["owner"] = lookupUserName(int(st.Uid))
		meta["group"] = lookupGroupName(int(st.Gid))
	}

	if info.Size() > max {
		meta["truncated"] = "true"
		return "", meta, nil
	}

	// Read one byte past the cap so a file that grew between stat and read is
	// reported as truncated rather than silently cut in half — a partial file
	// that later gets applied back would corrupt the real one.
	data, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return "", nil, err
	}
	if int64(len(data)) > max {
		meta["truncated"] = "true"
		return "", meta, nil
	}
	if !utf8.Valid(data) {
		meta["binary"] = "true"
		return "", meta, nil
	}
	return string(data), meta, nil
}

// handleDeleteFile removes one regular file. Idempotent by design: a delete of
// something already gone reports success, so a retry after a lost reply does not
// look like a failure.
func (h *CommandHandler) handleDeleteFile(commandID string, cmd *proto.DeleteFileCommand) error {
	h.logger.Info("delete file command received", "command_id", commandID, "path", cmd.Path, "backup", cmd.Backup)
	h.reportCommandStatus(commandID, "in_progress", 0, fmt.Sprintf("Removing %s", cmd.Path))

	path, err := h.resolveForFileOp(cmd.Path, h.adoptionFilePath)
	if err != nil {
		h.reportCommandResult(commandID, "failed", err.Error(), nil)
		return err
	}

	// Anchor to the resolved PARENT once and do everything through that fd.
	// This block used to re-walk the path string three times —
	// Lstat, Lstat of the backup, Rename/Remove — and any unprivileged local
	// user able to swap a parent component between them retargeted the delete.
	target, err := openAnchored(path)
	if err != nil {
		if errIsNotExist(err) {
			h.reportCommandResult(commandID, "success", "file was already absent", map[string]string{
				"path": path, "existed": "false",
			})
			return nil
		}
		h.reportCommandResult(commandID, "failed", err.Error(), nil)
		return err
	}
	defer target.Close()

	info, err := target.Lstat()
	if errIsNotExist(err) {
		h.reportCommandResult(commandID, "success", "file was already absent", map[string]string{
			"path": path, "existed": "false",
		})
		return nil
	}
	if err != nil {
		h.reportCommandResult(commandID, "failed", err.Error(), nil)
		return err
	}
	if !info.Mode().IsRegular() {
		msg := fmt.Sprintf("%s is not a regular file", path)
		h.reportCommandResult(commandID, "failed", msg, nil)
		return fmt.Errorf("%s", msg)
	}

	if cmd.Backup {
		backupName := filepath.Base(path) + ".orchestrator.deleted"
		backup := path + ".orchestrator.deleted"
		exists, serr := target.SiblingExists(backupName)
		if serr != nil {
			h.reportCommandResult(commandID, "failed", serr.Error(), nil)
			return serr
		}
		if exists {
			msg := fmt.Sprintf("%s already exists; remove it before deleting again", backup)
			h.reportCommandResult(commandID, "failed", msg, nil)
			return fmt.Errorf("%s", msg)
		}
		if rerr := target.RenameTo(backupName); rerr != nil {
			h.reportCommandResult(commandID, "failed", "backup rename failed: "+rerr.Error(), nil)
			return rerr
		}
		h.reportCommandResult(commandID, "success", "file renamed", map[string]string{
			"path": path, "existed": "true", "backup": backup,
		})
		return nil
	}

	if rerr := target.Unlink(); rerr != nil {
		h.reportCommandResult(commandID, "failed", rerr.Error(), nil)
		return rerr
	}
	h.reportCommandResult(commandID, "success", "file removed", map[string]string{
		"path": path, "existed": "true",
	})
	return nil
}

// lookupUserName resolves a uid to a name, falling back to the numeric form.
func lookupUserName(uid int) string {
	if name, err := lookupID("/etc/passwd", uid); err == nil && name != "" {
		return name
	}
	return strconv.Itoa(uid)
}

// lookupGroupName resolves a gid to a name, falling back to the numeric form.
func lookupGroupName(gid int) string {
	if name, err := lookupID("/etc/group", gid); err == nil && name != "" {
		return name
	}
	return strconv.Itoa(gid)
}

// lookupID reads a passwd/group-shaped file and returns the name for an id.
// os/user's cgo resolver is unavailable in the static netboot build, and the
// pure-Go fallback reads these same files anyway.
func lookupID(file string, id int) (string, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return "", err
	}
	want := strconv.Itoa(id)
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) >= 3 && fields[2] == want {
			return fields[0], nil
		}
	}
	return "", nil
}
