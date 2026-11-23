//go:build linux

package handlers

import (
	"archive/tar"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
	"time"

	"agent/pkg/domain/redact"
	"agent/pkg/domain/refusal"
	proto "agent/pkg/infrastructure/grpc/proto"
)

// softwareCmdTimeout bounds a single package/service operation.
const softwareCmdTimeout = 30 * time.Minute

// downloadTimeout bounds a download_file fetch so a stalled/black-holed server
// cannot wedge the agent's (synchronous) command loop forever.
const downloadTimeout = 30 * time.Minute

// maxDownloadBytes (the download byte cap) lives in download_bounds.go.

// maxExtractBytes caps the total uncompressed bytes written by a tar extract.
const maxExtractBytes = 16 << 30 // 16 GiB

// maxExtractEntries caps the number of entries in an extracted archive.
const maxExtractEntries = 200000

// unitNameRe is the strict allowlist for a systemd unit name (blocks path
// traversal and newline/control chars).
var unitNameRe = regexp.MustCompile(`^[A-Za-z0-9@._-]+$`)

// platformManagedUnits are the units manage_service may neither write nor
// control. Both binaries are here: the full agent and the telemetry-only
// Watcher, since either one is how the platform reaches the device at all.
//
// watchdog.service is deliberately NOT here. The platform has its own managed
// path for it (system.apply_watchdog, and the uninstall script's deliberate
// disarm), and an operator taking a node's watchdog down by hand during
// maintenance is a real thing to want. Adding it would refuse that with no
// alternative.
var platformManagedUnits = map[string]bool{
	"orchestrator-agent.service":   true,
	"orchestrator-watcher.service": true,
}

// platformManagedUnit reports whether a unit name is one the platform owns.
// Case-insensitive: systemd unit names are case-sensitive, but a refusal that
// can be stepped around by capitalising a letter is not a refusal.
func platformManagedUnit(name string) bool {
	return platformManagedUnits[strings.ToLower(strings.TrimSpace(name))]
}

// handleInstallPackages installs OS packages with apt-get (non-interactive).
func (h *CommandHandler) handleInstallPackages(commandID string, cmd *proto.InstallPackagesCommand) error {
	h.logger.Info("install packages command received", "command_id", commandID, "packages", cmd.Packages)
	h.reportCommandStatus(commandID, "in_progress", 0, "Installing packages")

	if len(cmd.Packages) == 0 {
		h.reportCommandResult(commandID, "failed", "no packages specified", nil)
		return fmt.Errorf("no packages specified")
	}
	if _, err := exec.LookPath("apt-get"); err != nil {
		msg := "install_packages requires apt-get (Debian/Ubuntu); not found on this node"
		h.reportCommandResult(commandID, "failed", msg, nil)
		return fmt.Errorf("%s", msg)
	}

	env := append(os.Environ(), "DEBIAN_FRONTEND=noninteractive")
	var out strings.Builder
	// One lock-wait budget for the whole command (see packageLockWait).
	lockWait := h.packageLockWaitFor(commandID)
	if cmd.Update {
		h.reportCommandStatus(commandID, "in_progress", 20, "Updating package lists")
		// DPkg::Lock::Timeout: wait on a held dpkg lock instead of failing
		// instantly — the unattended_upgrades utility makes apt-daily hold it
		// at random times fleet-wide.
		//
		// Waited for here first, with progress reports and a named holder
		// (packageLockWait), so apt's own silent wait only covers a race.
		var stdout string
		lockWait.locks, lockWait.progress = aptListsLockFiles, 20
		if err := lockWait.run(func() (bool, error) {
			var err error
			stdout, err = runWithEnv(env, softwareCmdTimeout, "apt-get", "-o", "DPkg::Lock::Timeout=300", "update")
			return err != nil && aptLockBusy(stdout), err
		}); err != nil {
			out.WriteString(stdout)
			// truncateOutput, like the success path below: an unbounded value
			// here rides one gRPC frame and an oversized frame tears down the
			// node's stream instead of failing the command.
			h.reportCommandResult(commandID, "failed", "apt-get update failed: "+err.Error(),
				map[string]string{"stdout": truncateOutput(out.String())})
			return err
		} else {
			out.WriteString(stdout)
		}
	}

	// Reject option-looking or path tokens: apt-get accepts options and local
	// .deb paths positionally, so a token like "-oDPkg::..." or "/tmp/x.deb"
	// would change behavior. The "--" terminator then pins the rest as names.
	for _, p := range cmd.Packages {
		if strings.HasPrefix(p, "-") || strings.Contains(p, "/") {
			msg := fmt.Sprintf("invalid package name %q", p)
			h.reportCommandResult(commandID, "failed", msg, nil)
			return fmt.Errorf("%s", msg)
		}
	}
	h.reportCommandStatus(commandID, "in_progress", 50, "Installing packages")
	args := append([]string{"-o", "DPkg::Lock::Timeout=300", "install", "-y", "--no-install-recommends", "--"}, cmd.Packages...)
	var stdout string
	lockWait.locks, lockWait.progress = dpkgLockFiles, 50
	err := lockWait.run(func() (bool, error) {
		var err error
		stdout, err = runWithEnv(env, softwareCmdTimeout, "apt-get", args...)
		return err != nil && aptLockBusy(stdout), err
	})
	out.WriteString(stdout)
	if err != nil {
		h.reportCommandResult(commandID, "failed", "apt-get install failed: "+err.Error(),
			map[string]string{"stdout": truncateOutput(out.String())})
		return err
	}

	h.reportCommandResult(commandID, "success", "packages installed",
		map[string]string{"stdout": truncateOutput(out.String())})
	return nil
}

// aptLockBusy reports whether apt-get failed because another process held a
// lock ("Could not get lock /var/lib/dpkg/lock-frontend. It is held by
// process ..."), as opposed to a real failure.
func aptLockBusy(output string) bool {
	return strings.Contains(output, "Could not get lock") || strings.Contains(output, "Unable to acquire the dpkg frontend lock")
}

// handleManageService writes an optional systemd unit and controls it.
func (h *CommandHandler) handleManageService(commandID string, cmd *proto.ManageServiceCommand) error {
	h.logger.Info("manage service command received", "command_id", commandID, "name", cmd.Name, "action", cmd.Action)
	h.reportCommandStatus(commandID, "in_progress", 0, "Managing service")

	name := strings.TrimSpace(cmd.Name)
	if name == "" {
		h.reportCommandResult(commandID, "failed", "unit name is required", nil)
		return refusal.Wrap(fmt.Errorf("unit name is required"))
	}
	if !strings.Contains(name, ".") {
		name += ".service"
	}
	// Strict allowlist: blocks path traversal into /etc/systemd/system as well
	// as newline/tab/control chars that would land in the unit path or a
	// systemctl arg.
	if !unitNameRe.MatchString(name) {
		h.reportCommandResult(commandID, "failed", "invalid unit name", nil)
		return refusal.Wrap(fmt.Errorf("invalid unit name %q", name))
	}

	// The agent's own units are refused, whatever the action.
	//
	// unitNameRe permits "orchestrator-agent.service", and every other
	// file-writing handler routes through resolveForFileOp, whose protectedFiles
	// names that exact unit — this one bypassed it and the dispatch builder only
	// trimmed the name. So a playbook could overwrite the packaged unit, which is
	// root code on the next boot, or `disable_now` it, which takes the node off
	// the platform permanently with no way back but a physical visit.
	//
	// By NAME rather than by path, because the control half never touches a path
	// at all: systemctl takes the unit name, so a check on the file cannot see a
	// stop or a disable coming.
	if platformManagedUnit(name) {
		msg := name + " is managed by the platform; use the agent update and Watcher controls instead"
		h.reportCommandResult(commandID, "failed", msg, nil)
		return refusal.Wrap(fmt.Errorf("%s", msg))
	}

	// The action is validated before anything is written: an unknown action
	// must leave no unit on disk and no daemon-reload behind.
	scArgs, err := serviceActionArgs(cmd.Action, name)
	if err != nil {
		h.reportCommandResult(commandID, "failed", "unknown action: "+cmd.Action, nil)
		return refusal.Wrap(err)
	}

	if strings.TrimSpace(cmd.UnitContent) != "" {
		// Through the same path policy every other file-writing handler uses. The
		// name guard above already refuses the agent's units; this covers what a
		// name cannot express — a unit directory that is a symlink into a
		// protected tree, or a name that resolves onto a protected inode.
		unitPath, err := h.resolveForFileOp(filepath.Join("/etc/systemd/system", name), h.adoptionFilePath)
		if err != nil {
			h.reportCommandResult(commandID, "failed", err.Error(), nil)
			return err
		}
		if err := atomicWriteFile(unitPath, []byte(cmd.UnitContent), 0o644); err != nil {
			h.reportCommandResult(commandID, "failed", "failed to write unit: "+err.Error(), nil)
			return err
		}
		if _, err := runWithEnv(nil, softwareCmdTimeout, "systemctl", "daemon-reload"); err != nil {
			h.reportCommandResult(commandID, "failed", "daemon-reload failed: "+err.Error(), nil)
			return err
		}
	}

	h.reportCommandStatus(commandID, "in_progress", 50, "Applying service action")
	for _, args := range scArgs {
		if stdout, err := runWithEnv(nil, softwareCmdTimeout, "systemctl", args...); err != nil {
			h.reportCommandResult(commandID, "failed",
				fmt.Sprintf("systemctl %s failed: %v", strings.Join(args, " "), err),
				map[string]string{"stdout": truncateOutput(stdout)})
			return err
		}
	}

	// Report whether the unit is now active (best-effort; "status" only reads).
	activeOut, _ := runWithEnv(nil, softwareCmdTimeout, "systemctl", "is-active", name)
	active := strings.TrimSpace(activeOut)
	h.reportCommandResult(commandID, "success", "service action applied", map[string]string{
		"active": active,
	})
	return nil
}

// handleDownloadFile downloads a file over http(s), optionally verifying a
// SHA-256 and unpacking a tar archive.
func (h *CommandHandler) handleDownloadFile(commandID string, cmd *proto.DownloadFileCommand) error {
	// Redacted: a download_file URL is operator-authored and routinely carries a
	// resolved {{secrets.*}} value in its query (a repo token, a presigned
	// capability). Logging it in full puts that credential in journald on the
	// device, readable through the node web terminal.
	h.logger.Info("download file command received", "command_id", commandID, "url", redactURL(cmd.Url), "dest", cmd.DestPath)
	h.reportCommandStatus(commandID, "in_progress", 0, "Downloading file")

	if strings.TrimSpace(cmd.Url) == "" || strings.TrimSpace(cmd.DestPath) == "" {
		h.reportCommandResult(commandID, "failed", "url and dest_path are required", nil)
		return fmt.Errorf("url and dest_path are required")
	}

	// Same path policy as write_file, which this handler had never run. Until
	// now dest_path was validated for non-emptiness only, so
	// dest_path=/usr/bin/orchestrator-agent or the agent's own systemd unit
	// succeeded and reported success — the largest "strand a node" primitive in
	// the agent, and asymmetric with its sibling for no stated reason.
	//
	// With extract=true the destination is a DIRECTORY the archive is unpacked
	// into, so the same check has to be applied to it: extractTar is hardened
	// against path escape but not against being aimed at / on purpose.
	destPath := cmd.DestPath
	if !isPlatformConfigPath(cmd.DestPath) {
		resolved, rerr := h.resolveForFileOp(cmd.DestPath, h.adoptionFilePath)
		if rerr != nil {
			h.reportCommandResult(commandID, "failed", rerr.Error(), nil)
			return rerr
		}
		destPath = resolved
	}
	if cmd.Extract {
		if clean := filepath.Clean(destPath); clean == "/" {
			msg := "refusing to extract into / — name the directory the archive belongs in"
			h.reportCommandResult(commandID, "failed", msg, nil)
			return fmt.Errorf("%s", msg)
		}
	}

	// Download to a private temp file FIRST (mode 0600 via CreateTemp, so a
	// secret is never briefly world-readable at its final path), verify the
	// checksum if one was supplied — on BOTH the plain and extract paths — and
	// only then put it in place. This closes the "extract skips the checksum"
	// gap and the TOCTOU window on the plain path.
	ctx, cancel := context.WithTimeout(context.Background(), downloadTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, cmd.Url, nil)
	if err != nil {
		h.reportCommandResult(commandID, "failed", "invalid url: "+err.Error(), nil)
		return err
	}
	for k, v := range cmd.Headers {
		req.Header.Set(k, v)
	}
	client, headersDropped := newDownloadFileClient(downloadTimeout, cmd.Headers)
	resp, err := client.Do(req)
	if err != nil {
		// A transport failure is a *url.Error quoting the WHOLE request URL,
		// userinfo and query included. The status report is redacted at its
		// choke point, but the returned error travels to the dispatcher's log
		// line as is — so it is rebuilt without the URL here, keeping its
		// chain for errors.Is/As.
		err = redact.Error(err)
		h.reportCommandResult(commandID, "failed", "download failed: "+err.Error(), nil)
		return fmt.Errorf("failed to download: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		msg := fmt.Sprintf("download failed: HTTP %d", resp.StatusCode)
		h.reportCommandResult(commandID, "failed", msg, nil)
		return fmt.Errorf("%s", msg)
	}

	// Stage the temp on the SAME filesystem as the destination so the final
	// rename is atomic (not a cross-device EXDEV failure) and a large archive
	// does not fill a RAM-backed /tmp.
	stageDir := filepath.Dir(destPath)
	if err := os.MkdirAll(stageDir, 0o755); err != nil {
		h.reportCommandResult(commandID, "failed", "mkdir failed: "+err.Error(), nil)
		return err
	}
	// Re-resolve now that the parent exists (same reason as handleWriteFile):
	// an unresolvable parent left destPath unresolved, and the anchor below
	// refuses any symlink component.
	if !isPlatformConfigPath(cmd.DestPath) {
		resolved, rerr := h.resolveForFileOp(destPath, h.adoptionFilePath)
		if rerr != nil {
			h.reportCommandResult(commandID, "failed", rerr.Error(), nil)
			return rerr
		}
		destPath = resolved
	}
	// Anchor the destination's parent ONCE and stage, rename and chown through
	// that descriptor. Before this the temp was created and the
	// final rename performed by path string — two more walks of a directory an
	// unprivileged local user may own, each a chance to swap a component for a
	// symlink and have root rename the download somewhere else.
	dest, err := openAnchored(destPath)
	if err != nil {
		h.reportCommandResult(commandID, "failed", err.Error(), nil)
		return err
	}
	defer dest.Close()
	tmpName, tmpF, err := dest.CreateTemp()
	if err != nil {
		h.reportCommandResult(commandID, "failed", "temp create failed: "+err.Error(), nil)
		return err
	}
	defer dest.RemoveTemp(tmpName)
	hash := sha256.New()
	// A response longer than the cap is a FAILURE here, before the mode, the
	// checksum, the extraction or the rename — the staged temp is removed by
	// the deferred RemoveTemp and the previous destination is never touched.
	// An advertised length past the cap is refused before a
	// byte is read; a body that turns out longer is refused at cap+1.
	if resp.ContentLength > downloadByteCap {
		tmpF.Close()
		msg := fmt.Sprintf("download refused: the server advertises %d bytes, more than the %d-byte cap", resp.ContentLength, downloadByteCap)
		h.reportCommandResult(commandID, "failed", msg, nil)
		return fmt.Errorf("%w: %s", errDownloadTooLarge, msg)
	}
	if _, err := copyDownloadBounded(io.MultiWriter(tmpF, hash), resp.Body, downloadByteCap); err != nil {
		tmpF.Close()
		h.reportCommandResult(commandID, "failed", "download read failed: "+err.Error(), nil)
		return err
	}
	// The mode goes on through the DESCRIPTOR, while the file is still open and
	// before anything refers to it by name again.
	//
	// `os.Chmod(tmpPath, …)` is chmod(2) and follows symlinks. The temp is
	// staged in the DESTINATION's parent — routinely a directory an
	// unprivileged local user owns, and this product manufactures exactly such
	// users — so between the create and the chmod that user can unlink the
	// root-owned temp (a home directory is not sticky) and plant a symlink at
	// the same name. The agent, as root, then chmods the LINK TARGET: 0644 on
	// /etc/shadow, or whatever mode the block asked for. The window is the whole
	// download, minutes for a large artifact, and re-armed on every run.
	//
	// fchmod cannot be redirected, which is what `AtomicWrite` has always done
	// and what the anchored chown beside it made structural — it did
	// not reach here while the temp was a plain string from os.CreateTemp; it
	// is an anchored entry now, and the descriptor is still the right handle.
	mode := parseMode(cmd.Mode)
	if mode == 0 {
		mode = 0o644
	}
	if err := tmpF.Chmod(mode); err != nil {
		tmpF.Close()
		h.reportCommandResult(commandID, "failed", "chmod failed: "+err.Error(), nil)
		return fmt.Errorf("failed to set mode on the staged download: %w", err)
	}
	if cmd.Checksum != "" {
		if got := hex.EncodeToString(hash.Sum(nil)); !strings.EqualFold(got, cmd.Checksum) {
			tmpF.Close()
			msg := "checksum verification failed"
			h.reportCommandResult(commandID, "failed", msg, nil)
			return fmt.Errorf("%s", msg)
		}
	}

	if cmd.Extract {
		// Extract from the SAME descriptor the bytes were written and hashed
		// through, rewound — never a re-open by name. A re-open in this
		// directory means the checksum was verified over one file and a
		// different one was unpacked as root, which is a worse outcome than the
		// chmod above: it is arbitrary content, not just a mode.
		defer tmpF.Close()
		if _, err := tmpF.Seek(0, io.SeekStart); err != nil {
			h.reportCommandResult(commandID, "failed", "rewind failed: "+err.Error(), nil)
			return err
		}
		// ONE root descriptor for the whole extraction-and-ownership
		// lifecycle: the destination
		// is created and opened component by component from "/", never by
		// a multi-component open(2) that O_NOFOLLOW guards only at its last
		// step, and the same descriptor carries into the ownership walk —
		// a reopen by path between the two was the one moment an ancestor
		// swap could redirect a root chown to an unrelated tree.
		rootFD, err := openOrCreateDirNoSymlinks(destPath)
		if err != nil {
			h.reportCommandResult(commandID, "failed", "extract root: "+err.Error(), nil)
			return err
		}
		defer unix.Close(rootFD)
		// The root is judged by OBJECT identity as well as by name: a
		// bind-mount alias of /etc passes every string check (the file
		// policy compares against protected FILES, and the entries' names
		// are spelled under the alias), so it is refused outright here.
		governingIDs := governingDirectoryIdentities(h.adoptionFilePath)
		if err := refuseGoverningAlias(rootFD, destPath, governingIDs); err != nil {
			h.reportCommandResult(commandID, "failed", err.Error(), nil)
			return err
		}
		protected := func(path string) error { return checkProtectedNames(path, h.adoptionFilePath) }
		created, err := extractTarIntoTracked(rootFD, tmpF, cmd.Url, destPath, protected, governingIDs)
		if err != nil {
			h.reportCommandResult(commandID, "failed", "extract failed: "+err.Error(), nil)
			return err
		}
		if cmd.Owner != "" {
			// Names AND boundaries: a protected name keeps
			// its owner, so does any directory governing one — by name or by
			// object — and so does any object the archive did not bring (a
			// hardlink alias, a mount point) whatever it is called.
			applyOwnerRecursiveWith(rootFD, destPath, cmd.Owner, ownershipPolicy{
				protected:    protected,
				governs:      func(path string) bool { return governsProtectedPath(path, h.adoptionFilePath) },
				governingIDs: governingIDs,
				created:      created,
			}, h)
		}
	} else {
		// The mode is already on the file (through the descriptor, above), so it
		// is never visible at its real path with the wrong 0600.
		tmpF.Close()
		// Rename through the anchor the temp was created in: same directory
		// object at both ends, so neither the source nor the destination can be
		// retargeted by a rename or a planted link after the check.
		if err := dest.ReplaceWithTemp(tmpName); err != nil {
			h.reportCommandResult(commandID, "failed", "rename failed: "+err.Error(), nil)
			return err
		}
		if cmd.Owner != "" {
			// Through the same anchor. A path-based chown here follows a final
			// symlink, and the parent directory of a download target is
			// routinely writable by an unprivileged local user — which is the
			// whole shape of the escalation.
			applyOwnerAnchored(dest, cmd.Owner, h)
		}
	}

	result := map[string]string{"dest_path": destPath}
	if headersDropped() {
		result["headers_dropped_on_redirect"] = "true"
	}
	h.reportCommandResult(commandID, "success", "file downloaded", result)
	return nil
}

// handleWriteFile writes an arbitrary file atomically.
func (h *CommandHandler) handleWriteFile(commandID string, cmd *proto.WriteFileCommand) error {
	h.logger.Info("write file command received", "command_id", commandID, "path", cmd.Path)
	h.reportCommandStatus(commandID, "in_progress", 0, "Writing file")

	if strings.TrimSpace(cmd.Path) == "" {
		h.reportCommandResult(commandID, "failed", "path is required", nil)
		return fmt.Errorf("path is required")
	}
	// The same guard delete_file uses. Without it the agent refused to delete
	// its own unit file but would overwrite it — which is root code execution
	// on the next boot — and the platform's list is the only thing that stood
	// between an edit and an unbootable device.
	//
	// The boot config is the deliberate exception: editing it is the original
	// feature this whole panel grew out of, and the platform owns that path.
	//
	// Act on the RESOLVED path, not the one the command carried. Validating the
	// symlink-resolved identity and then writing the raw string means the check
	// and the write can be about two different files: /etc/app/conf passes
	// because its resolved target is unprotected, and the write follows the
	// symlink to wherever it actually points. Same value, one variable.
	path := cmd.Path
	if !isPlatformConfigPath(cmd.Path) {
		resolved, err := h.resolveForFileOp(cmd.Path, h.adoptionFilePath)
		if err != nil {
			h.reportCommandResult(commandID, "failed", err.Error(), nil)
			return err
		}
		path = resolved
	} else {
		path = canonicalPlatformConfigPath(cmd.Path)
	}
	// The directory must exist before it can be anchored.
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		h.reportCommandResult(commandID, "failed", "mkdir failed: "+err.Error(), nil)
		return err
	}
	// Resolve AGAIN now that the parent exists. When it did not, resolveForFileOp
	// could only hand back the cleaned string, symlinks and all, and the anchor
	// below refuses any symlink component — so /var/run/new/f,
	// whose ancestor is a legitimate link, would fail here for the wrong reason.
	// Re-running the policy on the now-resolvable path also re-checks the
	// protected names against where the write will actually land.
	if !isPlatformConfigPath(cmd.Path) {
		resolved, err := h.resolveForFileOp(path, h.adoptionFilePath)
		if err != nil {
			h.reportCommandResult(commandID, "failed", err.Error(), nil)
			return err
		}
		path = resolved
	} else {
		path = canonicalPlatformConfigPath(cmd.Path)
	}

	// Anchor to the resolved PARENT once and do everything through that fd.
	// This handler used to re-walk the path string four times —
	// the regular-file check, the backup stat, the mode/owner stat and the
	// atomic write — and any unprivileged local user able to swap a parent
	// component between them retargeted a root-owned write.
	target, err := openAnchored(path)
	if err != nil {
		h.reportCommandResult(commandID, "failed", err.Error(), nil)
		return err
	}
	defer target.Close()

	// Refuse a non-regular target. The write renames a fresh inode into
	// place, so writing /etc/resolv.conf (a symlink into /run) would silently
	// replace the link with a static file and break DNS at the next resolved
	// restart. The read path already refuses symlinks; this makes the two agree.
	existing, statErr := target.Lstat()
	if statErr == nil && !existing.Mode().IsRegular() {
		msg := fmt.Sprintf("%s is not a regular file", path)
		h.reportCommandResult(commandID, "failed", msg, nil)
		return fmt.Errorf("%s", msg)
	}

	if cmd.Backup && statErr == nil {
		backupName := filepath.Base(path) + ".orchestrator.bak"
		exists, berr := target.SiblingExists(backupName)
		if berr != nil {
			h.reportCommandResult(commandID, "failed", berr.Error(), nil)
			return berr
		}
		if !exists {
			// Through the ANCHOR, not the path string: a re-walk here is the
			// same TOCTOU the anchor exists to close, and what it returns is
			// what the backup preserves. Bounded because a bare read could
			// block forever on a FIFO or allocate a multi-gigabyte file, and
			// this runs on the agent's single command goroutine.
			data, rerr := target.ReadBounded(8 * 1024 * 1024)
			if rerr != nil {
				h.reportCommandResult(commandID, "failed", "backup read failed: "+rerr.Error(), nil)
				return rerr
			}
			// Preserve the original's mode (a 0600 config must not be backed up
			// world-readable) and owner; refuse to proceed if the backup cannot
			// be written rather than overwrite without a safety copy.
			if werr := target.WriteSibling(backupName, data, existing.Mode().Perm()); werr != nil {
				h.reportCommandResult(commandID, "failed", "backup write failed: "+werr.Error(), nil)
				return werr
			}
			if st, ok := existing.Sys().(*syscall.Stat_t); ok {
				_ = unixFchownatSibling(target, backupName, int(st.Uid), int(st.Gid))
			}
		}
	}
	// Default to what the file already is, not to 0644. atomicWriteFile renames
	// a fresh inode into place, so without this an applied edit silently turns a
	// 0600 root:shadow file into 0644 root:root — the platform would publish a
	// secret while reporting success.
	mode := os.FileMode(0o644)
	ownerName, groupName := cmd.Owner, ""
	// Reuse the stat already taken through the anchor rather than walking the
	// path again.
	if statErr == nil && existing.Mode().IsRegular() {
		mode = existing.Mode().Perm()
		if st, ok := existing.Sys().(*syscall.Stat_t); ok {
			if ownerName == "" {
				ownerName = strconv.Itoa(int(st.Uid))
				groupName = strconv.Itoa(int(st.Gid))
			}
		}
	}
	if m := parseMode(cmd.Mode); m != 0 {
		mode = m
	}
	validator := writeValidatorFor(path)
	if validator == writeValidatorSudoers {
		if err := checkSudoersCandidate([]byte(cmd.Content)); err != nil {
			err = refusal.Wrap(err)
			h.reportCommandResult(commandID, "failed", err.Error(), nil)
			return err
		}
	}
	// What sshd's check restores on a rejection: the previous content, or no
	// file at all. Read through the anchor before the write replaces it.
	var previous []byte
	if validator == writeValidatorSSHD && statErr == nil {
		data, rerr := target.ReadBounded(8 * 1024 * 1024)
		if rerr != nil {
			h.reportCommandResult(commandID, "failed", "read before write failed: "+rerr.Error(), nil)
			return rerr
		}
		previous = data
	}
	if err := target.AtomicWrite([]byte(cmd.Content), mode); err != nil {
		h.reportCommandResult(commandID, "failed", "write failed: "+err.Error(), nil)
		return err
	}
	if validator == writeValidatorSSHD {
		if verr := h.validateSSHDConfig("/"); verr != nil && !errors.Is(verr, exec.ErrNotFound) {
			var rerr error
			if statErr == nil {
				rerr = target.AtomicWrite(previous, existing.Mode().Perm())
				if st, ok := existing.Sys().(*syscall.Stat_t); ok && rerr == nil {
					_ = target.Chown(int(st.Uid), int(st.Gid))
				}
			} else {
				rerr = target.Unlink()
			}
			msg := "sshd rejected the configuration, the previous file was restored: " + verr.Error()
			if rerr != nil {
				msg = "sshd rejected the configuration and restoring the previous file failed (" +
					rerr.Error() + "): " + verr.Error()
			}
			err := refusal.Wrap(errors.New(msg))
			h.reportCommandResult(commandID, "failed", msg, nil)
			return err
		}
	}
	// No chmod here: AtomicWrite already applied `mode`, which already carries
	// cmd.Mode. A path-based one would also be a re-walk of the string the
	// anchor exists to stop trusting.
	if cmd.Owner != "" {
		applyOwnerAnchored(target, cmd.Owner, h)
	}
	if cmd.Owner == "" && ownerName != "" && groupName != "" {
		// Restore the original ownership the rename dropped, through the anchor.
		if uid, uerr := strconv.Atoi(ownerName); uerr == nil {
			if gid, gerr := strconv.Atoi(groupName); gerr == nil {
				_ = target.Chown(uid, gid)
			}
		}
	}
	h.reportCommandResult(commandID, "success", "file written", map[string]string{"path": path})
	return nil
}

// --- helpers ---

// runWithEnv runs a command with a timeout and returns combined output.
func runWithEnv(env []string, timeout time.Duration, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	if env != nil {
		cmd.Env = env
	}
	// Bounded output, a bounded wait after the kill, and the kill aimed at
	// the whole process GROUP. This helper runs package
	// managers, service management, Docker and the network agents inline on
	// the inbound command loop: a grandchild that kept the output pipe open
	// after the child died parked that loop past the advertised timeout,
	// and an unusually chatty command grew its buffer without limit. The
	// same shape run_script has carried since it was hardened.
	out := newBoundedBuffer()
	cmd.Stdout = out
	cmd.Stderr = out
	cmd.WaitDelay = 5 * time.Second
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
	err := cmd.Run()
	text := out.String()
	if out.Truncated() {
		text += "\n[output truncated]"
	}
	if ctx.Err() == context.DeadlineExceeded {
		return text, fmt.Errorf("%s timed out after %s", name, timeout)
	}
	if errors.Is(err, exec.ErrWaitDelay) {
		// The child exited; a descendant still held the pipe. The result
		// is the child's, and it is reported as such.
		if cmd.ProcessState != nil && cmd.ProcessState.Success() {
			return text, nil
		}
		return text, fmt.Errorf("%s: a child process kept the output open after exit", name)
	}
	return text, err
}

// atomicWriteFile writes content to a temp file then renames it into place,
// syncing both the file and its parent directory.
func atomicWriteFile(path string, content []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	// A predictable temp name opened without O_EXCL is a local privilege
	// escalation once arbitrary paths are writable: anyone who can create files
	// in the directory pre-plants "<path>.orchestrator.tmp" as a symlink and the
	// root agent writes through it.
	f, err := os.CreateTemp(dir, ".orchestrator-*.tmp")
	if err != nil {
		return err
	}
	tmp := f.Name()
	if cerr := f.Chmod(mode); cerr != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return cerr
	}
	if _, err := f.Write(content); err != nil {
		f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

// extractTar unpacks a (optionally gz/xz/zst-compressed) tar stream into dir.
// It is hardened against hostile archives (a downloaded artifact is untrusted):
// lexical zip-slip, symlink-indirection escape (a symlink entry followed by a
// file written THROUGH it), absolute/escaping symlink & hardlink targets,
// setuid/setgid bit smuggling, and decompression bombs (byte + entry caps).
func extractTar(r io.Reader, sourceURL, dir string) error {
	rootFD, err := openOrCreateDirNoSymlinks(filepath.Clean(dir))
	if err != nil {
		return err
	}
	defer unix.Close(rootFD)
	return extractTarInto(rootFD, r, sourceURL, dir, nil)
}

// openOrCreateDirNoSymlinks opens dir as an O_PATH directory descriptor,
// walking from "/" one component at a time with O_NOFOLLOW and creating the
// missing components on the way. A symlink at any
// depth is refused by name, whether it was there before or appeared during
// the walk; MkdirAll on the path string would have followed it.
func openOrCreateDirNoSymlinks(dir string) (int, error) {
	if !filepath.IsAbs(dir) {
		return -1, fmt.Errorf("%s is not an absolute path", dir)
	}
	dir = filepath.Clean(dir)
	rootFD, err := unix.Open("/", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, &os.PathError{Op: "open", Path: "/", Err: err}
	}
	defer unix.Close(rootFD)
	comps, err := entryComponents("/", dir)
	if err != nil {
		return -1, err
	}
	fd, _, err := walkAnchored(rootFD, "/", comps, true, nil)
	return fd, err
}

// extractTarInto unpacks the archive below rootFD, an already-anchored
// descriptor for dir (the plain extractTar above creates one for the tests).
// protected, when set, is asked about every entry's target path (and a
// hardlink's source) BEFORE anything is unlinked or created: the destination
// itself passed the file-operation policy, but "/etc" is not a protected
// name while "/etc/shadow" inside an archive aimed at it is.
func extractTarInto(rootFD int, r io.Reader, sourceURL, dir string, protected func(string) error) error {
	_, err := extractTarIntoTracked(rootFD, r, sourceURL, dir, protected, nil)
	return err
}

// extractTarIntoTracked is extractTarInto that also reports the regular
// files and hardlinks THIS extraction created, keyed by their full path, so
// the ownership walk that follows can tell an archive's own hardlink pair
// from a pre-existing alias to something outside the tree.
// governingIDs, when set, refuses any entry whose path crosses an existing
// directory that is a governing directory under another name (walkAnchored).
//
// A refused archive leaves nothing behind: when r can be rewound (the
// download path hands over its staging descriptor) the whole archive is read
// and judged once WITHOUT writing — every name, link target, hardlink source,
// protected-name check, entry and byte cap, the decoder's completion, and the
// paths the archive's own members create (archiveLayout: a member reached
// through a symlink or file an earlier member made) — and only an archive that
// passes is unpacked. Refusals that depend on the destination's own state (a
// symlinked or aliased component it already held, met during the walk) can
// still stop the unpack part-way.
func extractTarIntoTracked(rootFD int, r io.Reader, sourceURL, dir string, protected func(string) error, governingIDs map[fileIdentity]string) (map[string]struct{}, error) {
	if rs, ok := r.(io.ReadSeeker); ok {
		start, err := rs.Seek(0, io.SeekCurrent)
		if err != nil {
			return nil, fmt.Errorf("cannot rewind the archive: %w", err)
		}
		if _, err := extractTarPass(rootFD, rs, sourceURL, dir, protected, governingIDs, false); err != nil {
			return nil, err
		}
		if _, err := rs.Seek(start, io.SeekStart); err != nil {
			return nil, fmt.Errorf("cannot rewind the archive: %w", err)
		}
	}
	return extractTarPass(rootFD, r, sourceURL, dir, protected, governingIDs, true)
}

// extractTarPass reads the archive once. With apply unset it only judges it:
// nothing below rootFD is created, opened or unlinked.
func extractTarPass(rootFD int, r io.Reader, sourceURL, dir string, protected func(string) error, governingIDs map[fileIdentity]string, apply bool) (map[string]struct{}, error) {
	created := map[string]struct{}{}
	// The decoder is chosen from the URL's path extension (decoder_bounds.go)
	// and, once tar has seen its end marker, run to COMPLETION before the
	// extraction counts as done: the end marker precedes the
	// container's trailer and the xz process's exit, and archive/tar never
	// reads past it.
	dec, err := newArchiveDecoder(sourceURL, r)
	if err != nil {
		return nil, err
	}
	defer dec.Release()

	tr := tar.NewReader(dec)
	cleanDir := filepath.Clean(dir)
	// Every entry is created RELATIVE to this anchor, component by component,
	// never following a symlink at any depth. The
	// string-path version resolved an entry's parent with EvalSymlinks and
	// read every resolution error as "the parent does not exist yet, so it
	// will be created inside the destination" — which is false when an
	// EXISTING ancestor is a symlink pointing outside and only a descendant
	// below it is missing: MkdirAll and OpenFile then walked through the link,
	// and a local user who owned one component of the destination could
	// redirect a root extraction outside its tree with no race at all.
	// Directory entries never asked at all. The root descriptor is the
	// caller's, opened by the same component walk, and it outlives this
	// function so the ownership walk that follows uses the same anchor.
	var totalBytes int64
	var entries int
	layout := archiveLayout{}
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("failed to read chunk: %w", err)
		}
		if entries++; entries > maxExtractEntries {
			return nil, fmt.Errorf("archive has too many entries (>%d)", maxExtractEntries)
		}
		// Lexical zip-slip guard: kept as the cheap, readable refusal; the
		// anchored walk below is the one that holds against the filesystem.
		target := filepath.Join(cleanDir, hdr.Name)
		if target != cleanDir && !strings.HasPrefix(target, cleanDir+string(os.PathSeparator)) {
			return nil, fmt.Errorf("tar entry escapes destination: %q", hdr.Name)
		}
		comps, err := entryComponents(cleanDir, target)
		if err != nil {
			return nil, fmt.Errorf("tar entry %q: %w", hdr.Name, err)
		}
		if protected != nil && len(comps) > 0 {
			if perr := protected(target); perr != nil {
				return nil, fmt.Errorf("tar entry %q: %w", hdr.Name, perr)
			}
		}
		// Strip setuid/setgid/sticky so a hostile archive can't drop a
		// setuid-root binary (the agent extracts as root).
		mode := os.FileMode(hdr.Mode).Perm() & 0o777
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := layout.place(comps, archiveDir); err != nil {
				return nil, fmt.Errorf("tar entry %q: %w", hdr.Name, err)
			}
			if len(comps) == 0 || !apply {
				continue // the root itself, or a judging pass
			}
			fd, created, err := walkAnchored(rootFD, cleanDir, comps, true, governingIDs)
			if err != nil {
				return nil, err
			}
			if created {
				// An O_PATH descriptor cannot be fchmod'ed; the proc path names
				// exactly the directory the walk opened, not a re-walk.
				_ = unix.Chmod(fmt.Sprintf("/proc/self/fd/%d", fd), uint32(mode))
			}
			_ = unix.Close(fd)
		case tar.TypeReg:
			if len(comps) == 0 {
				return nil, fmt.Errorf("tar entry %q is not a file name", hdr.Name)
			}
			if err := layout.place(comps, archiveFile); err != nil {
				return nil, fmt.Errorf("tar entry %q: %w", hdr.Name, err)
			}
			if !apply {
				created[target] = struct{}{}
				written, err := io.Copy(io.Discard, io.LimitReader(tr, maxExtractBytes-totalBytes+1))
				if err != nil {
					return nil, err
				}
				totalBytes += written
				if totalBytes > maxExtractBytes {
					return nil, fmt.Errorf("archive exceeds the %d-byte extraction cap", int64(maxExtractBytes))
				}
				break
			}
			name := comps[len(comps)-1]
			parentFD, _, err := walkAnchored(rootFD, cleanDir, comps[:len(comps)-1], true, governingIDs)
			if err != nil {
				return nil, err
			}
			// Remove any pre-existing name first, then create fresh with O_EXCL: a
			// regular-file entry must not write THROUGH a hardlink an earlier entry
			// created, and O_NOFOLLOW stops symlinks but NOT hardlinks. Without this
			// a hostile archive could hardlink a name to /etc/shadow and overwrite it
			// as root with a following file of the same name.
			_ = unix.Unlinkat(parentFD, name, 0)
			fd, err := unix.Openat(parentFD, name,
				unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, uint32(mode))
			_ = unix.Close(parentFD)
			if err != nil {
				return nil, &os.PathError{Op: "openat", Path: target, Err: err}
			}
			f := os.NewFile(uintptr(fd), target)
			created[target] = struct{}{}
			written, err := io.Copy(f, io.LimitReader(tr, maxExtractBytes-totalBytes+1))
			f.Close()
			if err != nil {
				return nil, err
			}
			totalBytes += written
			if totalBytes > maxExtractBytes {
				return nil, fmt.Errorf("archive exceeds the %d-byte extraction cap", int64(maxExtractBytes))
			}
		case tar.TypeSymlink:
			if len(comps) == 0 {
				return nil, fmt.Errorf("tar entry %q is not a file name", hdr.Name)
			}
			// A symlink's target is interpreted relative to the LINK's own
			// directory when it is followed, so that is the path the containment
			// check must clear.
			linkTarget := hdr.Linkname
			resolved := linkTarget
			if !filepath.IsAbs(resolved) {
				resolved = filepath.Join(filepath.Dir(target), linkTarget)
			}
			resolved = filepath.Clean(resolved)
			if resolved != cleanDir && !strings.HasPrefix(resolved, cleanDir+string(os.PathSeparator)) {
				return nil, fmt.Errorf("tar symlink %q -> %q escapes destination", hdr.Name, linkTarget)
			}
			if err := layout.place(comps, archiveSymlink); err != nil {
				return nil, fmt.Errorf("tar entry %q: %w", hdr.Name, err)
			}
			if !apply {
				break
			}
			name := comps[len(comps)-1]
			parentFD, _, err := walkAnchored(rootFD, cleanDir, comps[:len(comps)-1], true, governingIDs)
			if err != nil {
				return nil, err
			}
			_ = unix.Unlinkat(parentFD, name, 0)
			err = unix.Symlinkat(linkTarget, parentFD, name)
			_ = unix.Close(parentFD)
			if err != nil {
				return nil, &os.PathError{Op: "symlinkat", Path: target, Err: err}
			}
		case tar.TypeLink:
			if len(comps) == 0 {
				return nil, fmt.Errorf("tar entry %q is not a file name", hdr.Name)
			}
			// A hardlink's source is another archive entry, resolved against the
			// extraction ROOT — and it is THAT exact path the link consumes, so it
			// is the one that must be containment-checked. The old code validated
			// a DIFFERENT path (dir(target)+linkname), so `a/b/x -> ../../etc/shadow`
			// passed the check (it resolved inside cleanDir) while os.Link
			// hardlinked the real /etc/shadow; a following regular-file entry of
			// the same name then overwrote it as root. The source is
			// reached through the anchor too, and linkat with no AT_SYMLINK_FOLLOW
			// links a symlink AS the link, never its target.
			source := filepath.Clean(filepath.Join(cleanDir, hdr.Linkname))
			if source != cleanDir && !strings.HasPrefix(source, cleanDir+string(os.PathSeparator)) {
				return nil, fmt.Errorf("tar hardlink %q -> %q escapes destination", hdr.Name, hdr.Linkname)
			}
			srcComps, err := entryComponents(cleanDir, source)
			if err != nil || len(srcComps) == 0 {
				return nil, fmt.Errorf("tar hardlink %q -> %q: not a file name", hdr.Name, hdr.Linkname)
			}
			if protected != nil {
				if perr := protected(source); perr != nil {
					return nil, fmt.Errorf("tar hardlink %q -> %q: %w", hdr.Name, hdr.Linkname, perr)
				}
			}
			// An archive may hardlink only to its OWN members. A link to a
			// file that already lived in the destination lands in the created
			// set by name and is then chowned as the archive's — which chowns
			// the pre-existing inode.
			if _, ours := created[source]; !ours {
				return nil, fmt.Errorf("tar hardlink %q -> %q: the source is not a member of this archive", hdr.Name, hdr.Linkname)
			}
			if err := layout.parents(srcComps, false); err != nil {
				return nil, fmt.Errorf("tar hardlink %q -> %q: %w", hdr.Name, hdr.Linkname, err)
			}
			if err := layout.place(comps, layout.kindOf(srcComps)); err != nil {
				return nil, fmt.Errorf("tar entry %q: %w", hdr.Name, err)
			}
			if !apply {
				created[target] = struct{}{}
				break
			}
			srcParentFD, _, err := walkAnchored(rootFD, cleanDir, srcComps[:len(srcComps)-1], false, governingIDs)
			if err != nil {
				return nil, err
			}
			name := comps[len(comps)-1]
			dstParentFD, _, err := walkAnchored(rootFD, cleanDir, comps[:len(comps)-1], true, governingIDs)
			if err != nil {
				_ = unix.Close(srcParentFD)
				return nil, err
			}
			_ = unix.Unlinkat(dstParentFD, name, 0)
			err = unix.Linkat(srcParentFD, srcComps[len(srcComps)-1], dstParentFD, name, 0)
			_ = unix.Close(srcParentFD)
			_ = unix.Close(dstParentFD)
			if err != nil {
				return nil, &os.PathError{Op: "linkat", Path: target, Err: err}
			}
			created[target] = struct{}{}
		}
	}
	// The end marker is not the end of the archive: the container's trailer
	// and the decoder's own completion still have to be reached and judged
	// before the extraction may be called complete.
	if err := dec.Finish(); err != nil {
		return nil, err
	}
	return created, nil
}

// entryComponents splits an entry's path under cleanDir into its bare
// components. Empty for the root itself; refuses anything that is not a plain
// descendant, which the lexical guard already excluded and this restates so
// the walk never sees a "." or "..".
func entryComponents(cleanDir, target string) ([]string, error) {
	rel, err := filepath.Rel(cleanDir, target)
	if err != nil {
		return nil, err
	}
	if rel == "." {
		return nil, nil
	}
	comps := strings.Split(rel, string(os.PathSeparator))
	for _, c := range comps {
		if c == "" || c == "." || c == ".." {
			return nil, fmt.Errorf("path component %q is not allowed", c)
		}
	}
	return comps, nil
}

// walkAnchored opens comps below rootFD one component at a time, refusing a
// symlink at ANY depth, and creates a missing directory on the way when create
// is set. It returns an O_PATH directory descriptor the caller closes, and
// whether the LAST component was created by this call. A component created
// here and swapped for a symlink before it is opened is refused by the
// O_NOFOLLOW|O_DIRECTORY open that follows the mkdir — the swap wins nothing.
//
// governingIDs, when set, is compared with the identity of every EXISTING
// directory the walk opens (never one it has just created): a component that
// is a governing directory under another name — a bind mount of /etc planted
// below the destination — is refused by name, the same way the root is
// (refuseGoverningAlias), because every name check on the entries below it
// would be answered against the alias's spelling.
func walkAnchored(rootFD int, displayRoot string, comps []string, create bool, governingIDs map[fileIdentity]string) (int, bool, error) {
	fd, err := unix.Openat(rootFD, ".", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, false, &os.PathError{Op: "openat", Path: displayRoot, Err: err}
	}
	walked := displayRoot
	created := false
	const flags = unix.O_PATH | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC
	for _, comp := range comps {
		created = false
		next, err := unix.Openat(fd, comp, flags, 0)
		if err == unix.ENOENT && create {
			merr := unix.Mkdirat(fd, comp, 0o755)
			if merr != nil && merr != unix.EEXIST {
				_ = unix.Close(fd)
				return -1, false, &os.PathError{Op: "mkdirat", Path: filepath.Join(walked, comp), Err: merr}
			}
			// created only when THIS call made it: an EEXIST means somebody
			// else did, and the archive's mode must not land on their entry.
			created = merr == nil
			next, err = unix.Openat(fd, comp, flags, 0)
		}
		if err != nil {
			var st unix.Stat_t
			if err == unix.ENOTDIR && unix.Fstatat(fd, comp, &st, unix.AT_SYMLINK_NOFOLLOW) == nil &&
				st.Mode&unix.S_IFMT == unix.S_IFLNK {
				_ = unix.Close(fd)
				return -1, false, fmt.Errorf("tar entry parent %s is a symlink; refusing to extract through it",
					filepath.Join(walked, comp))
			}
			_ = unix.Close(fd)
			return -1, false, &os.PathError{Op: "openat", Path: filepath.Join(walked, comp), Err: err}
		}
		_ = unix.Close(fd)
		fd = next
		walked = filepath.Join(walked, comp)
		if !created && len(governingIDs) > 0 {
			if governed, alias := governingAliasOf(fd, walked, governingIDs); alias {
				_ = unix.Close(fd)
				return -1, false, fmt.Errorf("tar entry parent %s is the same directory as %s, which governs platform-managed files; refusing to extract through it under another name", walked, governed)
			}
		}
	}
	return fd, created, nil
}

func parseMode(s string) os.FileMode {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0
	}
	n, err := strconv.ParseUint(s, 8, 32)
	if err != nil {
		return 0
	}
	return os.FileMode(n)
}

// applyOwnerAnchored sets an owner on an anchored target (best-effort).
//
// There is deliberately no path-taking variant: the one that existed took a
// string and called os.Chown, which follows a final symlink, and it survived a
// hardening pass because it sat two lines from a call that was converted.
func applyOwnerAnchored(t *anchoredTarget, owner string, h *CommandHandler) {
	uid, gid, ok := resolveOwner(owner)
	if !ok {
		h.logger.Warn("failed to resolve owner", "owner", owner, "path", t.Path().String())
		return
	}
	if err := t.Chown(uid, gid); err != nil {
		h.logger.Warn("failed to chown", "path", t.Path().String(), "error", err)
	}
}

func applyOwnerRecursive(root, owner string, h *CommandHandler) {
	rootFD, err := openDirNoSymlinks(filepath.Clean(root))
	if err != nil {
		h.logger.Warn("failed to open the extracted tree for ownership", "path", root, "error", err)
		return
	}
	defer unix.Close(rootFD)
	applyOwnerRecursiveAt(rootFD, root, owner, nil, h)
}

// ownershipPolicy is what the recursive ownership walk consults before it
// touches an entry.
type ownershipPolicy struct {
	// protected refuses a platform-managed NAME: never chowned, never
	// descended (an extraction aimed at /etc must not hand /etc/shadow, or
	// /etc/ssh/authorized_keys.d, to the archive's owner).
	protected func(string) error
	// governs marks a directory that is a proper ancestor of a protected
	// name: its owner is kept, but it IS descended, so the application files
	// under it are still chowned.
	governs func(string) bool
	// governingIDs is the same set by OBJECT identity (device, inode), so a
	// governing directory reached under another name — a bind-mount alias —
	// keeps its owner too.
	governingIDs map[fileIdentity]string
	// created lists the regular files and hardlinks THIS extraction created.
	// A multi-link file outside it is an alias to an object the archive did
	// not bring — possibly outside the tree — and keeps its owner. nil means
	// "unknown", which is treated as "none".
	created map[string]struct{}
}

// applyOwnerRecursiveAt is applyOwnerRecursiveWith with only the name check.
func applyOwnerRecursiveAt(rootFD int, root, owner string, protected func(string) error, h *CommandHandler) {
	applyOwnerRecursiveWith(rootFD, root, owner, ownershipPolicy{protected: protected}, h)
}

// applyOwnerRecursiveWith chowns the tree below rootFD — the SAME descriptor
// the extraction used, never a reopen by path:
// the destination is routinely writable by an unprivileged local user, and a
// multi-component open(2) between extraction and ownership, even with
// O_NOFOLLOW, guards only its last component. Each directory below is opened
// once with O_NOFOLLOW and every entry chowned relative to it, under policy.
func applyOwnerRecursiveWith(rootFD int, root, owner string, policy ownershipPolicy, h *CommandHandler) {
	uid, gid, ok := resolveOwner(owner)
	if !ok {
		h.logger.Warn("failed to resolve owner", "owner", owner, "path", root)
		return
	}
	dirFD, err := unix.Openat(rootFD, ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		h.logger.Warn("failed to open the extracted tree for ownership", "path", root, "error", err)
		return
	}
	defer unix.Close(dirFD)
	w := &ownerWalk{uid: uid, gid: gid, policy: policy, logger: h.logger}
	w.chownTree(dirFD, filepath.Clean(root))
}

// ownerWalk is one recursive ownership pass.
type ownerWalk struct {
	uid, gid int
	policy   ownershipPolicy
	logger   *slog.Logger
}

// chownTree chowns dirFD and everything below it. Only regular files and
// directories are touched, never through a link: a symlink is neither
// (AT_SYMLINK_NOFOLLOW stats the link itself), and an extracted tree has no
// legitimate use for a socket, FIFO or device node. Best-effort throughout,
// like the string-path walk it replaced. display is the directory's path for
// the policy and the log lines only; no operation uses it.
func (w *ownerWalk) chownTree(dirFD int, display string) {
	// The directory's OWN owner is decided BEFORE it is changed, and a
	// directory governing a protected name keeps it: /etc handed to the
	// archive's owner lets that owner replace the entry for /etc/shadow, so
	// the name check on the child protected nothing.
	// Its children are still walked.
	var dirSt unix.Stat_t
	haveDirSt := unix.Fstat(dirFD, &dirSt) == nil
	// By name AND by object: the descriptor's identity is compared with the
	// governing directories, so /etc under a bind-mount alias is still /etc.
	governedAs := ""
	if haveDirSt {
		governedAs = w.policy.governingIDs[fileIdentity{uint64(dirSt.Dev), uint64(dirSt.Ino)}]
	}
	switch {
	case w.policy.governs != nil && w.policy.governs(display):
		w.logger.Info("ownership kept on a directory that governs a platform-managed path", "path", display)
	case governedAs != "":
		w.logger.Warn("ownership kept on a directory that is a platform-governing directory under another name", "path", display, "same_as", governedAs)
	default:
		_ = unix.Fchown(dirFD, w.uid, w.gid)
	}
	// Readdir needs its own descriptor: the read consumes the offset, and
	// os.File takes ownership of what it is given.
	dup, err := unix.Dup(dirFD)
	if err != nil {
		return
	}
	dir := os.NewFile(uintptr(dup), "")
	names, err := dir.Readdirnames(-1)
	_ = dir.Close()
	if err != nil {
		return
	}
	for _, name := range names {
		var st unix.Stat_t
		if unix.Fstatat(dirFD, name, &st, unix.AT_SYMLINK_NOFOLLOW) != nil {
			continue
		}
		path := filepath.Join(display, name)
		if w.policy.protected != nil && w.policy.protected(path) != nil {
			continue // a platform-managed name keeps its owner
		}
		// Object identity, not only names: an entry that is another
		// filesystem's root (a mount, a bind mount from elsewhere) is not
		// part of the extracted tree whatever it is called, and neither is a
		// file with more than one link that this extraction did not create —
		// it is an alias to an object that lives somewhere else, and chowning
		// it chowns that object. Both are skipped and said so, never failed:
		// the archive's own files are still handed over.
		if isMountRoot(dirFD, name, &st, haveDirSt, &dirSt) {
			w.logger.Warn("ownership skipped on a mount point inside the extracted tree", "path", path)
			continue
		}
		switch st.Mode & unix.S_IFMT {
		case unix.S_IFREG:
			if st.Nlink > 1 {
				if _, ours := w.policy.created[path]; !ours {
					w.logger.Warn("ownership skipped on a hardlink alias the extraction did not create", "path", path, "links", st.Nlink)
					continue
				}
			}
			_ = unix.Fchownat(dirFD, name, w.uid, w.gid, unix.AT_SYMLINK_NOFOLLOW)
		case unix.S_IFDIR:
			child, err := unix.Openat(dirFD, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
			if err != nil {
				continue // swapped for a link since the stat: leave it alone
			}
			w.chownTree(child, path)
			_ = unix.Close(child)
		}
	}
}

// isMountRoot reports whether the entry name under dirFD is the root of a
// mount. statx's STATX_ATTR_MOUNT_ROOT (Linux 5.8+) is exact and covers a
// bind mount from the SAME filesystem, which a device comparison cannot see;
// where the kernel does not report the attribute, a different st_dev from the
// parent is the fallback.
func isMountRoot(dirFD int, name string, st *unix.Stat_t, haveDirSt bool, dirSt *unix.Stat_t) bool {
	var stx unix.Statx_t
	if err := unix.Statx(dirFD, name, unix.AT_SYMLINK_NOFOLLOW|unix.AT_STATX_DONT_SYNC, unix.STATX_BASIC_STATS, &stx); err == nil &&
		stx.Attributes_mask&unix.STATX_ATTR_MOUNT_ROOT != 0 {
		return stx.Attributes&unix.STATX_ATTR_MOUNT_ROOT != 0
	}
	return haveDirSt && st.Dev != dirSt.Dev
}

// resolveOwner resolves "user[:group]" to numeric uid/gid.
func resolveOwner(owner string) (int, int, bool) {
	userPart, groupPart, hasGroup := strings.Cut(owner, ":")
	u, err := user.Lookup(userPart)
	if err != nil {
		// Allow a numeric uid.
		if uid, aerr := strconv.Atoi(userPart); aerr == nil {
			gid := uid
			if hasGroup {
				if g, gerr := strconv.Atoi(groupPart); gerr == nil {
					gid = g
				}
			}
			return uid, gid, true
		}
		return 0, 0, false
	}
	uid, _ := strconv.Atoi(u.Uid)
	gid, _ := strconv.Atoi(u.Gid)
	if hasGroup {
		if g, gerr := user.LookupGroup(groupPart); gerr == nil {
			gid, _ = strconv.Atoi(g.Gid)
		} else if gnum, aerr := strconv.Atoi(groupPart); aerr == nil {
			gid = gnum
		}
	}
	return uid, gid, true
}

// truncateOutput caps command output stored in the result map so a very chatty
// apt run does not bloat the command record.
func truncateOutput(s string) string {
	const max = 8 * 1024
	if len(s) <= max {
		return s
	}
	return s[len(s)-max:]
}

// isPlatformConfigPath reports whether a path is the boot config the platform
// manages itself. Editing it is the original purpose of the file panel, so the
// protected-path guard has to let it through while still refusing everything
// else on that list.
// canonicalPlatformConfigPath is the resolution the boot config gets INSTEAD of
// resolveForFileOp (which it is exempt from, being the platform's own file).
// The anchor walk refuses any symlink component, and it walks
// the string it is given — so if a distro ever ships /boot as a link to
// /boot/firmware or the like, an unresolved platform path would fail at the
// anchor for the wrong reason. EvalSymlinks on the PARENT makes the walk see
// the real directories; the file itself may not exist yet, so only the parent
// is resolved, and an unresolvable parent keeps the path as given.
func canonicalPlatformConfigPath(path string) string {
	clean := filepath.Clean(path)
	parent, err := filepath.EvalSymlinks(filepath.Dir(clean))
	if err != nil {
		return clean
	}
	return filepath.Join(parent, filepath.Base(clean))
}

func isPlatformConfigPath(path string) bool {
	switch strings.ToLower(filepath.Clean(path)) {
	case "/boot/firmware/config.txt", "/boot/config.txt":
		return true
	}
	return false
}
