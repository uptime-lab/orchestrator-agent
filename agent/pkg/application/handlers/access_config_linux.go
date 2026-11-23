//go:build linux

package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	proto "agent/pkg/infrastructure/grpc/proto"
	"agent/pkg/infrastructure/hardware"
)

// handleApplyAccessConfig reconciles the node's managed SSH access against the
// desired state sent by the platform.
//
// Unlike provision_connection, which only ever appends, this is declarative:
// a key removed from the desired state is removed from the host. That is what
// makes revocation work at all.
func (h *CommandHandler) handleApplyAccessConfig(commandID string, cmd *proto.ApplyAccessConfigCommand) error {
	return h.applyAccessConfigAt(commandID, cmd, "/")
}

// applyAccessConfigAt is the reconciler entry shared by the live apply
// (rootPath "/") and the recovery-mode offline apply (rootPath = a mounted
// target root). Every mutation below already goes through `chroot rootPath`
// or plain file I/O under rootPath, and applySSHDSettings short-circuits its
// live-daemon work when rootPath != "/".
func (h *CommandHandler) applyAccessConfigAt(commandID string, cmd *proto.ApplyAccessConfigCommand, rootPath string) error {
	h.logger.Info("applying access config",
		"command_id", commandID, "users", len(cmd.GetUsers()), "cas", len(cmd.GetCas()), "root_path", rootPath)
	h.reportCommandStatus(commandID, "in_progress", 10, "Validating access configuration")

	spec := accessSpecFromProto(cmd)

	// Phase 0 — validate everything before touching anything.
	if err := validateAccessConfig(spec); err != nil {
		msg := fmt.Sprintf("Access configuration rejected: %v", err)
		h.reportCommandStatus(commandID, "failed", 0, msg)
		return fmt.Errorf("%s", msg)
	}

	// Phase 0.5 — the lockout gate. Refuse rather than warn: this is a
	// deterministic outcome, not a risk, and the node may be physically remote.
	if wouldLockOutAllAccess(spec) {
		msg := "Access configuration refused: would_lock_out_all_access — " +
			"applying it would leave no working login on this node"
		h.reportCommandStatus(commandID, "failed", 0, msg)
		return fmt.Errorf("%s", msg)
	}

	state := loadAccessState(rootPath)

	// Idempotent no-op. Password actions are excluded from the hash, so they are
	// applied regardless (see hashAccessConfig on the server side).
	if state.ConfigHash == spec.ConfigHash && !state.Partial && !specHasPasswordWork(spec) {
		result := map[string]string{"noop": "true", "generation": spec.ConfigHash}
		h.reportCommandResult(commandID, "success", "Access configuration already current", result)
		return nil
	}

	h.reportCommandStatus(commandID, "in_progress", 30, "Reconciling users and keys")

	report, err := h.reconcileAccess(rootPath, spec, &state)
	if err != nil {
		state.Partial = true
		state.ConfigHash = ""
		if serr := saveAccessState(rootPath, state); serr != nil {
			h.logger.Warn("failed to persist partial access state", "error", serr)
		}
		msg := fmt.Sprintf("Access reconcile failed: %v", err)
		h.reportCommandResult(commandID, "failed", msg, report)
		return fmt.Errorf("%s", msg)
	}

	state.Partial = false
	state.ConfigHash = spec.ConfigHash
	if err := saveAccessState(rootPath, state); err != nil {
		// The host is correctly configured; only our bookkeeping failed. Report
		// success but surface it, since the next run will redo the work.
		h.logger.Warn("failed to persist access state", "error", err)
		report["state_persisted"] = "false"
	}

	h.reportCommandResult(commandID, "success", "Access configuration applied", report)
	return nil
}

// handleApplyAccessConfigOffline applies the same declarative access config,
// but into a MOUNTED target rootfs from the recovery bootstrap. This is how
// OU-assigned credentials reach a node whose live-OS agent never runs: mount
// the installed root, run the same reconciler against it (the target's own
// shadow-suite binaries via chroot), unmount. sshd is never reloaded — there
// is no daemon in the initramfs to reload; the settings take effect on boot.
func (h *CommandHandler) handleApplyAccessConfigOffline(commandID string, cmd *proto.ApplyAccessConfigOfflineCommand) error {
	inner := cmd.GetConfig()
	if inner == nil {
		msg := "apply_access_config_offline: payload carries no access config"
		h.reportCommandStatus(commandID, "failed", 0, msg)
		return fmt.Errorf("%s", msg)
	}
	h.logger.Info("offline access config command received",
		"command_id", commandID,
		"target_device", cmd.GetTargetDevice(),
		"root_partition", cmd.GetRootPartition())

	// Recovery-only, mirroring capture_image's gate with the polarity this
	// command needs: on an installed OS the live apply owns the machine, and
	// "mount some other disk and chroot into it" from a live root is exactly
	// the shape of mistake that rewrites the running system.
	if !hardware.RootIsEphemeral() {
		msg := "apply_access_config_offline must run from the netboot recovery bootstrap; " +
			"use apply_access_config on an installed OS"
		h.reportCommandStatus(commandID, "failed", 0, msg)
		return fmt.Errorf("%s", msg)
	}

	targetDevice := strings.TrimSpace(cmd.GetTargetDevice())
	if targetDevice == "" {
		// The platform resolves the target disk before dispatch (it holds the
		// node's reported storage inventory); the agent never guesses a disk
		// it is about to write users onto.
		msg := "apply_access_config_offline: target_device is required"
		h.reportCommandStatus(commandID, "failed", 0, msg)
		return fmt.Errorf("%s", msg)
	}
	if _, err := os.Stat(targetDevice); err != nil {
		msg := fmt.Sprintf("target device %s not found: %v", targetDevice, err)
		h.reportCommandStatus(commandID, "failed", 0, msg)
		return fmt.Errorf("%s", msg)
	}

	// Resolve the root partition: explicit number, else the sysfs+dumpe2fs
	// probe that works on unmounted disks (the df-based detector reads zero
	// sizes in recovery and would fall through to guessing).
	var rootPart string
	if n := cmd.GetRootPartition(); n > 0 {
		rootPart = getPartitionPath(targetDevice, int(n))
	} else {
		p, err := h.captureDetectRootPartition(commandID, targetDevice)
		if err != nil {
			msg := fmt.Sprintf("could not detect a Linux root partition on %s: %v", targetDevice, err)
			h.reportCommandStatus(commandID, "failed", 0, msg)
			return fmt.Errorf("%s", msg)
		}
		rootPart = p.path
	}

	h.reportCommandStatus(commandID, "in_progress", 5, "Mounting target root partition")
	mountPoint := "/mnt/tmp-access-offline"
	if err := os.MkdirAll(mountPoint, 0755); err != nil {
		msg := fmt.Sprintf("failed to create mount point: %v", err)
		h.reportCommandStatus(commandID, "failed", 0, msg)
		return fmt.Errorf("%s", msg)
	}
	mountCmd := exec.Command("mount", rootPart, mountPoint)
	var mountStderr bytes.Buffer
	mountCmd.Stderr = &mountStderr
	if err := mountCmd.Run(); err != nil {
		// A LUKS/encrypted or otherwise unmountable root fails HERE, cleanly:
		// mount(8) cannot open it, and this command deliberately has no
		// unlocking machinery.
		msg := fmt.Sprintf("failed to mount %s: %v (stderr: %s)", rootPart, err, strings.TrimSpace(mountStderr.String()))
		h.reportCommandStatus(commandID, "failed", 0, msg)
		return fmt.Errorf("%s", msg)
	}
	defer func() {
		if err := exec.Command("umount", mountPoint).Run(); err != nil {
			h.logger.Warn("failed to unmount target root after offline access apply",
				"mount_point", mountPoint, "error", err)
		}
		if err := os.Remove(mountPoint); err != nil {
			h.logger.Warn("failed to remove mount point", "mount_point", mountPoint, "error", err)
		}
	}()

	// Never operate on the filesystem this agent is running from.
	if same, err := sameFilesystem(mountPoint, "/"); err == nil && same {
		msg := "refusing offline access apply: target partition IS the live root filesystem"
		h.reportCommandStatus(commandID, "failed", 0, msg)
		return fmt.Errorf("%s", msg)
	}

	// The reconciler chroots into the target for every mutation, so the target
	// must be a Linux root carrying its own shadow suite. /etc/passwd is the
	// cheapest honest proxy; a data disk fails here instead of five steps in.
	if _, err := os.Stat(filepath.Join(mountPoint, "etc", "passwd")); err != nil {
		msg := fmt.Sprintf("%s does not look like a Linux root filesystem (no etc/passwd): %v", rootPart, err)
		h.reportCommandStatus(commandID, "failed", 0, msg)
		return fmt.Errorf("%s", msg)
	}

	err := h.applyAccessConfigAt(commandID, inner, mountPoint)
	// Push everything to the disk before the unmount in the deferred cleanup;
	// the whole point of this command is what the NEXT boot finds on disk.
	syscall.Sync()
	return err
}

// accessSpecFromProto decodes the wire message into the internal spec.
func accessSpecFromProto(cmd *proto.ApplyAccessConfigCommand) accessConfigSpec {
	spec := accessConfigSpec{
		ConfigHash:          cmd.GetConfigHash(),
		ManagePasswordAuth:  cmd.GetManageSshPasswordAuth(),
		PasswordAuthEnabled: cmd.GetSshPasswordAuth(),
	}
	for _, u := range cmd.GetUsers() {
		action := "unchanged"
		switch u.GetPasswordAction() {
		case proto.PasswordAction_PASSWORD_ACTION_SET:
			action = "set"
		case proto.PasswordAction_PASSWORD_ACTION_CLEAR:
			action = "clear"
		}
		spec.Users = append(spec.Users, accessUserSpec{
			Username:       u.GetUsername(),
			AuthorizedKeys: u.GetAuthorizedKeys(),
			Sudo:           u.GetSudo(),
			SudoNoPasswd:   u.GetSudoNopasswd(),
			PasswordHash:   u.GetPasswordHash(),
			PasswordAction: action,
			AdoptUnmanaged: u.GetAdoptUnmanaged(),
			// Per-user certificate principals (AuthorizedPrincipalsFile) — the
			// platform now declares them on the user directly.
			Principals: u.GetPrincipals(),
		})
	}
	for _, ca := range cmd.GetCas() {
		spec.CAs = append(spec.CAs, accessCASpec{
			PublicKey:  ca.GetCaPublicKey(),
			Principals: ca.GetPrincipals(),
		})
	}
	// LEGACY payloads declared principals per CA; they are enforced per user,
	// so fold them onto the users they name. New payloads carry them on the
	// user directly (above); the union keeps both shapes working.
	if len(spec.CAs) > 0 {
		for i := range spec.Users {
			for _, ca := range spec.CAs {
				for _, p := range ca.Principals {
					if p == spec.Users[i].Username && !containsString(spec.Users[i].Principals, p) {
						spec.Users[i].Principals = append(spec.Users[i].Principals, p)
					}
				}
			}
		}
	}
	return spec
}

// specHasPasswordWork reports whether any user carries a password action that
// must run even when the configuration hash is unchanged.
func specHasPasswordWork(spec accessConfigSpec) bool {
	for _, u := range spec.Users {
		if u.PasswordAction == "set" || u.PasswordAction == "clear" {
			return true
		}
	}
	return false
}

func containsString(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}

// reconcileAccess converges the host onto the desired state.
//
// Ordering is grant-before-revoke. There is no transaction across useradd,
// sshd_config and sudoers, and pretending otherwise would be worse than being
// honest: instead of atomicity we guarantee that a failure midway leaves MORE
// access than intended, never less.
func (h *CommandHandler) reconcileAccess(rootPath string, spec accessConfigSpec, state *accessState) (map[string]string, error) {
	report := map[string]string{"generation": spec.ConfigHash}
	var created, updated, locked, unlocked, skipped []string
	terminated := 0

	// Phase 1 — the fence must exist before anything joins it.
	if err := h.ensureManagedGroup(rootPath); err != nil {
		return report, fmt.Errorf("failed to ensure managed group: %w", err)
	}
	for _, dir := range []string{accessKeysDirRel, accessCADirRel, accessPrincipalsDirRel} {
		if err := os.MkdirAll(filepath.Join(rootPath, dir), 0o755); err != nil {
			return report, fmt.Errorf("failed to create %s: %w", dir, err)
		}
	}

	// Phase 1.5 — the lockout gate AGAIN, this time against the users that can
	// actually be managed on this host.
	//
	// The gate in phase 0.5 asks the question of the DESIRED config, which on a
	// node whose OS user was created by provision_connection — the common
	// shape — answers "there is a user with keys" about a
	// user this command will skip as unmanaged. The keys never get installed,
	// `PasswordAuthentication no` is written anyway, and the command reports
	// SUCCESS. So the "refused twice" property the platform advertises did not
	// hold on the most common node shape.
	//
	// Read-only: classifyUsers only inspects, so a refusal here has touched
	// nothing on the device. That is the whole reason it runs before phase 2
	// rather than "before the sshd rewrite" — the sshd write is last, but user
	// creation and key installation are not, and a refusal should leave no
	// half-made users behind either.
	preview, previewSkipped, previewAdopting, err := h.classifyUsers(rootPath, spec)
	if err != nil {
		return report, err
	}
	if err := adoptionLockRefusal(spec, previewAdopting); err != nil {
		return report, err
	}
	if len(previewSkipped) > 0 {
		effective := spec
		effective.Users = preview
		if wouldLockOutAllAccess(effective) {
			report["skipped_unmanaged"] = encodeList(previewSkipped)
			return report, fmt.Errorf(
				"would_lock_out_all_access: every user that grants a login on this node is unmanaged (%s), "+
					"so their keys would not be installed while password authentication is switched off",
				strings.Join(previewSkipped, ", "))
		}
	}

	// Phase 2 — create or adopt users.
	manageable := make([]accessUserSpec, 0, len(spec.Users))
	for _, u := range spec.Users {
		exists, err := h.userExists(rootPath, u.Username)
		if err != nil {
			return report, fmt.Errorf("failed to check user %s: %w", u.Username, err)
		}

		if !exists {
			if err := h.createManagedUser(rootPath, u.Username); err != nil {
				return report, fmt.Errorf("failed to create user %s: %w", u.Username, err)
			}
			st := state.Users[u.Username]
			st.CreatedByUs = true
			st.OriginalShell = "/bin/bash"
			state.Users[u.Username] = st
			created = append(created, u.Username)
			manageable = append(manageable, u)
			continue
		}

		// The user exists. We may only touch it if it is ours.
		ours, err := h.userInManagedGroup(rootPath, u.Username)
		if err != nil {
			return report, fmt.Errorf("failed to check group membership for %s: %w", u.Username, err)
		}
		if !ours {
			if !u.AdoptUnmanaged {
				// Never auto-adopt: silently taking over ubuntu/root or a
				// operator's own account — including the power to lock it — must
				// be a deliberate act, not a side effect of a name collision.
				skipped = append(skipped, u.Username)
				continue
			}
			if err := h.assertAdoptable(rootPath, u.Username); err != nil {
				return report, fmt.Errorf("refusing to adopt %s: %w", u.Username, err)
			}
			if err := h.addUserToManagedGroup(rootPath, u.Username); err != nil {
				return report, fmt.Errorf("failed to adopt user %s: %w", u.Username, err)
			}
			st := state.Users[u.Username]
			st.Adopted = true
			if st.OriginalShell == "" {
				st.OriginalShell = h.currentShell(rootPath, u.Username)
			}
			state.Users[u.Username] = st
			h.logger.Warn("adopted a pre-existing unmanaged user", "username", u.Username)
		}
		updated = append(updated, u.Username)
		manageable = append(manageable, u)
	}

	// Phase 3 — write key sets. Grants land before any revocation below.
	for _, u := range manageable {
		if err := h.writeAuthorizedKeys(rootPath, u, spec.ConfigHash); err != nil {
			return report, fmt.Errorf("failed to write keys for %s: %w", u.Username, err)
		}
	}

	// Phase 4 — CA trust and per-user principals.
	if err := h.reconcileTrustedCAs(rootPath, spec, state); err != nil {
		return report, fmt.Errorf("failed to reconcile trusted CAs: %w", err)
	}
	for _, u := range manageable {
		if err := h.writePrincipals(rootPath, u); err != nil {
			return report, fmt.Errorf("failed to write principals for %s: %w", u.Username, err)
		}
	}

	// Phase 5 — sudo.
	for _, u := range manageable {
		if err := h.reconcileSudo(rootPath, u, state); err != nil {
			return report, fmt.Errorf("failed to reconcile sudo for %s: %w", u.Username, err)
		}
	}

	// Phase 6 — passwords.
	for _, u := range manageable {
		switch u.PasswordAction {
		case "set":
			if err := h.setPasswordHashOnRoot(rootPath, u.Username, u.PasswordHash); err != nil {
				return report, fmt.Errorf("failed to set password for %s: %w", u.Username, err)
			}
		case "clear":
			if err := h.clearPassword(rootPath, u.Username); err != nil {
				return report, fmt.Errorf("failed to clear password for %s: %w", u.Username, err)
			}
		}
	}

	// Phase 7 — lock and unlock. Revocations happen last, after every grant.
	//
	// Both directions are applied unconditionally rather than only when our state
	// file says the user is in the opposite state. `chage -E` and the shell
	// restore are idempotent, and gating the unlock on bookkeeping meant a lost
	// state file left an expired account that no amount of re-attaching keys
	// could revive — the keys installed fine and sshd still refused them.
	for _, u := range manageable {
		st := state.Users[u.Username]
		wasLocked := st.Locked
		if u.Locked() {
			if err := h.lockManagedUser(rootPath, u.Username, &st); err != nil {
				return report, fmt.Errorf("failed to lock %s: %w", u.Username, err)
			}
			terminated += endSessionsOnce(&st, func() (int, bool) { return h.endManagedUserSessions(rootPath, u.Username) })
			if !wasLocked {
				locked = append(locked, u.Username)
			}
			st.Locked = true
		} else {
			if err := h.unlockManagedUser(rootPath, u.Username, st); err != nil {
				return report, fmt.Errorf("failed to unlock %s: %w", u.Username, err)
			}
			if wasLocked {
				unlocked = append(unlocked, u.Username)
			}
			st.Locked = false
			st.SessionsEnded = false
		}
		state.Users[u.Username] = st
	}

	// Phase 7b — users we used to manage that are no longer in the desired state.
	//
	// Deleting an access entry is the most natural way an operator revokes
	// someone, and without this their key file would simply stay on disk and keep
	// working forever — the exact revocation hole this feature exists to close.
	// They are locked, never deleted: an entry removed by mistake must not cost
	// anyone their home directory.
	departed, departedTerminated, err := h.reconcileDepartedUsers(rootPath, spec, state)
	terminated += departedTerminated
	if err != nil {
		return report, fmt.Errorf("failed to revoke departed users: %w", err)
	}
	locked = append(locked, departed...)

	// Phase 8/9 — sshd settings, validated before they can reach the daemon.
	reloaded, mode, err := h.applySSHDSettings(rootPath, spec)
	if err != nil {
		// Say WHICH failure this is. Reconciliation is grant-before-revoke and
		// the sshd write is last, so by the time this fails every user, key and
		// password in the configuration is already on the host: the run is red
		// and the access is live. The design's promise held — a failure leaves
		// more access than intended, never less — but an operator reading a bare
		// "failed" has no way to tell that from "nothing was applied", and the
		// two call for opposite next steps.
		return report, fmt.Errorf(
			"failed to apply sshd settings: %w — the users, SSH keys and passwords in this configuration ARE already "+
				"applied on the device and are live; only the sshd settings (password authentication, trusted CAs) were not. "+
				"Fix the cause and re-apply", err)
	}
	state.SSHConfigMode = mode

	report["users_created"] = encodeList(created)
	report["users_updated"] = encodeList(updated)
	report["users_locked"] = encodeList(locked)
	report["users_unlocked"] = encodeList(unlocked)
	report["skipped_unmanaged"] = encodeList(skipped)
	report["sshd_reloaded"] = strconv.FormatBool(reloaded)
	report["sshd_config_mode"] = mode
	report["cas_trusted"] = strconv.Itoa(len(spec.CAs))
	report["processes_terminated"] = strconv.Itoa(terminated)
	report["noop"] = "false"
	// A skipped user means this configuration was not fully applied. Recording
	// the generation as clean would make the next delivery of the same config a
	// no-op, so an operator who fixes the cause (adds the user to the managed
	// group) and re-pushes would be told "already current" and nothing would
	// happen.
	if len(skipped) > 0 {
		state.Partial = true
	}
	return report, nil
}

// reconcileDepartedUsers revokes access for users we previously managed that
// the desired state no longer names, and returns the ones it locked.
//
// Revocation here means: empty the key file, drop our sudo grant, empty the
// principals file, and lock the account. It never deletes the user or its home
// directory — an access entry removed by accident should cost a login, not data.
// What the user still has running is ended once per lock, tracked by
// SessionsEnded rather than by Locked, so a user locked before that step
// existed is still covered once.
//
// The candidate list comes from the managed GROUP, not from our state file.
// The state file is documented as losable, and deriving revocation from it meant
// a wiped /var/lib left departed users with working keys forever — the exact hole
// this function exists to close. Group membership is the authority everywhere
// else in this file, so it is the authority here too.
func (h *CommandHandler) reconcileDepartedUsers(rootPath string, spec accessConfigSpec, state *accessState) ([]string, int, error) {
	desired := make(map[string]bool, len(spec.Users))
	for _, u := range spec.Users {
		desired[u.Username] = true
	}

	managed, err := h.managedGroupMembers(rootPath)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list managed users: %w", err)
	}
	// Users the state file knows about are folded in as well, so one that was
	// dropped from the group while we were away is still cleaned up.
	for username := range state.Users {
		if !containsString(managed, username) {
			managed = append(managed, username)
		}
	}
	sort.Strings(managed)

	var locked []string
	terminated := 0
	for _, username := range managed {
		if desired[username] {
			continue
		}
		st := state.Users[username]

		ours, err := h.userInManagedGroup(rootPath, username)
		if err != nil {
			return locked, terminated, fmt.Errorf("failed to check group membership for %s: %w", username, err)
		}
		if !ours {
			// An operator took this account back from us. Stop tracking; do not
			// touch it.
			delete(state.Users, username)
			continue
		}

		exists, err := h.userExists(rootPath, username)
		if err != nil {
			return locked, terminated, fmt.Errorf("failed to check user %s: %w", username, err)
		}
		if !exists {
			delete(state.Users, username)
			continue
		}

		// Empty rather than delete: an empty file is unambiguous evidence that we
		// mean this user to have no keys, where a missing file is
		// indistinguishable from never-configured.
		empty := accessUserSpec{Username: username}
		if err := h.writeAuthorizedKeys(rootPath, empty, spec.ConfigHash); err != nil {
			return locked, terminated, fmt.Errorf("failed to clear keys for %s: %w", username, err)
		}
		if err := h.writePrincipals(rootPath, empty); err != nil {
			return locked, terminated, fmt.Errorf("failed to clear principals for %s: %w", username, err)
		}
		if err := h.reconcileSudo(rootPath, empty, state); err != nil {
			return locked, terminated, fmt.Errorf("failed to revoke sudo for %s: %w", username, err)
		}

		if !st.Locked {
			if err := h.lockManagedUser(rootPath, username, &st); err != nil {
				return locked, terminated, fmt.Errorf("failed to lock departed user %s: %w", username, err)
			}
			locked = append(locked, username)
		}
		terminated += endSessionsOnce(&st, func() (int, bool) { return h.endManagedUserSessions(rootPath, username) })
		st.Locked = true
		state.Users[username] = st
	}
	return locked, terminated, nil
}

// encodeList renders a list for the command result map (values are strings).
func encodeList(items []string) string {
	if len(items) == 0 {
		return "[]"
	}
	sort.Strings(items)
	b, err := json.Marshal(items)
	if err != nil {
		return "[]"
	}
	return string(b)
}

// ensureManagedGroup creates the group that marks a user as ours to modify.
func (h *CommandHandler) ensureManagedGroup(rootPath string) error {
	if h.groupExists(rootPath, accessManagedGroup) {
		return nil
	}
	cmd := exec.Command("chroot", rootPath, "groupadd", "--system", accessManagedGroup)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		if h.groupExists(rootPath, accessManagedGroup) {
			return nil // raced with something else; fine
		}
		return fmt.Errorf("groupadd failed: %w (stderr: %s)", err, stderr.String())
	}
	return nil
}

// managedGroupMembers lists the users in the managed group, i.e. every account
// this agent is allowed to modify. Read from /etc/group so it survives loss of
// the agent's own state.
func (h *CommandHandler) managedGroupMembers(rootPath string) ([]string, error) {
	content, err := os.ReadFile(filepath.Join(rootPath, "etc", "group"))
	if err != nil {
		return nil, fmt.Errorf("failed to read /etc/group: %w", err)
	}
	for _, line := range strings.Split(string(content), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, accessManagedGroup+":") {
			continue
		}
		fields := strings.Split(line, ":")
		if len(fields) < 4 || strings.TrimSpace(fields[3]) == "" {
			return nil, nil
		}
		var members []string
		for _, m := range strings.Split(fields[3], ",") {
			if m = strings.TrimSpace(m); m != "" {
				members = append(members, m)
			}
		}
		return members, nil
	}
	return nil, nil
}

func (h *CommandHandler) groupExists(rootPath, group string) bool {
	content, err := os.ReadFile(filepath.Join(rootPath, "etc", "group"))
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(content), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), group+":") {
			return true
		}
	}
	return false
}

// userInManagedGroup reports whether a user is ours. Reads /etc/group directly
// rather than trusting our own state file: authority must live where the OS
// keeps it, so a wiped /var/lib cannot make us believe we own an account.
func (h *CommandHandler) userInManagedGroup(rootPath, username string) (bool, error) {
	content, err := os.ReadFile(filepath.Join(rootPath, "etc", "group"))
	if err != nil {
		return false, fmt.Errorf("failed to read /etc/group: %w", err)
	}
	for _, line := range strings.Split(string(content), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, accessManagedGroup+":") {
			continue
		}
		fields := strings.Split(line, ":")
		if len(fields) < 4 {
			return false, nil
		}
		for _, m := range strings.Split(fields[3], ",") {
			if strings.TrimSpace(m) == username {
				return true, nil
			}
		}
		return false, nil
	}
	return false, nil
}

// assertAdoptable refuses adoption of accounts that must never be ours,
// regardless of what the platform asked for: root, system accounts, and the
// account the agent itself depends on.
func (h *CommandHandler) assertAdoptable(rootPath, username string) error {
	if username == "root" {
		return fmt.Errorf("root is never managed")
	}
	uid, err := h.userUID(rootPath, username)
	if err != nil {
		return err
	}
	if uid < minManagedUID {
		return fmt.Errorf("uid %d is a system account (minimum %d)", uid, minManagedUID)
	}
	return nil
}

func (h *CommandHandler) userUID(rootPath, username string) (int, error) {
	content, err := os.ReadFile(filepath.Join(rootPath, "etc", "passwd"))
	if err != nil {
		return 0, fmt.Errorf("failed to read /etc/passwd: %w", err)
	}
	for _, line := range strings.Split(string(content), "\n") {
		fields := strings.Split(strings.TrimSpace(line), ":")
		if len(fields) >= 3 && fields[0] == username {
			uid, err := strconv.Atoi(fields[2])
			if err != nil {
				return 0, fmt.Errorf("unreadable uid for %s", username)
			}
			return uid, nil
		}
	}
	return 0, fmt.Errorf("user %s not found", username)
}

func (h *CommandHandler) currentShell(rootPath, username string) string {
	content, err := os.ReadFile(filepath.Join(rootPath, "etc", "passwd"))
	if err != nil {
		return "/bin/bash"
	}
	for _, line := range strings.Split(string(content), "\n") {
		fields := strings.Split(strings.TrimSpace(line), ":")
		if len(fields) >= 7 && fields[0] == username {
			return fields[6]
		}
	}
	return "/bin/bash"
}

// createManagedUser creates a user already inside the managed group, so it is
// ours from the moment it exists — there is no window where a crash leaves an
// account we created but do not recognise.
func (h *CommandHandler) createManagedUser(rootPath, username string) error {
	cmd := exec.Command("chroot", rootPath, "useradd", "-m", "-s", "/bin/bash", "-G", accessManagedGroup, username)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		// adduser for distros without useradd. It cannot take a group, so join
		// separately.
		fallback := exec.Command("chroot", rootPath, "adduser", "--disabled-password", "--gecos", "", username)
		var fbErr bytes.Buffer
		fallback.Stderr = &fbErr
		if ferr := fallback.Run(); ferr != nil {
			return fmt.Errorf("useradd failed: %w (stderr: %s); adduser failed: %v (stderr: %s)",
				err, stderr.String(), ferr, fbErr.String())
		}
		if gerr := h.addUserToManagedGroup(rootPath, username); gerr != nil {
			return gerr
		}
	}
	return nil
}

func (h *CommandHandler) addUserToManagedGroup(rootPath, username string) error {
	cmd := exec.Command("chroot", rootPath, "usermod", "-aG", accessManagedGroup, username)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		alt := exec.Command("chroot", rootPath, "gpasswd", "-a", username, accessManagedGroup)
		var altErr bytes.Buffer
		alt.Stderr = &altErr
		if aerr := alt.Run(); aerr != nil {
			return fmt.Errorf("failed to add %s to %s: %w (stderr: %s)", username, accessManagedGroup, err, stderr.String())
		}
	}
	return nil
}

// writeAuthorizedKeys replaces the user's managed key file wholesale. Replace,
// not append: this is the operation that makes revocation possible.
func (h *CommandHandler) writeAuthorizedKeys(rootPath string, u accessUserSpec, configHash string) error {
	path := filepath.Join(rootPath, accessKeysDirRel, u.Username)
	// A locked user gets an empty file rather than a deleted one: empty is
	// unambiguous evidence of intent, missing is indistinguishable from
	// never-configured.
	content := authorizedKeysContent(u.Username, configHash, u.AuthorizedKeys)
	return writeFileAtomic(path, []byte(content), 0o644)
}

// writePrincipals sets which certificate principals are accepted for a user. An
// empty file means no certificate can authenticate as them, which is how a lock
// survives a still-trusted CA.
func (h *CommandHandler) writePrincipals(rootPath string, u accessUserSpec) error {
	path := filepath.Join(rootPath, accessPrincipalsDirRel, u.Username)
	var b strings.Builder
	b.WriteString("# Managed by orchestrator.\n")
	if !u.Locked() {
		for _, p := range u.Principals {
			b.WriteString(p)
			b.WriteString("\n")
		}
	}
	return writeFileAtomic(path, []byte(b.String()), 0o644)
}

// reconcileTrustedCAs writes one file per trusted CA and removes the ones no
// longer desired, then rebuilds the concatenated file sshd reads. Removal is
// the point: the previous single fixed path could never revoke a CA.
func (h *CommandHandler) reconcileTrustedCAs(rootPath string, spec accessConfigSpec, state *accessState) error {
	dir := filepath.Join(rootPath, accessCADirRel)

	desired := map[string]string{}
	for i, ca := range spec.CAs {
		desired[fmt.Sprintf("ca-%02d.pub", i)] = strings.TrimSpace(ca.PublicKey)
	}

	for _, old := range state.CAAliases {
		if _, keep := desired[old]; !keep {
			if err := os.Remove(filepath.Join(dir, old)); err != nil && !os.IsNotExist(err) {
				return fmt.Errorf("failed to remove revoked CA %s: %w", old, err)
			}
		}
	}

	aliases := make([]string, 0, len(desired))
	var combined strings.Builder
	combined.WriteString("# Managed by orchestrator. Trusted user CAs.\n")
	for alias, key := range desired {
		if err := writeFileAtomic(filepath.Join(dir, alias), []byte(key+"\n"), 0o644); err != nil {
			return fmt.Errorf("failed to write CA %s: %w", alias, err)
		}
		aliases = append(aliases, alias)
	}
	sort.Strings(aliases)
	for _, alias := range aliases {
		combined.WriteString(desired[alias])
		combined.WriteString("\n")
	}
	state.CAAliases = aliases

	return writeFileAtomic(filepath.Join(rootPath, accessTrustedCAsRel), []byte(combined.String()), 0o644)
}

// reconcileSudo installs or removes our sudo drop-in for a user.
//
// The file is validated with visudo before it is installed: a syntactically
// broken file in /etc/sudoers.d breaks sudo for EVERY user on the host, so this
// check is mandatory rather than defensive.
func (h *CommandHandler) reconcileSudo(rootPath string, u accessUserSpec, state *accessState) error {
	rel := accessSudoersPrefix + u.Username
	path := filepath.Join(rootPath, rel)
	st := state.Users[u.Username]

	// A locked user keeps no sudo grant.
	if !u.Sudo || u.Locked() {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("failed to remove sudo grant: %w", err)
		}
		st.SudoersFile = ""
		state.Users[u.Username] = st
		return nil
	}

	content := []byte(sudoersContent(u.Username, u.SudoNoPasswd))
	tmp := path + ".orchestrator-tmp"
	if err := writeFileAtomicNoRename(tmp, content, 0o440); err != nil {
		return fmt.Errorf("failed to stage sudoers file: %w", err)
	}
	defer os.Remove(tmp)

	// visudo runs against the staged file inside the target root.
	check := exec.Command("chroot", rootPath, "visudo", "-cf", "/"+rel+".orchestrator-tmp")
	var stderr bytes.Buffer
	check.Stderr = &stderr
	if err := check.Run(); err != nil {
		return fmt.Errorf("refusing to install an invalid sudoers file: %w (stderr: %s)", err, stderr.String())
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("failed to install sudoers file: %w", err)
	}

	st.SudoersFile = rel
	state.Users[u.Username] = st
	return nil
}

// clearPassword removes a user's password without leaving the field empty.
//
// Never `usermod -U`: on an account whose password field is just "!", it
// produces an EMPTY field, and with pam_unix nullok that is a passwordless
// login. Setting "!" explicitly is both correct and idempotent.
func (h *CommandHandler) clearPassword(rootPath, username string) error {
	cmd := exec.Command("chroot", rootPath, "usermod", "-p", "!", username)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to clear password for %s: %w (stderr: %s)", username, err, stderr.String())
	}
	return nil
}

// lockManagedUser makes a user unable to log in by ANY method, while leaving
// the account and its home directory intact.
//
// Account expiry is what does the work. `usermod -L` alone only touches the
// password field and does NOT block public-key or certificate authentication —
// the most commonly got-wrong part of locking a Linux account, and the reason a
// key-based lock needs `chage -E`.
func (h *CommandHandler) lockManagedUser(rootPath, username string, st *accessUserState) error {
	if st.OriginalShell == "" {
		if shell := h.currentShell(rootPath, username); shell != "" && !isNoLoginShell(shell) {
			st.OriginalShell = shell
		}
	}

	if err := h.clearPassword(rootPath, username); err != nil {
		return err
	}

	expire := exec.Command("chroot", rootPath, "chage", "-E", "1", username)
	var stderr bytes.Buffer
	expire.Stderr = &stderr
	if err := expire.Run(); err != nil {
		return fmt.Errorf("failed to expire account %s: %w (stderr: %s)", username, err, stderr.String())
	}

	shell := exec.Command("chroot", rootPath, "usermod", "-s", "/usr/sbin/nologin", username)
	stderr.Reset()
	shell.Stderr = &stderr
	if err := shell.Run(); err != nil {
		// A missing /usr/sbin/nologin is not fatal: expiry already blocks login.
		h.logger.Warn("failed to set nologin shell", "username", username, "error", err, "stderr", stderr.String())
	}
	return nil
}

// endManagedUserSessions ends what a locked or revoked managed user still has
// running on the LIVE root and returns how many processes it killed, and
// whether the teardown is complete (nothing of the user's left), so the caller
// runs it once per lock and retries only an incomplete one. A mounted offline
// root has nothing running, so it is a no-op there and not complete: the live
// root is torn down when it next applies. Failures are logged, never returned:
// the login is already blocked by the time this runs, and a logind that is
// absent or refuses must not undo that by failing the reconcile.
func (h *CommandHandler) endManagedUserSessions(rootPath, username string) (killed int, done bool) {
	if rootPath != "/" {
		return 0, false
	}
	uid, err := h.userUID(rootPath, username)
	if err != nil {
		h.logger.Warn("cannot end sessions: uid unknown", "username", username, "error", err)
		return 0, false
	}
	// sd_booted(3): systemd manages the host when this directory exists.
	_, sdErr := os.Stat("/run/systemd/system")
	scope := teardownScope{procRoot: "/proc", self: os.Getpid(), systemd: sdErr == nil}
	res, err := endUserSessions(username, uid, userTeardownOps{
		loginctl: func(args ...string) error {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			out, err := exec.CommandContext(ctx, "loginctl", args...).CombinedOutput()
			if err != nil {
				return fmt.Errorf("%w (%s)", err, strings.TrimSpace(string(out)))
			}
			return nil
		},
		listPIDs: scope.pidsOwnedBy,
		kill:     func(pid int) error { return syscall.Kill(pid, syscall.SIGKILL) },
		settle:   func() { time.Sleep(200 * time.Millisecond) },
	})
	for _, w := range res.Warnings {
		h.logger.Info("session teardown step did not apply", "username", username, "detail", w)
	}
	if err != nil {
		h.logger.Warn("session teardown incomplete", "username", username, "error", err)
	}
	if res.Killed > 0 {
		h.logger.Info("ended the running processes of a locked user", "username", username, "killed", res.Killed)
	}
	return res.Killed, err == nil
}

// unlockManagedUser reverses lockManagedUser, restoring the shell the user
// actually had rather than assuming /bin/bash.
func (h *CommandHandler) unlockManagedUser(rootPath, username string, st accessUserState) error {
	unexpire := exec.Command("chroot", rootPath, "chage", "-E", "-1", username)
	var stderr bytes.Buffer
	unexpire.Stderr = &stderr
	if err := unexpire.Run(); err != nil {
		return fmt.Errorf("failed to clear account expiry for %s: %w (stderr: %s)", username, err, stderr.String())
	}

	shell := st.OriginalShell
	if shell == "" || isNoLoginShell(shell) {
		shell = "/bin/bash"
	}
	restore := exec.Command("chroot", rootPath, "usermod", "-s", shell, username)
	stderr.Reset()
	restore.Stderr = &stderr
	if err := restore.Run(); err != nil {
		fallback := exec.Command("chroot", rootPath, "usermod", "-s", "/bin/sh", username)
		stderr.Reset()
		fallback.Stderr = &stderr
		if ferr := fallback.Run(); ferr != nil {
			return fmt.Errorf("failed to restore shell for %s: %w (stderr: %s)", username, err, stderr.String())
		}
	}
	// The password field stays "!": unlocking restores key access, and any
	// password is re-established by an explicit password action, never implied.
	return nil
}

// applySSHDSettings writes our drop-in, validates the whole configuration and
// reloads sshd. Returns whether a reload happened and which mode was used.
func (h *CommandHandler) applySSHDSettings(rootPath string, spec accessConfigSpec) (bool, string, error) {
	dropInPath := filepath.Join(rootPath, accessDropInRel)
	content := sshdDropInContent(spec, len(spec.CAs) > 0)

	mode := "dropin"
	if !h.sshdIncludesDropIns(rootPath) {
		// No Include directive: our drop-in would be inert, so the settings go
		// into the main config inside a marker block instead. Same safety as the
		// drop-in branch: snapshot, validate the whole config, restore on
		// rejection — a bad main config would otherwise strand the node on the
		// next sshd start, and rewriting the primary file is higher-stakes than a
		// drop-in.
		mode = "main"
		mainPath := filepath.Join(rootPath, "etc", "ssh", "sshd_config")
		previousMain, hadMain := os.ReadFile(mainPath)
		if err := h.writeSSHDMarkerBlock(rootPath, content); err != nil {
			return false, mode, err
		}
		if err := h.validateSSHDConfig(rootPath); err != nil {
			if hadMain == nil {
				_ = writeFileAtomic(mainPath, previousMain, 0o644)
			}
			return false, mode, fmt.Errorf("sshd rejected the configuration, reverted: %w", err)
		}
	} else {
		if err := os.MkdirAll(filepath.Dir(dropInPath), 0o755); err != nil {
			return false, mode, fmt.Errorf("failed to create sshd drop-in directory: %w", err)
		}
		previous, hadPrevious := os.ReadFile(dropInPath)
		if err := writeFileAtomic(dropInPath, []byte(content), 0o644); err != nil {
			return false, mode, err
		}
		// Validate the FULL configuration, not the fragment: `sshd -t -f
		// <fragment>` would miss conflicts with the main file. On failure the
		// previous drop-in is restored, so an invalid config never survives to
		// the next reboot — where sshd would refuse to start and strand the node.
		if err := h.validateSSHDConfig(rootPath); err != nil {
			if hadPrevious == nil {
				_ = writeFileAtomic(dropInPath, previous, 0o644)
			} else {
				_ = os.Remove(dropInPath)
			}
			return false, mode, fmt.Errorf("sshd rejected the configuration, reverted: %w", err)
		}
	}

	// An offline target root has no daemon to reload; the settings take effect
	// when it boots.
	if rootPath != "/" {
		return false, mode, nil
	}
	if err := h.reloadSSHD(); err != nil {
		// The configuration is valid and on disk — it will apply on next start.
		// Worth surfacing but not worth failing the whole reconcile over.
		h.logger.Warn("sshd reload failed; configuration applies on next restart", "error", err)
		return false, mode, nil
	}
	return true, mode, nil
}

func (h *CommandHandler) sshdIncludesDropIns(rootPath string) bool {
	content, err := os.ReadFile(filepath.Join(rootPath, "etc", "ssh", "sshd_config"))
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(content), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(strings.ToLower(line), "include") && strings.Contains(line, "sshd_config.d") {
			return true
		}
	}
	return false
}

// writeSSHDMarkerBlock maintains our settings inside the main sshd_config for
// images without an Include directive, delimited so a rewrite replaces exactly
// our block and nothing else.
func (h *CommandHandler) writeSSHDMarkerBlock(rootPath, content string) error {
	const (
		begin = accessMarkerBegin
		end   = accessMarkerEnd
	)
	path := filepath.Join(rootPath, "etc", "ssh", "sshd_config")
	existing, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read sshd_config: %w", err)
	}

	lines := strings.Split(string(existing), "\n")
	out := make([]string, 0, len(lines)+8)
	inBlock := false
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == begin {
			inBlock = true
			continue
		}
		if trimmed == end {
			inBlock = false
			continue
		}
		if !inBlock {
			out = append(out, line)
		}
	}

	body := strings.TrimRight(strings.Join(out, "\n"), "\n")
	// sshd honours the FIRST value it sees for a keyword, so our block goes at
	// the top — otherwise an existing PasswordAuthentication line below would win.
	updated := begin + "\n" + strings.TrimRight(content, "\n") + "\n" + end + "\n" + body + "\n"
	return writeFileAtomic(path, []byte(updated), 0o644)
}

func (h *CommandHandler) validateSSHDConfig(rootPath string) error {
	if rootPath != "/" {
		// Testing a foreign root would need a matching sshd binary in the target;
		// our own generated content is validated structurally instead.
		return nil
	}
	err, stderr := runSSHDTest()
	if err == nil {
		return nil
	}
	// `sshd -t` refuses to run at all when its privilege separation directory is
	// missing, which says nothing about the configuration we just wrote. That
	// directory lives on a tmpfs and is created by sshd's own systemd unit
	// (RuntimeDirectory=sshd), so it is legitimately absent on a host where sshd
	// has not started yet — and the apply then fails at its LAST phase, after the
	// users, keys and passwords are already on the device. Seen intermittently.
	//
	// The path comes from sshd's own message rather than a hardcoded /run/sshd:
	// it is a compile-time option, and a guess that is wrong on some image would
	// create a stray directory and still not fix the validation. Retried exactly
	// once, and only when sshd named a path — anything else is a real rejection
	// and must stay one.
	if dir := missingPrivsepDir(stderr); dir != "" {
		if mkErr := os.MkdirAll(dir, 0o755); mkErr != nil {
			h.logger.Warn("sshd's privilege separation directory is missing and could not be created",
				"path", dir, "error", mkErr)
			return err
		}
		h.logger.Info("created sshd's missing privilege separation directory before validating", "path", dir)
		if retryErr, retryStderr := runSSHDTest(); retryErr != nil {
			return fmt.Errorf("%w (%s)", retryErr, strings.TrimSpace(retryStderr))
		}
		return nil
	}
	return fmt.Errorf("%w (%s)", err, strings.TrimSpace(stderr))
}

// runSSHDTest runs `sshd -t` and returns its error together with what it said.
func runSSHDTest() (error, string) {
	cmd := exec.Command("sshd", "-t")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	return cmd.Run(), stderr.String()
}

// reloadSSHD reloads rather than restarts: a reload re-reads the configuration
// without dropping established sessions, so the operator watching the rollout
// over SSH does not get disconnected by their own change.
func (h *CommandHandler) reloadSSHD() error {
	var lastErr error
	for _, unit := range []string{"ssh", "sshd"} {
		cmd := exec.Command("systemctl", "reload", unit)
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		if err := cmd.Run(); err == nil {
			return nil
		} else {
			lastErr = fmt.Errorf("systemctl reload %s: %w (%s)", unit, err, strings.TrimSpace(stderr.String()))
		}
	}
	return lastErr
}

// writeFileAtomicNoRename writes a staging file that a caller will validate and
// rename itself (used for sudoers, which must pass visudo before installation).
func writeFileAtomicNoRename(path string, content []byte, perm os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("failed to create directory for %s: %w", path, err)
	}
	if err := os.WriteFile(path, content, perm); err != nil {
		return err
	}
	return os.Chmod(path, perm)
}

// classifyUsers reports which of the desired users this command will be able to
// manage on this host, which it will skip as unmanaged, and which of the
// manageable ones it adopts from outside the managed group. It only INSPECTS —
// no user is created, adopted or modified — so its caller can refuse a
// configuration before anything on the device has changed.
//
// The rule it mirrors is phase 2's: a user that does not exist will be created
// (manageable), a user already in the managed group is ours, a user outside it
// is manageable only with an explicit adopt request. Keep the two in step; the
// gate is worth nothing if it predicts a different outcome than the reconcile.
func (h *CommandHandler) classifyUsers(rootPath string, spec accessConfigSpec) (manageable []accessUserSpec, skipped, adopting []string, err error) {
	manageable = make([]accessUserSpec, 0, len(spec.Users))
	for _, u := range spec.Users {
		exists, eerr := h.userExists(rootPath, u.Username)
		if eerr != nil {
			return nil, nil, nil, fmt.Errorf("failed to check user %s: %w", u.Username, eerr)
		}
		if !exists {
			manageable = append(manageable, u)
			continue
		}
		ours, gerr := h.userInManagedGroup(rootPath, u.Username)
		if gerr != nil {
			return nil, nil, nil, fmt.Errorf("failed to check group membership for %s: %w", u.Username, gerr)
		}
		if !ours && !u.AdoptUnmanaged {
			skipped = append(skipped, u.Username)
			continue
		}
		if !ours {
			adopting = append(adopting, u.Username)
		}
		manageable = append(manageable, u)
	}
	return manageable, skipped, adopting, nil
}
