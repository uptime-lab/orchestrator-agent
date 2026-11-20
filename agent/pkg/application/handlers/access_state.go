package handlers

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// accessStateVersion guards against reading a file written by a future agent
// with different semantics. An unreadable or newer state file is treated as
// absent, never as an error: the state file is bookkeeping, and authority over
// what we may touch lives in the OS (group membership), so losing it must
// degrade gracefully rather than block a reconcile.
const accessStateVersion = 1

// accessStateRelPath is where the reconciler records what it has done, relative
// to the target root. Root-owned, 0600 — it can name managed users and the
// original shells to restore, which is not world-readable information.
const accessStateRelPath = "var/lib/orchestrator/access-state.json"

// accessState is the agent's record of the access configuration it applied.
//
// It is deliberately NOT the source of truth for ownership: membership of the
// orchestrator-managed group is. If this file is lost, the reconciler still
// refuses to touch unmanaged users; it only loses the ability to restore an
// original shell on unlock and the cheap no-op check.
type accessState struct {
	Version int `json:"version"`
	// ConfigHash is the last successfully applied desired-state hash. A repeat
	// delivery of the same hash is a no-op.
	ConfigHash string `json:"config_hash"`
	// Partial marks a reconcile that failed midway, so the next run knows not to
	// trust ConfigHash as "fully applied".
	Partial bool                       `json:"partial,omitempty"`
	Users   map[string]accessUserState `json:"users"`
	// CAAliases are the CA files we wrote, so ones dropped from the desired
	// state can be removed — CA revocation is impossible without this list.
	CAAliases []string `json:"ca_aliases,omitempty"`
	// SSHConfigMode records how the sshd settings were applied ("dropin" or
	// "main"), because an image with no Include directive needs the marker-block
	// path and recovery differs between the two.
	SSHConfigMode string `json:"sshd_config_mode,omitempty"`
}

// accessUserState is what we know about one user we manage.
type accessUserState struct {
	// CreatedByUs distinguishes a user we made from one an operator explicitly
	// asked us to adopt. Both may be locked; only the distinction is logged.
	CreatedByUs bool `json:"created_by_us"`
	Adopted     bool `json:"adopted,omitempty"`
	// OriginalShell is captured before locking so unlock restores what the user
	// actually had rather than guessing /bin/bash.
	OriginalShell string `json:"original_shell,omitempty"`
	Locked        bool   `json:"locked,omitempty"`
	// SessionsEnded records that the user's running processes were ended after
	// the lock, so the teardown runs once per lock rather than on every apply.
	// Absent (a lock that predates it, or a lost state file) means not yet.
	SessionsEnded bool `json:"sessions_ended,omitempty"`
	// SudoersFile is the drop-in we own for this user, so revoking sudo removes
	// exactly our grant and never an operator's.
	SudoersFile string `json:"sudoers_file,omitempty"`
}

// loadAccessState reads the state file under rootPath. A missing, unreadable,
// corrupt or future-version file yields an empty state rather than an error —
// see the type comment for why that is safe.
func loadAccessState(rootPath string) accessState {
	empty := accessState{Version: accessStateVersion, Users: map[string]accessUserState{}}

	raw, err := os.ReadFile(filepath.Join(rootPath, accessStateRelPath))
	if err != nil {
		return empty
	}
	var st accessState
	if err := json.Unmarshal(raw, &st); err != nil {
		return empty
	}
	if st.Version != accessStateVersion {
		return empty
	}
	if st.Users == nil {
		st.Users = map[string]accessUserState{}
	}
	return st
}

// saveAccessState writes the state file atomically (temp + rename + directory
// fsync), the same durability pattern handlePatchFile uses: a torn state file
// would cost the original-shell record needed to unlock a user correctly.
func saveAccessState(rootPath string, st accessState) error {
	st.Version = accessStateVersion

	path := filepath.Join(rootPath, accessStateRelPath)
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("failed to create state directory: %w", err)
	}

	payload, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to encode access state: %w", err)
	}
	payload = append(payload, '\n')

	tmp, err := os.CreateTemp(dir, ".access-state-*.tmp")
	if err != nil {
		return fmt.Errorf("failed to create temp state file: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	if _, err := tmp.Write(payload); err != nil {
		tmp.Close()
		return fmt.Errorf("failed to write temp state file: %w", err)
	}
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return fmt.Errorf("failed to set state file permissions: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("failed to sync temp state file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("failed to close temp state file: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("failed to install state file: %w", err)
	}
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}
