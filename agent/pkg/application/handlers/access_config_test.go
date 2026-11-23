package handlers

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const validKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f alice@example"

// validHash is a real crypt(3) SHA-512 hash — `openssl passwd -6 -salt
// 0123456789abcdef hunter2` on Ubuntu. A hand-made lookalike would pass the
// pattern while proving nothing about the shape the platform actually emits.
const validHash = "$6$0123456789abcdef$GrCa1cuN5Plxg4bUmR0cJ9ohuWHAeWGcvZKD2crRyMGZbkg3t90kKEdI82BGc7AiTt5KY9TA0pFYP2h0miibi1"

func TestValidateAuthorizedKeyLine(t *testing.T) {
	valid := []struct {
		name string
		line string
	}{
		{"ed25519", validKey},
		{"rsa", "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCzAAAA comment"},
		{"no comment", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f"},
	}
	for _, tc := range valid {
		t.Run(tc.name, func(t *testing.T) {
			if err := validateAuthorizedKeyLine(tc.line); err != nil {
				t.Fatalf("rejected a valid key: %v", err)
			}
		})
	}

	invalid := []struct {
		name string
		line string
		why  string
	}{
		{"empty", "", "an empty line is not a key"},
		{"no key material", "ssh-ed25519", "type alone authorizes nothing"},
		{"newline injection", "ssh-ed25519 AAAAB3\nssh-rsa AAAAB3", "a newline smuggles in a second key"},
		{"bad base64", "ssh-ed25519 not-base64!!", "sshd may ignore the whole file after a malformed line"},
		{"unknown type", "totally-bogus AAAAB3NzaC1yc2E", "unknown algorithms are not silently accepted"},
		{"key options", `from="1.2.3.4" ssh-ed25519 AAAAB3NzaC1yc2E`, "options can carry command=/permitopen= the operator never specified"},
	}
	for _, tc := range invalid {
		t.Run(tc.name, func(t *testing.T) {
			if err := validateAuthorizedKeyLine(tc.line); err == nil {
				t.Fatalf("accepted an invalid key (%s): %q", tc.why, tc.line)
			}
		})
	}
}

func TestValidateAccessConfigRejectsBadInput(t *testing.T) {
	cases := []struct {
		name string
		spec accessConfigSpec
	}{
		{"duplicate usernames", accessConfigSpec{Users: []accessUserSpec{
			{Username: "alice", AuthorizedKeys: []string{validKey}},
			{Username: "alice", AuthorizedKeys: []string{validKey}},
		}}},
		{"invalid username", accessConfigSpec{Users: []accessUserSpec{
			{Username: "Jane Doe", AuthorizedKeys: []string{validKey}},
		}}},
		{"principal with newline", accessConfigSpec{Users: []accessUserSpec{
			{Username: "alice", AuthorizedKeys: []string{validKey}, Principals: []string{"ops\nroot"}},
		}}},
		{"set action with no password hash", accessConfigSpec{Users: []accessUserSpec{
			{Username: "alice", AuthorizedKeys: []string{validKey}, PasswordAction: "set", PasswordHash: ""},
		}}},
		// The hash is written straight into /etc/shadow through `chpasswd -e`,
		// whose input is `user:value` per line — so a colon or a newline in it
		// addresses a DIFFERENT account rather than setting a bad password.
		{"password hash containing a colon", accessConfigSpec{Users: []accessUserSpec{
			{Username: "alice", AuthorizedKeys: []string{validKey}, PasswordAction: "set",
				PasswordHash: "$6$saltsalt$aaa:root$6$x$" + strings.Repeat("a", 60)},
		}}},
		{"password hash containing a newline", accessConfigSpec{Users: []accessUserSpec{
			{Username: "alice", AuthorizedKeys: []string{validKey}, PasswordAction: "set",
				PasswordHash: validHash + "\nroot:" + validHash},
		}}},
		{"cleartext password where a hash belongs", accessConfigSpec{Users: []accessUserSpec{
			{Username: "alice", AuthorizedKeys: []string{validKey}, PasswordAction: "set", PasswordHash: "s3cret"},
		}}},
		{"an MD5 crypt hash we never emit", accessConfigSpec{Users: []accessUserSpec{
			{Username: "alice", AuthorizedKeys: []string{validKey}, PasswordAction: "set",
				PasswordHash: "$1$saltsalt$" + strings.Repeat("a", 22)},
		}}},
		{"malformed CA key", accessConfigSpec{CAs: []accessCASpec{
			{PublicKey: "not a key", Principals: []string{"ops"}},
		}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := validateAccessConfig(tc.spec); err == nil {
				t.Fatal("accepted an invalid access config; validation must reject before anything is applied")
			}
		})
	}
}

// The single most important safety property: a configuration that leaves no way
// in must be refused outright, not applied with a warning.
func TestWouldLockOutAllAccess(t *testing.T) {
	cases := []struct {
		name string
		spec accessConfigSpec
		want bool
	}{
		{
			name: "no users at all with password auth off",
			spec: accessConfigSpec{ManagePasswordAuth: true, PasswordAuthEnabled: false},
			want: true,
		},
		{
			name: "every user locked and password auth off",
			spec: accessConfigSpec{
				ManagePasswordAuth: true, PasswordAuthEnabled: false,
				Users: []accessUserSpec{{Username: "alice"}, {Username: "bob"}},
			},
			want: true,
		},
		{
			name: "one user keeps a key",
			spec: accessConfigSpec{
				ManagePasswordAuth: true, PasswordAuthEnabled: false,
				Users: []accessUserSpec{
					{Username: "alice"},
					{Username: "bob", AuthorizedKeys: []string{validKey}},
				},
			},
			want: false,
		},
		{
			name: "no keys but password auth still permitted",
			spec: accessConfigSpec{
				ManagePasswordAuth: true, PasswordAuthEnabled: true,
				Users: []accessUserSpec{{Username: "alice", PasswordAction: "set", PasswordHash: validHash}},
			},
			want: false,
		},
		{
			// The user is active (has a password), but with SSH password auth
			// off and no keys there is no SSH way in — the gate still fires.
			name: "password-only user with SSH password auth off is not an SSH way in",
			spec: accessConfigSpec{
				ManagePasswordAuth: true, PasswordAuthEnabled: false,
				Users: []accessUserSpec{{Username: "alice", PasswordAction: "set", PasswordHash: validHash}},
			},
			want: true,
		},
		{
			name: "CA plus principals counts as a way in",
			spec: accessConfigSpec{
				ManagePasswordAuth: true, PasswordAuthEnabled: false,
				Users: []accessUserSpec{{Username: "alice", AuthorizedKeys: []string{validKey}, Principals: []string{"alice"}}},
				CAs:   []accessCASpec{{PublicKey: validKey, Principals: []string{"alice"}}},
			},
			want: false,
		},
		{
			name: "trusted CA with no principals is not a way in",
			spec: accessConfigSpec{
				ManagePasswordAuth: true, PasswordAuthEnabled: false,
				Users: []accessUserSpec{{Username: "alice"}},
				CAs:   []accessCASpec{{PublicKey: validKey}},
			},
			want: true,
		},
		{
			name: "we do not manage password auth, so the existing path may survive",
			spec: accessConfigSpec{
				ManagePasswordAuth: false,
				Users:              []accessUserSpec{{Username: "alice", PasswordAction: "unchanged"}},
			},
			want: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := wouldLockOutAllAccess(tc.spec); got != tc.want {
				t.Fatalf("wouldLockOutAllAccess = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestUserSpecLockedDerivedFromCredentials(t *testing.T) {
	// No credential at all -> locked.
	if !(accessUserSpec{Username: "alice"}).Locked() {
		t.Fatal("a user with no keys and no password must be locked")
	}
	// A key -> active.
	if (accessUserSpec{Username: "alice", AuthorizedKeys: []string{validKey}}).Locked() {
		t.Fatal("a user with keys must not be locked")
	}
	// A password but no keys -> active: password login is a valid way in, and
	// locking the account would kill the password path too.
	if (accessUserSpec{Username: "alice", PasswordAction: "set", PasswordHash: validHash}).Locked() {
		t.Fatal("a password-only user must not be locked")
	}
}

func TestSSHDDropInReflectsPolicy(t *testing.T) {
	off := sshdDropInContent(accessConfigSpec{ManagePasswordAuth: true, PasswordAuthEnabled: false}, false)
	if !strings.Contains(off, "PasswordAuthentication no") {
		t.Fatal("password auth off must render PasswordAuthentication no")
	}
	if !strings.Contains(off, "KbdInteractiveAuthentication no") {
		t.Fatal("keyboard-interactive must be closed alongside passwords, or it stays a password path")
	}
	if strings.Contains(off, "TrustedUserCAKeys") {
		t.Fatal("no CA trust should be declared when there are no CAs")
	}

	on := sshdDropInContent(accessConfigSpec{ManagePasswordAuth: true, PasswordAuthEnabled: true}, true)
	if !strings.Contains(on, "PasswordAuthentication yes") {
		t.Fatal("password auth on must render PasswordAuthentication yes")
	}
	if !strings.Contains(on, "AuthorizedPrincipalsFile") {
		t.Fatal("trusting a CA without a principals file lets it vouch for any principal")
	}

	unmanaged := sshdDropInContent(accessConfigSpec{ManagePasswordAuth: false}, false)
	if strings.Contains(unmanaged, "PasswordAuthentication") {
		t.Fatal("we must not touch password auth when we do not manage it")
	}

	// The user's own file must keep working: we add a location, never replace one.
	if !strings.Contains(off, "AuthorizedKeysFile .ssh/authorized_keys /"+accessKeysDirRel+"/%u") {
		t.Fatal("AuthorizedKeysFile must list the user's own file first, then ours")
	}
}

func TestSudoersContentUsesNoPasswdOnlyWithoutPassword(t *testing.T) {
	withPassword := sudoersContent("alice", false)
	if strings.Contains(withPassword, "NOPASSWD") {
		t.Fatal("a user with a password must be prompted by sudo")
	}
	keyOnly := sudoersContent("alice", true)
	if !strings.Contains(keyOnly, "NOPASSWD:ALL") {
		t.Fatal("a key-only user needs NOPASSWD or sudo is unusable for them")
	}
}

func TestAuthorizedKeysContentIsReplaceNotAppend(t *testing.T) {
	content := authorizedKeysContent("alice", "abc123", []string{validKey})
	if !strings.Contains(content, validKey) {
		t.Fatal("key missing from rendered file")
	}
	rotated := authorizedKeysContent("alice", "def456", []string{"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCzAAAA new"})
	if strings.Contains(rotated, validKey) {
		t.Fatal("the old key survived a rotation; rendering must replace the whole set, not append")
	}
}

func TestAccessStateRoundTripAndDegradation(t *testing.T) {
	root := t.TempDir()

	// A missing state file must read as empty, not error: it is bookkeeping, and
	// authority lives in the OS.
	if st := loadAccessState(root); len(st.Users) != 0 || st.ConfigHash != "" {
		t.Fatal("a missing state file should read as empty state")
	}

	want := accessState{
		ConfigHash: "abc123",
		Users: map[string]accessUserState{
			"alice": {CreatedByUs: true, OriginalShell: "/bin/zsh", Locked: true},
		},
		CAAliases:     []string{"ca-00.pub"},
		SSHConfigMode: "dropin",
	}
	if err := saveAccessState(root, want); err != nil {
		t.Fatalf("failed to save state: %v", err)
	}

	got := loadAccessState(root)
	if got.ConfigHash != want.ConfigHash || got.SSHConfigMode != "dropin" {
		t.Fatalf("state did not round-trip: %+v", got)
	}
	if u := got.Users["alice"]; u.OriginalShell != "/bin/zsh" || !u.Locked {
		t.Fatalf("user state did not round-trip: %+v", u)
	}

	// The file may name managed users and their shells — not world-readable.
	info, err := os.Stat(filepath.Join(root, accessStateRelPath))
	if err != nil {
		t.Fatalf("state file missing: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("state file mode = %o, want 600", perm)
	}

	// A corrupt file degrades to empty rather than blocking a reconcile.
	if err := os.WriteFile(filepath.Join(root, accessStateRelPath), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if st := loadAccessState(root); st.ConfigHash != "" {
		t.Fatal("a corrupt state file must degrade to empty state")
	}
}

func TestIsNoLoginShell(t *testing.T) {
	for _, s := range []string{"/usr/sbin/nologin", "/sbin/nologin", "/bin/false", "/usr/bin/false"} {
		if !isNoLoginShell(s) {
			t.Fatalf("%s should be recognized as a no-login shell", s)
		}
	}
	for _, s := range []string{"/bin/bash", "/bin/zsh", "/bin/sh"} {
		if isNoLoginShell(s) {
			t.Fatalf("%s is a real shell and must be restorable on unlock", s)
		}
	}
}

// provision_connection writes its own sshd drop-in and unconditionally forces
// password auth on. If the two shared a filename, running it after an access
// reconcile would drop AuthorizedKeysFile — revoking every managed user, since
// sshd would fall back to ~/.ssh/authorized_keys which this feature never
// writes — and silently re-open password logins.
func TestAccessDropInDoesNotCollideWithProvisionConnection(t *testing.T) {
	const provisionDropIn = "etc/ssh/sshd_config.d/00-orchestrator.conf"
	if accessDropInRel == provisionDropIn {
		t.Fatal("access config and provision_connection must not share a drop-in file")
	}

	// sshd honours the FIRST value for a keyword and reads drop-ins in lexical
	// order, so ours must sort before provision_connection's to win.
	access := filepath.Base(accessDropInRel)
	provision := filepath.Base(provisionDropIn)
	if !(access < provision) {
		t.Fatalf("%q must sort before %q or provision_connection's password-auth setting wins", access, provision)
	}
}

// The gate the platform advertises as "refused twice" was blind to the most
// common node shape: a device whose OS user was created by provision_connection
// is UNMANAGED, so apply_access_config skips it — the keys are never installed —
// while `PasswordAuthentication no` is written anyway and the command reports
// success.
//
// This asserts the decision the linux reconcile now makes after classifying
// users: evaluate the gate against the manageable set, not the desired one.
// (classifyUsers itself is linux-tagged and cannot run on a dev Mac; what is
// worth pinning here is the rule, which is portable.)
func TestLockoutGateSeesThroughSkippedUnmanagedUsers(t *testing.T) {
	desired := accessConfigSpec{
		ManagePasswordAuth:  true,
		PasswordAuthEnabled: false, // this config closes the password path
		Users: []accessUserSpec{{
			// Created by provision_connection, so not in the managed group and
			// not marked adoptable: this command will skip it.
			Username:       "orchestrator",
			AuthorizedKeys: []string{"ssh-ed25519 AAAA... operator"},
		}},
	}

	if wouldLockOutAllAccess(desired) {
		t.Fatal("the desired config looks fine — that is exactly why the first gate misses this")
	}

	// What the device will actually end up with: the skipped user contributes
	// nothing, so nothing grants a login.
	effective := desired
	effective.Users = nil
	if !wouldLockOutAllAccess(effective) {
		t.Fatal("evaluated against the manageable set, this config must be refused")
	}
}

// The privilege separation directory is read out of sshd's own message. Getting
// this wrong in either direction is bad: missing it leaves an apply failing at
// its last phase on a host where sshd has simply not started yet,
// and matching too eagerly has the agent create directories because
// something in stderr looked like a path.
func TestMissingPrivsepDir(t *testing.T) {
	cases := []struct {
		name   string
		stderr string
		want   string
	}{
		{
			name:   "the real message",
			stderr: "Missing privilege separation directory: /run/sshd\n",
			want:   "/run/sshd",
		},
		{
			name:   "buried among other lines",
			stderr: "/etc/ssh/sshd_config line 3: Deprecated option\nMissing privilege separation directory: /var/empty\n",
			want:   "/var/empty",
		},
		{
			// A genuine rejection of the configuration we just wrote. Creating
			// anything here would be pure noise, and retrying would hide it.
			name:   "a real config error",
			stderr: "/etc/ssh/sshd_config.d/60-orchestrator.conf line 4: Bad configuration option: Nonsense\n",
			want:   "",
		},
		{
			// Never resolved against the agent's working directory.
			name:   "a relative path",
			stderr: "Missing privilege separation directory: run/sshd\n",
			want:   "",
		},
		{
			name:   "nothing at all",
			stderr: "",
			want:   "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := missingPrivsepDir(tc.stderr); got != tc.want {
				t.Errorf("missingPrivsepDir() = %q, want %q", got, tc.want)
			}
		})
	}
}

// Adopting an existing account that the entry gives no key and no password
// takes the account over AND locks it in one apply: its password is cleared,
// it is expired, and its sessions are ended — the operator's own login
// included. Nothing in the desired config looks like a lockout, because an
// account the platform does not manage is assumed to keep working; that
// assumption is false for the account the same apply adopts.
func TestAdoptingAnAccountWithNoCredentialIsRefused(t *testing.T) {
	spec := accessConfigSpec{
		Users: []accessUserSpec{{
			Username:       "ubuntu",
			AdoptUnmanaged: true,
			Sudo:           true,
			PasswordAction: "clear",
		}},
	}
	if wouldLockOutAllAccess(spec) {
		t.Fatal("the whole-node gate fires on its own; this test no longer pins the adoption case")
	}
	err := adoptionLockRefusal(spec, []string{"ubuntu"})
	if err == nil {
		t.Fatal("adopting an account with no key and no password was accepted")
	}
	if !strings.Contains(err.Error(), "ubuntu") {
		t.Errorf("the refusal does not name the account: %v", err)
	}

	// The same entry with a key adopts and keeps a way in.
	spec.Users[0].AuthorizedKeys = []string{"ssh-ed25519 AAAA ops"}
	if err := adoptionLockRefusal(spec, []string{"ubuntu"}); err != nil {
		t.Fatalf("an adoption that keeps a key was refused: %v", err)
	}
	// A managed user losing its last key is the documented lock, not this case.
	spec.Users[0].AuthorizedKeys = nil
	if err := adoptionLockRefusal(spec, nil); err != nil {
		t.Fatalf("locking an already-managed user was refused: %v", err)
	}
}
