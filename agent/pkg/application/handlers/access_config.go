package handlers

import (
	"encoding/base64"
	"fmt"
	"regexp"
	"slices"
	"strings"
)

// Paths the reconciler owns, relative to the target root. Everything here is
// root-owned and outside any user's home: a file inside ~/.ssh is writable by
// the user, so a revoked employee with a shell could simply restore their own
// key. Revocation only sticks if the file we rewrite is one they cannot touch.
const (
	// accessKeysDirRel holds one authorized_keys file per managed user, wired up
	// via AuthorizedKeysFile. The user's own ~/.ssh/authorized_keys is never read
	// or written by us — we only ever add a second location.
	accessKeysDirRel = "etc/ssh/authorized_keys.d"
	// accessCADirRel holds one file per trusted CA, so a CA dropped from the
	// desired state can actually be removed. The old single fixed path could
	// only ever hold one CA and had no way to revoke it.
	accessCADirRel = "etc/ssh/orchestrator_ca.d"
	// accessTrustedCAsRel is the concatenation of accessCADirRel that
	// TrustedUserCAKeys points at (sshd accepts many CA keys, one per line).
	accessTrustedCAsRel = "etc/ssh/orchestrator_trusted_cas.pub"
	// accessPrincipalsDirRel holds one file per user listing the certificate
	// principals accepted for them. Without this a trusted CA vouches for ANY
	// principal it signs — far broader than the API implies.
	accessPrincipalsDirRel = "etc/ssh/auth_principals"
	// accessDropInRel is the sshd drop-in we own outright and rewrite wholesale.
	//
	// Deliberately NOT the same file provision_connection writes
	// (00-orchestrator.conf). Sharing one file meant a later provision_connection
	// silently dropped AuthorizedKeysFile — instantly revoking every managed
	// user, since sshd would fall back to ~/.ssh/authorized_keys, which this
	// feature never writes — and force-re-enabled password logins over a
	// deliberate keys-only policy.
	//
	// The name also has to sort FIRST: sshd takes the first value it sees for a
	// keyword, and drop-ins are read in lexical order. '-' (0x2D) sorts before
	// '.' (0x2E), so "00-orchestrator-access.conf" precedes
	// "00-orchestrator.conf" and the access policy wins.
	accessDropInRel = "etc/ssh/sshd_config.d/00-orchestrator-access.conf"
	// accessMarkerBegin/End delimit the access policy's block inside the MAIN
	// sshd_config, for images with no Include directive. They are named here,
	// beside the drop-in path, because a second handler has to recognise them:
	// provision_connection edits the same file and must leave this block alone,
	// and it did not — flipping the access policy's own PasswordAuthentication
	// to yes, which the next apply could not detect because the DESIRED hash had
	// not changed.
	accessMarkerBegin = "# >>> orchestrator access config >>>"
	accessMarkerEnd   = "# <<< orchestrator access config <<<"
	// accessSudoersPrefix namespaces our sudo grants so revoking one removes
	// exactly our file and never an operator's.
	accessSudoersPrefix = "etc/sudoers.d/90-orchestrator-"
	// accessManagedGroup is the authority on which users we may modify. It lives
	// in /etc/group where a human can inspect it from the recovery terminal, and
	// an operator can revoke our authority over an account by removing it.
	accessManagedGroup = "orchestrator-managed"
)

// minManagedUID refuses to manage system accounts even if something put them in
// the managed group. root and the service accounts are never ours to lock.
const minManagedUID = 1000

// accessUserSpec is one user in the desired state, decoded from the wire.
type accessUserSpec struct {
	Username       string
	AuthorizedKeys []string
	Sudo           bool
	SudoNoPasswd   bool
	// PasswordHash is a crypt(3) `$6$` hash, applied with `chpasswd -e`. The
	// platform hashes server-side and no longer populates the wire's cleartext
	// `password` field at all, which is why there is no cleartext member here to
	// fall back to: a cleartext field would let a shell on one node open a
	// stream as that node and read the account's passwords for every other one.
	PasswordHash   string
	PasswordAction string // unchanged | set | clear
	AdoptUnmanaged bool
	Principals     []string
}

// hasPassword reports whether this reconcile leaves the user with a password.
// PASSWORD_SET means one is being set; the backend always sends SET or CLEAR for
// a resolved entry (never UNCHANGED), so the action reliably reflects presence.
func (s accessUserSpec) hasPassword() bool {
	return s.PasswordAction == "set"
}

// Locked reports the desired lifecycle: a user with NO way in at all — no keys
// and no password. Derived rather than carried as a flag so the state can never
// disagree with the credentials. A password-only user is NOT locked: password
// login is allowed by default (an sshd policy may disable it separately, but
// that is not a reason to expire the account).
func (s accessUserSpec) Locked() bool {
	return len(s.AuthorizedKeys) == 0 && !s.hasPassword()
}

// accessCASpec is one trusted external CA. We trust it; we never issue.
type accessCASpec struct {
	PublicKey  string
	Principals []string
}

// accessConfigSpec is a full desired access state for one root filesystem.
type accessConfigSpec struct {
	ConfigHash          string
	ManagePasswordAuth  bool
	PasswordAuthEnabled bool
	Users               []accessUserSpec
	CAs                 []accessCASpec
}

var (
	// principalPattern is deliberately strict: a principal reaches
	// AuthorizedPrincipalsFile, where a newline would inject an extra accepted
	// principal and whitespace would silently split one into two.
	principalPattern = regexp.MustCompile(`^[A-Za-z0-9._@-]+$`)
	// keyTypePattern matches the algorithm field of an authorized_keys line.
	keyTypePattern = regexp.MustCompile(`^[a-z0-9@.-]+$`)
	// shadowHashPattern matches a crypt(3) SHA-512 hash with the default round
	// count: `$6$<salt up to 16>$<86 chars>`, all from crypt(3)'s own alphabet.
	// No `rounds=` form, because the platform never emits one — accepting shapes
	// we do not produce only widens what an attacker who can forge a config may
	// write into /etc/shadow.
	shadowHashPattern = regexp.MustCompile(`^\$6\$[A-Za-z0-9./]{1,16}\$[A-Za-z0-9./]{86}$`)
)

// validateAccessConfig checks the entire desired state before anything is
// applied. Front-loading validation is what makes the common failure — bad
// input — mutate nothing at all, instead of leaving a half-configured host.
func validateAccessConfig(spec accessConfigSpec) error {
	seen := map[string]bool{}
	for _, u := range spec.Users {
		if err := validateProvisionUsername(u.Username); err != nil {
			return fmt.Errorf("invalid username %q: %w", u.Username, err)
		}
		if seen[u.Username] {
			return fmt.Errorf("duplicate user %q in access config", u.Username)
		}
		seen[u.Username] = true

		if u.PasswordAction == "set" {
			if u.PasswordHash == "" {
				return fmt.Errorf("password action for %q is set but no password hash was sent", u.Username)
			}
			if !shadowHashPattern.MatchString(u.PasswordHash) {
				// Deliberately strict, and fail-closed. This string is written
				// straight into /etc/shadow via `chpasswd -e`, whose input format
				// is `user:hash` per line — so a colon or a newline here does not
				// produce a bad password, it produces a DIFFERENT line, i.e. an
				// edit to another account's shadow entry. The pattern therefore
				// matches exactly the shape the platform emits rather than
				// "anything that looks like a hash".
				return fmt.Errorf("password hash for %q is not a crypt(3) SHA-512 hash", u.Username)
			}
		}
		for _, k := range u.AuthorizedKeys {
			if err := validateAuthorizedKeyLine(k); err != nil {
				return fmt.Errorf("invalid ssh key for %q: %w", u.Username, err)
			}
		}
		for _, p := range u.Principals {
			if !principalPattern.MatchString(p) {
				return fmt.Errorf("invalid principal %q for %q", p, u.Username)
			}
		}
	}

	for _, ca := range spec.CAs {
		if err := validateAuthorizedKeyLine(ca.PublicKey); err != nil {
			return fmt.Errorf("invalid CA key: %w", err)
		}
		for _, p := range ca.Principals {
			if !principalPattern.MatchString(p) {
				return fmt.Errorf("invalid CA principal %q", p)
			}
		}
	}
	return nil
}

// validateAuthorizedKeyLine rejects anything that is not a well-formed public
// key line. This is not pedantry: sshd stops reading an authorized_keys file at
// a malformed line on some versions, so one bad entry can silently revoke every
// key below it. A newline would also let one entry smuggle in another.
func validateAuthorizedKeyLine(line string) error {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		return fmt.Errorf("empty key line")
	}
	if strings.ContainsAny(trimmed, "\n\r") {
		return fmt.Errorf("key line contains a newline")
	}

	fields := strings.Fields(trimmed)
	if len(fields) < 2 {
		return fmt.Errorf("key line has no key material")
	}
	// Options (from="...",no-pty) may precede the type. We do not emit them and
	// do not accept them: an option field can carry command= or permitopen=,
	// which changes what the key does in ways the operator never specified.
	keyType, blob := fields[0], fields[1]
	if !keyTypePattern.MatchString(keyType) {
		return fmt.Errorf("unrecognized key type %q (key options are not accepted)", keyType)
	}
	if !strings.HasPrefix(keyType, "ssh-") && !strings.HasPrefix(keyType, "ecdsa-") && !strings.HasPrefix(keyType, "sk-") {
		return fmt.Errorf("unrecognized key type %q", keyType)
	}
	decoded, err := base64.StdEncoding.DecodeString(blob)
	if err != nil {
		return fmt.Errorf("key material is not valid base64")
	}
	if len(decoded) < 4 {
		return fmt.Errorf("key material is too short")
	}
	return nil
}

// wouldLockOutAllAccess reports that applying this config leaves no way in.
//
// This is the most important check in the reconciler. It runs against the
// DESIRED state before anything is written, and a positive result fails the
// command with nothing changed: over-access for a while is recoverable, a
// locked-out fleet may need a physical visit.
func wouldLockOutAllAccess(spec accessConfigSpec) bool {
	// The gate only fires when this configuration CLOSES the password path.
	// Leaving it open means whatever works today keeps working — including
	// accounts we do not manage, which we cannot see from here. Refusing in that
	// case would block legitimate configurations on a guess.
	if !spec.ManagePasswordAuth || spec.PasswordAuthEnabled {
		return false
	}

	caTrusted := len(spec.CAs) > 0
	for _, u := range spec.Users {
		if u.Locked() {
			// A locked user cannot log in by ANY method — that is what the
			// account-expiry lock guarantees, certificates included. A password
			// cannot rescue them.
			continue
		}
		if len(u.AuthorizedKeys) > 0 {
			return false
		}
		if caTrusted && len(u.Principals) > 0 {
			return false
		}
	}
	return true
}

// adoptionLockRefusal refuses an apply that would adopt an existing account
// (adopting: the users outside the managed group that this apply takes over)
// and lock it in the same step, because the entry gives it no key and no
// password. The lock clears the account's password for good, expires it and
// ends its sessions, so the account someone was using stops working. The
// whole-node gate cannot see this: it assumes an account the platform does not
// manage keeps working, which is untrue for the one this apply adopts.
func adoptionLockRefusal(spec accessConfigSpec, adopting []string) error {
	var lockedOnAdoption []string
	for _, u := range spec.Users {
		if u.Locked() && slices.Contains(adopting, u.Username) {
			lockedOnAdoption = append(lockedOnAdoption, u.Username)
		}
	}
	if len(lockedOnAdoption) == 0 {
		return nil
	}
	return fmt.Errorf("would_lock_out_adopted_account: adopting %s with no key and no password "+
		"would clear its password, lock it and end its sessions; give the entry a key first",
		strings.Join(lockedOnAdoption, ", "))
}

// sshdDropInContent renders the sshd settings we own. Rewritten wholesale from
// the desired state every time, so removing a setting here removes it from the
// host — the file has no history we need to parse.
func sshdDropInContent(spec accessConfigSpec, haveCAs bool) string {
	var b strings.Builder
	b.WriteString("# Managed by orchestrator. Rewritten on every access reconcile.\n")
	b.WriteString("# Generation: " + spec.ConfigHash + "\n")
	// A list, not a replacement: the user's own ~/.ssh/authorized_keys keeps
	// working. We only add a location we control.
	b.WriteString("AuthorizedKeysFile .ssh/authorized_keys /" + accessKeysDirRel + "/%u\n")
	b.WriteString("PubkeyAuthentication yes\n")
	if haveCAs {
		b.WriteString("TrustedUserCAKeys /" + accessTrustedCAsRel + "\n")
		b.WriteString("AuthorizedPrincipalsFile /" + accessPrincipalsDirRel + "/%u\n")
	}
	if spec.ManagePasswordAuth {
		value := "no"
		if spec.PasswordAuthEnabled {
			value = "yes"
		}
		b.WriteString("PasswordAuthentication " + value + "\n")
		b.WriteString("KbdInteractiveAuthentication " + value + "\n")
	}
	return b.String()
}

// sudoersContent renders our sudo grant for one user. NOPASSWD is used when the
// user has no password: without it a key-only user can log in but cannot run
// sudo at all, having no credential to authenticate with.
func sudoersContent(username string, noPasswd bool) string {
	rule := username + " ALL=(ALL) ALL\n"
	if noPasswd {
		rule = username + " ALL=(ALL) NOPASSWD:ALL\n"
	}
	return "# Managed by orchestrator. Do not edit.\n" + rule
}

// isNoLoginShell reports a shell that denies interactive login. Used both when
// locking (to avoid recording nologin as the "original" shell and then
// restoring it on unlock) and when unlocking.
func isNoLoginShell(shell string) bool {
	switch shell {
	case "/usr/sbin/nologin", "/sbin/nologin", "/bin/false", "/usr/bin/false":
		return true
	}
	return false
}

// authorizedKeysContent renders a user's key file, with a header naming the
// owner for whoever finds it in a recovery shell.
func authorizedKeysContent(username, configHash string, keys []string) string {
	var b strings.Builder
	b.WriteString("# Managed by orchestrator for " + username + ". Rewritten on every access reconcile.\n")
	b.WriteString("# Generation: " + configHash + "\n")
	for _, k := range keys {
		b.WriteString(strings.TrimSpace(k))
		b.WriteString("\n")
	}
	return b.String()
}

// missingPrivsepDir extracts the privilege separation directory from sshd's
// complaint, or "" when that is not what it complained about.
//
// `sshd -t` refuses to run at all when that directory is absent, which says
// nothing about the configuration under test — and it is legitimately absent on
// a host where sshd has never started, because it lives on a tmpfs and is
// created by sshd's own systemd unit (RuntimeDirectory=sshd). See
// validateSSHDConfig, which creates it and retries once.
//
// The path is taken from sshd's own message rather than hardcoded to /run/sshd:
// it is a compile-time option, and a wrong guess would create a stray directory
// and still not fix the validation. Only an absolute path with no whitespace is
// accepted — a relative one would resolve against the agent's working directory,
// and creating a directory somewhere unexpected is worse than reporting the
// failure honestly.
//
// This lives in the portable file, not next to its caller, so it can be tested
// off Linux: the caller shells out to sshd and cannot run on a dev machine.
func missingPrivsepDir(stderr string) string {
	const marker = "Missing privilege separation directory:"
	for _, line := range strings.Split(stderr, "\n") {
		idx := strings.Index(line, marker)
		if idx < 0 {
			continue
		}
		path := strings.TrimSpace(line[idx+len(marker):])
		if strings.HasPrefix(path, "/") && !strings.ContainsAny(path, " \t") {
			return path
		}
	}
	return ""
}
