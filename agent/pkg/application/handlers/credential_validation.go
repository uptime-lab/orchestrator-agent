package handlers

import (
	"fmt"
	"regexp"
)

// usernameRegex matches a conservative POSIX-style Linux username: starts with a
// lowercase letter or underscore, followed by lowercase letters, digits,
// underscores or hyphens. This deliberately forbids a leading hyphen (which
// useradd/usermod would parse as an option) and any whitespace, colon or
// newline (which would break chpasswd input).
var usernameRegex = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)

// validateProvisionUsername rejects usernames that could be used for option or
// chpasswd line injection before they are passed to root-privileged tooling.
func validateProvisionUsername(username string) error {
	if username == "" {
		return fmt.Errorf("username is required")
	}
	if !usernameRegex.MatchString(username) {
		return fmt.Errorf("invalid username %q: must match %s", username, usernameRegex.String())
	}
	return nil
}

// validateProvisionConnectionUsername is the provision_connection variant. It
// additionally refuses root, which the command can only ever half-serve: sshd
// under Ubuntu's default `PermitRootLogin prohibit-password` refuses the
// password, and the account would still be handed the fleet-wide provisioning
// default, usable from the console or by any local user with `su`. The
// access-config path SKIPS such a user instead of refusing, because one name
// must not fail a whole node's config; here the username IS the command, so
// refusing is the only honest answer.
func validateProvisionConnectionUsername(username string) error {
	if err := validateProvisionUsername(username); err != nil {
		return err
	}
	if username == "root" {
		return fmt.Errorf("provision_connection refuses to provision root")
	}
	return nil
}

// validateProvisionSSHKey checks the public key material provision_connection is
// about to write, with exactly the rule the access-config path already applies
// (validateAuthorizedKeyLine): one well-formed key line, no newline, no key
// options.
//
// The platform validates only the FIRST non-empty line of a stored SSH key
// (`domain/ssh_key.ValidateOpenSSHFormat`) and stores the content whole, so
// everything after that line arrives here unexamined — and this path appends it
// verbatim, either to the user's `~/.ssh/authorized_keys` (extra keys nobody
// granted) or to `/etc/ssh/ca_key.pub` (extra trusted CAs, i.e. anyone holding
// that CA can mint a certificate for this node).
//
// Refusing rather than truncating to the first line is what makes the two apply
// paths agree: the same key material already fails access-config today, so
// accepting it here would mean a node's shell access depends on which command
// wrote it. The failure is loud — the command settles failed and nothing on the
// device is touched, since this runs before any mutation.
func validateProvisionSSHKey(sshKey, sshKeyType string) error {
	if err := validateAuthorizedKeyLine(sshKey); err != nil {
		if sshKeyType == "ca" {
			return fmt.Errorf("invalid CA key: %w", err)
		}
		return fmt.Errorf("invalid ssh key: %w", err)
	}
	return nil
}

// envNameRegex matches a valid shell environment variable name.
var envNameRegex = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// validateEnvName rejects environment variable names that are not valid shell
// identifiers, which also prevents injecting extra lines or an "=" separator
// into the env-secrets file.
func validateEnvName(name string) error {
	if !envNameRegex.MatchString(name) {
		return fmt.Errorf("invalid environment variable name %q", name)
	}
	return nil
}

// validateProvisionPassword is GONE with the last cleartext password path.
// It guarded the "user:password" line fed to chpasswd against a
// newline injecting a second entry — a real hazard, and one that has NOT gone
// away: it moved to shadowHashPattern in access_config.go, which every value
// now bound for that line must match. Its callers all send a `$6$` hash now, so
// keeping a plaintext validator would advertise a path that no longer exists.
