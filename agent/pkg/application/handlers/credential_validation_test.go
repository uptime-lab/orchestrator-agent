package handlers

import "testing"

func TestValidateProvisionUsername(t *testing.T) {
	valid := []string{"pi", "admin", "user_1", "orchestrator-agent", "_svc"}
	for _, u := range valid {
		if err := validateProvisionUsername(u); err != nil {
			t.Errorf("expected %q to be valid: %v", u, err)
		}
	}

	invalid := []string{
		"",                                     // empty
		"-rf",                                  // leading hyphen -> option injection
		"root\nroot",                           // newline -> chpasswd line injection
		"user:x",                               // colon -> chpasswd field separator
		"has space",                            // whitespace
		"UPPER",                                // uppercase not allowed
		"1leading",                             // must start with letter/underscore
		"tooooooooooooooooooooooooooooooolong", // >32 chars
	}
	for _, u := range invalid {
		if err := validateProvisionUsername(u); err == nil {
			t.Errorf("expected %q to be rejected", u)
		}
	}
}

func TestValidateEnvName(t *testing.T) {
	valid := []string{"DB_URL", "TOKEN", "_x", "API_KEY_2"}
	for _, n := range valid {
		if err := validateEnvName(n); err != nil {
			t.Errorf("expected %q to be a valid env name: %v", n, err)
		}
	}
	invalid := []string{"", "2FA", "has space", "a=b", "line\nBREAK", "a-b"}
	for _, n := range invalid {
		if err := validateEnvName(n); err == nil {
			t.Errorf("expected %q to be rejected", n)
		}
	}
}

// The cleartext-password validator is gone with the last cleartext path; the
// hazard it guarded — a newline in the value fed to chpasswd injecting a SECOND
// entry, e.g. resetting root — did not go away, so it is retested here against
// its replacement. Same attack, expressed against the shape that now travels.
func TestShadowHashPatternBlocksChpasswdLineInjection(t *testing.T) {
	// A genuine hash, as `openssl passwd -6` produces.
	if !shadowHashPattern.MatchString(validHash) {
		t.Fatalf("a real crypt(3) SHA-512 hash was rejected: %q", validHash)
	}
	rejected := []struct {
		name  string
		value string
	}{
		{"newline injecting a second chpasswd entry", validHash + "\nroot:" + validHash},
		{"carriage return", validHash + "\rroot:x"},
		{"colon addressing another account", "$6$salt$aaa:root"},
		{"a cleartext password", "s3cret:with-colon!"},
		{"empty", ""},
		{"an MD5 hash we never emit", "$1$saltsalt$0123456789012345678901"},
	}
	for _, tc := range rejected {
		if shadowHashPattern.MatchString(tc.value) {
			t.Errorf("%s was accepted: %q", tc.name, tc.value)
		}
	}
}

// provision_connection appends its key material to ~/.ssh/authorized_keys, or —
// for a CA key — to /etc/ssh/ca_key.pub, where a second line is a second trusted
// certificate authority. The platform validates only the FIRST line of a stored
// key, so the rest arrives here unexamined; these are the shapes that must not
// reach either file.
func TestValidateProvisionSSHKey(t *testing.T) {
	if err := validateProvisionSSHKey(validKey, "ssh"); err != nil {
		t.Fatalf("a real key was rejected: %v", err)
	}
	if err := validateProvisionSSHKey(validKey, "ca"); err != nil {
		t.Fatalf("a real CA key was rejected: %v", err)
	}
	// An empty type means "ssh" downstream; it must not change the verdict.
	if err := validateProvisionSSHKey(validKey, ""); err != nil {
		t.Fatalf("a real key with an unset type was rejected: %v", err)
	}

	rejected := []struct {
		name string
		key  string
	}{
		{"a second key smuggled on another line", validKey + "\nssh-rsa AAAAB3NzaC1yc2EAAAA attacker@host"},
		{"a carriage return", validKey + "\rssh-rsa AAAAB3NzaC1yc2EAAAA"},
		{"key options that change what the key does", `command="/bin/sh" ` + validKey},
		{"no key material", "ssh-ed25519"},
		{"empty", ""},
		{"whitespace only", "   \n  "},
	}
	for _, tc := range rejected {
		if err := validateProvisionSSHKey(tc.key, "ssh"); err == nil {
			t.Errorf("%s was accepted: %q", tc.name, tc.key)
		}
		if err := validateProvisionSSHKey(tc.key, "ca"); err == nil {
			t.Errorf("%s was accepted as a CA key: %q", tc.name, tc.key)
		}
	}
}

// The two apply paths must agree on what a usable key is: the same material
// already fails apply_access_config, so provision_connection accepting it would
// make a node's shell access depend on which command happened to write it.
func TestProvisionKeyRuleMatchesAccessConfigRule(t *testing.T) {
	for _, key := range []string{
		validKey,
		validKey + "\nssh-rsa AAAAB3NzaC1yc2EAAAA",
		`from="10.0.0.0/8" ` + validKey,
		"not-a-key",
		"",
	} {
		accessErr := validateAuthorizedKeyLine(key)
		provisionErr := validateProvisionSSHKey(key, "ssh")
		if (accessErr == nil) != (provisionErr == nil) {
			t.Errorf("verdicts differ for %q: access=%v provision=%v", key, accessErr, provisionErr)
		}
	}
}
