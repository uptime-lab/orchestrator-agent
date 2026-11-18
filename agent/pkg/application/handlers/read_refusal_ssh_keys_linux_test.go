//go:build linux

package handlers

import "testing"

// The agent's read refusal missed the two SSH private-key shapes that matter
// most on these devices.
//
// OpenSSH private keys carry no extension: ssh_host_ed25519_key and id_ed25519
// end in "_key" and in nothing at all, so neither matched ".key". Only the
// BACKEND's ValidateTrackPath stopped a read_file lifting a host key into a
// workflow output — and that function's own comment says the agent must not
// depend on its caller.
func TestSSHPrivateKeysAreRefusedByShape(t *testing.T) {
	refused := []string{
		"/etc/ssh/ssh_host_ed25519_key",
		"/etc/ssh/ssh_host_rsa_key",
		"/etc/ssh/SSH_HOST_ECDSA_KEY",
		"/home/user/.ssh/id_ed25519",
		"/root/.ssh/id_rsa",
	}
	for _, p := range refused {
		if !looksLikeSSHPrivateKey(p) {
			t.Errorf("%s is readable; it is an SSH private key", p)
		}
	}
}

// The public counterparts stay readable — an operator inspecting an installed
// public key is a real thing to want, and refusing it would break tracked files
// for no gain.
func TestPublicKeysAndOrdinaryFilesStayReadable(t *testing.T) {
	allowed := []string{
		"/etc/ssh/ssh_host_ed25519_key.pub",
		"/home/user/.ssh/id_ed25519.pub",
		"/home/user/.ssh/authorized_keys",
		"/etc/ssh/sshd_config",
		"/boot/firmware/config.txt",
		"/var/lib/orchestrator/id_map.json",
	}
	for _, p := range allowed {
		if looksLikeSSHPrivateKey(p) {
			t.Errorf("%s was refused as a private key; it is not one", p)
		}
	}
}
