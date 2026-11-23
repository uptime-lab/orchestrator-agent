package handlers

import (
	"fmt"
	"path/filepath"
	"strings"
)

// The write-and-delete path policy, kept free of build tags so its rules are
// tested on every platform the module builds on. resolveForFileOp
// (file_ops_linux.go) applies it after resolving symlinks.

// protectedFiles are files this agent refuses to delete, whatever the platform
// says. Losing any of them strands the device: no boot, no login, or no way for
// the platform to reach it again. The backend keeps the same list; this copy is
// the one that still holds when a backend path forgets to check.
var protectedFiles = []string{
	"/boot/firmware/config.txt",
	"/boot/config.txt",
	"/boot/firmware/cmdline.txt",
	"/etc/watchdog.conf",
	"/etc/systemd/system.conf.d/10-orchestrator-watchdog.conf",
	"/etc/systemd/system/orchestrator-agent.service",
	"/lib/systemd/system/orchestrator-agent.service",
	"/usr/bin/orchestrator-agent",
	"/usr/local/bin/orchestrator-agent",
	"/etc/machine-id",
	"/etc/fstab",
	"/etc/passwd",
	"/etc/shadow",
	"/etc/gshadow",
	"/etc/sudoers",
	"/etc/group",
	// The access reconciler's login policy and CA trust, and
	// provision_connection's password-auth drop-in.
	"/" + accessDropInRel,
	"/" + accessTrustedCAsRel,
	"/etc/ssh/sshd_config.d/00-orchestrator.conf",
}

// protectedPrefixes is the WRITE and DELETE side of the path policy. It must
// stay in step with the read side's refused prefixes (see refusedReadPrefixes),
// and it did not: reads refused six kernel/runtime prefixes while writes and
// deletes refused three. The backend grew /var/run and /var/lock; the agent's
// write side never followed.
//
// Refusing a write under /run is not pedantry. /run holds pid files, sockets and
// the systemd runtime tree; writing there through a platform command can wedge
// services that are mid-flight, and unlike /etc there is no versioned copy to
// restore from because the whole tree is a tmpfs that exists only until reboot.
var protectedPrefixes = []string{
	// What the access reconciler writes, spelled from its own constants so a
	// rename there cannot leave the policy guarding a name nothing uses.
	"/" + accessKeysDirRel + "/",
	"/" + accessCADirRel + "/",
	"/" + accessPrincipalsDirRel + "/",
	"/" + accessSudoersPrefix,
	"/proc/",
	"/sys/",
	"/dev/",
	"/run/",
	"/var/run/",
	"/var/lock/",
}

// checkProtectedNames is the name-based half of the check. Case-insensitive on
// purpose: the boot partition is vfat, where CONFIG.TXT and config.txt are one
// file.
func checkProtectedNames(candidate, adoptionFile string) error {
	if adoptionFile != "" && strings.EqualFold(candidate, filepath.Clean(adoptionFile)) {
		return fmt.Errorf("%s is this node's adoption file", candidate)
	}
	for _, p := range protectedFiles {
		if strings.EqualFold(candidate, p) {
			return fmt.Errorf("%s is managed by the platform and cannot be modified by this command", candidate)
		}
	}
	for _, prefix := range protectedPrefixes {
		// The directory ITSELF is protected too, not only what is under it:
		// an ownership walk that chowned /etc/ssh/authorized_keys.d to an
		// archive's owner would make sshd's StrictModes refuse every key in
		// it — the platform's own login path.
		if strings.HasPrefix(strings.ToLower(candidate), strings.ToLower(prefix)) ||
			strings.EqualFold(candidate, strings.TrimSuffix(prefix, "/")) {
			return fmt.Errorf("%s is under %s, which this command may not touch", candidate, strings.TrimSuffix(prefix, "/"))
		}
	}
	return nil
}
