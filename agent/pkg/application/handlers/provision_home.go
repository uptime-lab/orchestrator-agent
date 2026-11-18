package handlers

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// passwdEntry is the subset of an /etc/passwd line the provisioning path needs.
type passwdEntry struct {
	UID  string
	GID  string
	Home string
}

// lookupPasswdEntry reads a user's uid, gid and HOME directory out of the target
// rootfs's /etc/passwd. The home is field 6 (index 5) and is the only thing that
// answers where sshd will look for authorized_keys: assuming /home/<username>
// writes the key into a directory nobody reads, and every chown/chmod that
// follows then succeeds against it, so the command reports success while the
// account has no key access at all.
func lookupPasswdEntry(rootPath, username string) (passwdEntry, error) {
	content, err := os.ReadFile(filepath.Join(rootPath, "etc", "passwd"))
	if err != nil {
		return passwdEntry{}, fmt.Errorf("failed to read passwd file to get user info: %w", err)
	}
	for _, line := range strings.Split(string(content), "\n") {
		fields := strings.Split(strings.TrimSpace(line), ":")
		if len(fields) >= 6 && fields[0] == username {
			return passwdEntry{UID: fields[2], GID: fields[3], Home: fields[5]}, nil
		}
	}
	return passwdEntry{}, fmt.Errorf("user %s not found in passwd file", username)
}

// resolveProvisionHome turns a passwd home field into the path to install keys
// into, refusing the values that mean "this account has no home". Writing into
// / or /nonexistent would report success and grant nothing, which is the failure
// this whole path exists to avoid.
func resolveProvisionHome(username, home string) (string, error) {
	home = strings.TrimSpace(home)
	if home == "" {
		// An empty field carries no information at all, so fall back to what
		// useradd would have created rather than failing a working setup.
		home = "/home/" + username
	}
	if !strings.HasPrefix(home, "/") {
		return "", fmt.Errorf("home directory %q for user %s is not an absolute path", home, username)
	}
	home = filepath.Clean(home)
	if home == "/" || home == "/nonexistent" {
		return "", fmt.Errorf("user %s has no usable home directory (%s), so an ssh key would grant no access", username, home)
	}
	return home, nil
}

// applyPasswdOwnership sets uid/gid and mode on a path inside the target rootfs.
// The ids come from that rootfs's own passwd and the path is already rooted at
// it, so this is done directly rather than by chrooting into the target to run
// coreutils: a rootfs that has no chown — a minimal or partially-unpacked image
// is exactly the case provisioning has to survive — would otherwise fail with a
// message about a missing binary rather than about the key.
// numericPasswdIDs parses a passwd entry's uid/gid, so a caller that works
// through file descriptors does not have to re-parse them at every syscall.
func numericPasswdIDs(uid, gid string) (int, int, error) {
	numericUID, err := strconv.Atoi(uid)
	if err != nil {
		return 0, 0, fmt.Errorf("passwd uid %q is not numeric: %w", uid, err)
	}
	numericGID, err := strconv.Atoi(gid)
	if err != nil {
		return 0, 0, fmt.Errorf("passwd gid %q is not numeric: %w", gid, err)
	}
	return numericUID, numericGID, nil
}

func applyPasswdOwnership(path, uid, gid string, mode os.FileMode) error {
	numericUID, err := strconv.Atoi(uid)
	if err != nil {
		return fmt.Errorf("passwd uid %q is not numeric: %w", uid, err)
	}
	numericGID, err := strconv.Atoi(gid)
	if err != nil {
		return fmt.Errorf("passwd gid %q is not numeric: %w", gid, err)
	}
	if err := os.Chown(path, numericUID, numericGID); err != nil {
		return fmt.Errorf("failed to set ownership on %s: %w", path, err)
	}
	if mode != 0 {
		if err := os.Chmod(path, mode); err != nil {
			return fmt.Errorf("failed to set permissions on %s: %w", path, err)
		}
	}
	return nil
}
