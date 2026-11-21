package handlers

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// envSecretsRelPath is where env secrets land, relative to a root filesystem:
// /etc/orchestrator/env, 0600 root:root. Readable by root only, and loaded by
// nothing automatically — a service opts in with
// `EnvironmentFile=/etc/orchestrator/env`, a root shell with
// `set -a; . /etc/orchestrator/env; set +a`. /etc/orchestrator is the agent's own
// directory: image capture strips it and the uninstall script removes it, so the
// values leave with the node's identity.
//
// It is NOT /etc/environment. pam_env reads that file as root and exports every
// line into every session it opens (ssh, login, su, cron), so every account that
// can log in on the device saw every value whatever the file's mode was.
var envSecretsRelPath = filepath.Join("etc", "orchestrator", "env")

// legacyEnvironmentRelPath is the file older agents wrote env secrets into.
var legacyEnvironmentRelPath = filepath.Join("etc", "environment")

// environmentMarker names the block older agents managed in /etc/environment
// (`# >>> orchestrator:environment >>>`, the patch_file idiom). Its content is
// the last set those agents applied; everything outside it is operator-owned.
const environmentMarker = "environment"

// renderEnvSecretsFile renders the effective env-secret set in a syntax that
// systemd's EnvironmentFile= and a POSIX shell's `.` read to the same values:
// every value is double-quoted with backslash, double quote, dollar and
// backtick escaped (see quoteEnvValue). The single-quote idiom a shell reads
// (close, escaped quote, reopen) is NOT what systemd reads: it hands a unit a
// different value. Keys are
// sorted so an unchanged set renders byte-identically. Callers validate keys and
// reject newlines in values before rendering.
func renderEnvSecretsFile(env map[string]string) []byte {
	names := make([]string, 0, len(env))
	for name := range env {
		names = append(names, name)
	}
	sort.Strings(names)

	var b strings.Builder
	b.WriteString("# Environment secrets delivered by the orchestrator agent. Root only.\n")
	b.WriteString("# Rewritten on every provision; edits here are lost.\n")
	b.WriteString("# A systemd unit: EnvironmentFile=/etc/orchestrator/env\n")
	b.WriteString("# A root shell:   set -a; . /etc/orchestrator/env; set +a\n")
	for _, name := range names {
		fmt.Fprintf(&b, "%s=%s\n", name, quoteEnvValue(env[name]))
	}
	return []byte(b.String())
}

// quoteEnvValue double-quotes a value. Inside double quotes both systemd and
// a POSIX shell unescape exactly \\, \", \$ and \`, and neither expands
// anything once those are escaped, so the two read the same bytes back.
func quoteEnvValue(v string) string {
	return `"` + envValueEscaper.Replace(v) + `"`
}

var envValueEscaper = strings.NewReplacer(`\`, `\\`, `"`, `\"`, `$`, `\$`, "`", "\\`")

// errLegacyEnvironmentMarkers marks a /etc/environment whose managed block
// cannot be identified (a marker without its pair, an end before its begin, or
// a marker twice). The file is then left exactly as it is.
var errLegacyEnvironmentMarkers = errors.New("managed block markers are malformed")

// scrubLegacyEnvironment removes every env secret an older agent wrote into
// /etc/environment and returns the cleaned content plus the set it found in the
// managed block (the last set that agent applied).
//
// What is removed: the managed block, markers included; and, outside it, every
// line whose key is in that block's last-applied set — the block itself proves
// those keys were the agent's, and agents that predate the marker merged the
// same keys into the file body. Nothing else is touched: comments, blank lines
// and an operator's own variables survive byte-for-byte. Without a block there
// is no evidence that any line is the agent's, so the content is returned
// unchanged, whatever keys are delivered elsewhere: a key the platform also
// delivers (http_proxy, PATH) may be the operator's own line.
//
// Broken or duplicated markers are refused, as patchManagedBlock refuses them:
// the managed region cannot be identified, so the file is not modified.
func scrubLegacyEnvironment(original []byte) ([]byte, map[string]string, error) {
	begin, end := patchMarkerLines(environmentMarker)
	lines := strings.Split(string(original), "\n")

	beginIdx, endIdx := -1, -1
	beginCount, endCount := 0, 0
	for i, line := range lines {
		switch strings.TrimSpace(line) {
		case begin:
			beginCount++
			if beginIdx == -1 {
				beginIdx = i
			}
		case end:
			endCount++
			if endIdx == -1 {
				endIdx = i
			}
		}
	}
	if beginCount > 1 || endCount > 1 {
		return nil, nil, fmt.Errorf("%w: '%s' appears more than once (%d begin, %d end)", errLegacyEnvironmentMarkers, environmentMarker, beginCount, endCount)
	}
	switch {
	case beginCount == 0 && endCount == 0:
	case beginIdx == -1:
		return nil, nil, fmt.Errorf("%w: '%s' has an end marker at line %d and no begin marker", errLegacyEnvironmentMarkers, environmentMarker, endIdx+1)
	case endIdx == -1:
		return nil, nil, fmt.Errorf("%w: '%s' has a begin marker at line %d and no end marker", errLegacyEnvironmentMarkers, environmentMarker, beginIdx+1)
	case endIdx < beginIdx:
		return nil, nil, fmt.Errorf("%w: '%s' ends at line %d, before it begins at line %d", errLegacyEnvironmentMarkers, environmentMarker, endIdx+1, beginIdx+1)
	}
	if beginIdx == -1 {
		return original, map[string]string{}, nil
	}

	applied := map[string]string{}
	for _, line := range lines[beginIdx+1 : endIdx] {
		if key, value, ok := envAssignment(line); ok {
			applied[key] = value
		}
	}

	kept := make([]string, 0, len(lines))
	for i, line := range lines {
		if i >= beginIdx && i <= endIdx {
			continue
		}
		if key, _, ok := envAssignment(line); ok {
			if _, wasApplied := applied[key]; wasApplied {
				continue
			}
		}
		kept = append(kept, line)
	}
	return []byte(strings.Join(kept, "\n")), applied, nil
}

// envAssignment parses a KEY=value line as older agents wrote them. Blank and
// comment lines are not assignments.
func envAssignment(line string) (key, value string, ok bool) {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" || strings.HasPrefix(trimmed, "#") {
		return "", "", false
	}
	parts := strings.SplitN(trimmed, "=", 2)
	key = strings.TrimSpace(parts[0])
	if len(parts) == 2 {
		value = parts[1]
	}
	return key, value, key != ""
}

// validateEnvSecrets rejects a set that could not be written one assignment per
// line: a key that is not a shell identifier, or a value carrying a line break
// or a NUL (which a shell and systemd would each cut short differently). The
// refusal names the key and never the value: it reaches the command's result.
func validateEnvSecrets(env map[string]string) error {
	for name, value := range env {
		if err := validateEnvName(name); err != nil {
			return err
		}
		if strings.ContainsAny(value, "\n\r\x00") {
			return fmt.Errorf("invalid value for env %q: must not contain newline, carriage return or NUL characters", name)
		}
	}
	return nil
}

// writeEnvSecretsOnRoot makes the root-only env file under rootPath hold exactly
// the given effective set (node → OU → root, resolved platform-side, so it is
// authoritative: a detached secret disappears). An empty set removes the file.
// rootPath is "/" on the running system or the mount point of an installed
// rootfs written from recovery.
func writeEnvSecretsOnRoot(rootPath string, env map[string]string) error {
	if err := validateEnvSecrets(env); err != nil {
		return err
	}
	path := filepath.Join(rootPath, envSecretsRelPath)
	if len(env) == 0 {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("failed to remove %s: %w", path, err)
		}
		return nil
	}
	// writeFileAtomic stages in a 0600 temp file beside the target and renames
	// it into place, so no reader ever sees a partial file and no copy of a
	// value is left behind on either outcome.
	return writeFileAtomic(path, renderEnvSecretsFile(env), 0o600)
}

// scrubLegacyEnvironmentOnRoot removes the env secrets older agents wrote into
// rootPath's /etc/environment (see scrubLegacyEnvironment) and returns the set
// found in their managed block. A file with nothing of ours in it is not
// rewritten, so a stock /etc/environment keeps its content and its mode; a
// rewritten one keeps its current mode. No backup copy is made — it would carry
// the values this exists to remove.
func scrubLegacyEnvironmentOnRoot(rootPath string) (map[string]string, error) {
	path := filepath.Join(rootPath, legacyEnvironmentRelPath)
	original, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to read %s: %w", path, err)
	}
	cleaned, applied, err := scrubLegacyEnvironment(original)
	if err != nil {
		return nil, fmt.Errorf("failed to remove env secrets from %s: %w", path, err)
	}
	if bytes.Equal(cleaned, original) {
		return applied, nil
	}
	mode := os.FileMode(0o600)
	if fi, err := os.Stat(path); err == nil {
		mode = fi.Mode().Perm()
	}
	if err := writeFileAtomic(path, cleaned, mode); err != nil {
		return nil, err
	}
	return applied, nil
}

// reconcileEnvSecretsOnRoot is what every apply runs: the root-only file is
// written first, so a failure there leaves the device as it was; only then are
// the legacy copies in /etc/environment removed.
//
// That removal is cleanup of a file the agent no longer writes, so a block it
// cannot identify does not fail the apply: /etc/environment is left as it is
// and the returned warning says why, for the command's result. Any other
// failure to read or rewrite the file is still an error.
func reconcileEnvSecretsOnRoot(rootPath string, env map[string]string) (warning string, err error) {
	if err := writeEnvSecretsOnRoot(rootPath, env); err != nil {
		return "", err
	}
	if _, err := scrubLegacyEnvironmentOnRoot(rootPath); err != nil {
		if errors.Is(err, errLegacyEnvironmentMarkers) {
			return fmt.Sprintf("/%s was left unchanged (%v); remove that block by hand", legacyEnvironmentRelPath, errors.Unwrap(err)), nil
		}
		return "", err
	}
	return "", nil
}

// migrateLegacyEnvironmentOnRoot moves a set an older agent left in
// /etc/environment into the root-only file without waiting for the next apply,
// so taking the new agent is enough to take the values out of login sessions.
// The root-only file, when it exists, came from a newer apply and wins: the
// legacy set is then only removed. It reports whether anything was migrated.
func migrateLegacyEnvironmentOnRoot(rootPath string) (bool, error) {
	path := filepath.Join(rootPath, legacyEnvironmentRelPath)
	original, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, fmt.Errorf("failed to read %s: %w", path, err)
	}
	_, applied, err := scrubLegacyEnvironment(original)
	if err != nil {
		return false, fmt.Errorf("failed to inspect %s: %w", path, err)
	}
	if len(applied) == 0 {
		return false, nil
	}
	if _, err := os.Stat(filepath.Join(rootPath, envSecretsRelPath)); os.IsNotExist(err) {
		// Values an older agent accepted but this one would refuse are dropped
		// rather than carried over: the file must stay one assignment per line.
		valid := make(map[string]string, len(applied))
		for k, v := range applied {
			if validateEnvSecrets(map[string]string{k: v}) == nil {
				valid[k] = v
			}
		}
		if len(valid) > 0 {
			if err := writeEnvSecretsOnRoot(rootPath, valid); err != nil {
				return false, err
			}
		}
	} else if err != nil {
		return false, fmt.Errorf("failed to stat %s: %w", filepath.Join(rootPath, envSecretsRelPath), err)
	}
	if _, err := scrubLegacyEnvironmentOnRoot(rootPath); err != nil {
		return false, err
	}
	return true, nil
}
