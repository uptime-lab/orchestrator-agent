//go:build linux

package handlers

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

// ZeroTier ships from the vendor's apt repository, not Ubuntu's archives —
// the ONE third-party source the catalog carries, and it is pinned here as
// constants (key URL + signed-by keyring) rather than parameterized: a
// configurable apt source would be the supply-chain knob the typed-params
// doctrine exists to refuse.
const (
	// This exact URL answers 200 on the vendor's own domain (an earlier
	// guess, debian/zerotier-releases.gpg, is a 404 — found by a live apply,
	// which is why the applier's failure message carries the HTTP status).
	zerotierKeyURL      = "https://download.zerotier.com/contact%40zerotier.com.gpg"
	zerotierKeyringPath = "/usr/share/keyrings/zerotier-releases.gpg"
	zerotierListPath    = "/etc/apt/sources.list.d/zerotier.list"
)

var zerotierNetworkIDRe = regexp.MustCompile(`^[0-9a-fA-F]{16}$`)

// createdFileSet tracks which files ONE run created, so a failure path can
// remove exactly those and never a pre-existing one — an operator's own file
// must survive our failed install.
type createdFileSet struct {
	files []string
}

// record notes a path as removable only when this run created it.
func (s *createdFileSet) record(path string, preExisted bool) {
	if preExisted {
		return
	}
	for _, f := range s.files {
		if f == path {
			return
		}
	}
	s.files = append(s.files, path)
}

// paths returns the files this run created, in creation order.
func (s *createdFileSet) paths() []string {
	return s.files
}

// applyZeroTierUtility converges ZeroTier membership: vendor repo → package →
// service → join. Networks joined outside the assignment are never touched
// (retain doctrine one level down), and "joined but awaiting authorization"
// counts as applied — authorization happens in ZeroTier Central, which the
// platform neither holds credentials for nor should.
func (h *CommandHandler) applyZeroTierUtility(params map[string]interface{}) error {
	networkID := strings.ToLower(paramStr(params, "network_id", ""))
	if !zerotierNetworkIDRe.MatchString(networkID) {
		return fmt.Errorf("network_id must be 16 hex characters, got %q", networkID)
	}

	createdRepoFiles, err := ensureZeroTierRepo()
	if err != nil {
		// A partial repo write (keyring landed, list did not) is the same
		// litter as a failed install — remove what THIS run created.
		h.removeZeroTierRepoFiles(createdRepoFiles)
		return err
	}
	if err := aptInstallIfAbsent("zerotier-one"); err != nil {
		// A dead mirror or an unsupported codename must not leave a source
		// list that fails every later apt run on the node. Only files this
		// run created are removed — a pre-existing operator source survives.
		h.removeZeroTierRepoFiles(createdRepoFiles)
		return err
	}
	if out, err := runWithEnv(nil, softwareCmdTimeout, "systemctl", "enable", "--now", "zerotier-one"); err != nil {
		return fmt.Errorf("failed to enable zerotier-one: %v: %s", err, truncateOutput(out))
	}

	// The service needs a moment on first start before the CLI socket answers.
	var listed string
	for i := 0; i < 5; i++ {
		out, err := runWithEnv(nil, softwareCmdTimeout, "zerotier-cli", "listnetworks")
		if err == nil {
			listed = out
			break
		}
		time.Sleep(2 * time.Second)
	}
	if !strings.Contains(strings.ToLower(listed), networkID) {
		if out, err := runWithEnv(nil, softwareCmdTimeout, "zerotier-cli", "join", networkID); err != nil {
			return fmt.Errorf("zerotier-cli join failed: %v: %s", err, truncateOutput(out))
		}
	}
	// Verify membership is REGISTERED (any status): OK/REQUESTING_CONFIGURATION/
	// ACCESS_DENIED all mean the join stuck; what they differ on is Central-side
	// authorization, which is the operator's half of the handshake.
	out, err := runWithEnv(nil, softwareCmdTimeout, "zerotier-cli", "listnetworks")
	if err != nil || !strings.Contains(strings.ToLower(out), networkID) {
		return fmt.Errorf("network %s is not in zerotier-cli listnetworks after join", networkID)
	}
	return nil
}

// ensureZeroTierRepo installs the vendor apt source once: signed-by keyring
// fetched over https (bounded), codename read from os-release. Skipped
// entirely when the package is already installed — an air-gapped site that
// preloaded the deb must not require reaching the vendor. It returns the
// files THIS run created (tracked via createdFileSet, pre-existing ones
// excluded), so a later failure can remove exactly its own litter — the
// return is meaningful on error too, since the keyring may already be on
// disk when the list write or the codename read fails.
func ensureZeroTierRepo() ([]string, error) {
	var created createdFileSet
	if out, err := runWithEnv(nil, softwareCmdTimeout, "dpkg-query", "-W", "-f", "${Status}", "zerotier-one"); err == nil &&
		strings.Contains(out, "install ok installed") {
		return nil, nil
	}
	listPreExisted := fileExists(zerotierListPath)
	keyringPreExisted := fileExists(zerotierKeyringPath)
	if listPreExisted && keyringPreExisted {
		return nil, nil
	}
	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Get(zerotierKeyURL)
	if err != nil {
		return created.paths(), fmt.Errorf("failed to fetch the ZeroTier signing key: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return created.paths(), fmt.Errorf("ZeroTier signing key fetch answered %d", resp.StatusCode)
	}
	key, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return created.paths(), fmt.Errorf("failed to read the ZeroTier signing key: %w", err)
	}
	// The key may arrive ASCII-armored; dearmor when gpg is present and the
	// payload looks armored, else write as-is (binary keyring).
	if strings.Contains(string(key), "BEGIN PGP PUBLIC KEY") {
		if _, err := exec.LookPath("gpg"); err != nil {
			return created.paths(), fmt.Errorf("the ZeroTier key is ASCII-armored and gpg is not available to dearmor it")
		}
		tmp := zerotierKeyringPath + ".armored"
		if err := atomicWriteFile(tmp, key, 0o644); err != nil {
			return created.paths(), err
		}
		defer os.Remove(tmp)
		if out, err := runWithEnv(nil, softwareCmdTimeout, "gpg", "--yes", "--dearmor", "-o", zerotierKeyringPath, tmp); err != nil {
			created.record(zerotierKeyringPath, keyringPreExisted) // gpg may have written before failing
			return created.paths(), fmt.Errorf("gpg --dearmor failed: %v: %s", err, truncateOutput(out))
		}
	} else {
		if err := atomicWriteFile(zerotierKeyringPath, key, 0o644); err != nil {
			return created.paths(), err
		}
	}
	created.record(zerotierKeyringPath, keyringPreExisted)
	codename := osReleaseCodename()
	if codename == "" {
		return created.paths(), fmt.Errorf("could not read VERSION_CODENAME from /etc/os-release")
	}
	line := fmt.Sprintf("deb [signed-by=%s] https://download.zerotier.com/debian/%s %s main\n",
		zerotierKeyringPath, codename, codename)
	if _, err := writeIfChanged(zerotierListPath, []byte(line), 0o644); err != nil {
		return created.paths(), err
	}
	created.record(zerotierListPath, listPreExisted)
	return created.paths(), nil
}

// removeZeroTierRepoFiles removes vendor-repo files a failed run created.
// Best-effort: the files are the litter being cleaned, not the failure itself.
func (h *CommandHandler) removeZeroTierRepoFiles(paths []string) {
	for _, p := range paths {
		if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
			h.logger.Warn("failed to remove zerotier repo file after failed install",
				"path", p, "error", err)
		}
	}
}

// fileExists reports whether a path currently exists (any stat-able entry).
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// osReleaseCodename reads VERSION_CODENAME (e.g. "noble") from /etc/os-release.
func osReleaseCodename() string {
	raw, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if v, ok := strings.CutPrefix(line, "VERSION_CODENAME="); ok {
			return strings.Trim(strings.TrimSpace(v), `"`)
		}
	}
	return ""
}
