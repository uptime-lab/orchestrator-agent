//go:build linux

package handlers

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"
)

// Tailscale ships from the vendor's apt repository (pkgs.tailscale.com) — the
// second third-party source the catalog carries, pinned as constants for the
// zerotier reason: a configurable apt source would be the supply-chain knob
// the typed-params doctrine exists to refuse. The keyring URL is per
// distro+codename; the .noarmor.gpg variant is a binary keyring, so no
// dearmor step exists to fail.
const (
	tailscaleKeyringPath = "/usr/share/keyrings/tailscale-archive-keyring.gpg"
	tailscaleListPath    = "/etc/apt/sources.list.d/tailscale.list"
	// tailscaleManagedMarker records that THIS platform performed the tailnet
	// login. Its absence in front of a logged-in tailscaled is the refusal
	// gate: an operator's own session is never hijacked by an assignment.
	tailscaleManagedMarker = "/var/lib/orchestrator-agent/tailscale-managed"
	// tailscaleSysctlPath is our own drop-in enabling IP forwarding for exit
	// nodes — written for advertise_exit_node, removed when it turns off.
	tailscaleSysctlPath = "/etc/sysctl.d/99-orchestrator-tailscale.conf"
)

var (
	// tskey-auth-… (pre-auth), and the rest of the vendor's key family all
	// share the tskey- prefix and a dash-separated base62 tail.
	tailscaleAuthKeyRe  = regexp.MustCompile(`^tskey-[A-Za-z0-9-]{10,200}$`)
	tailscaleHostnameRe = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`)
)

// applyTailscaleUtility converges tailnet membership: vendor repo → package →
// service → login (or settings-only convergence when we already own the
// login). Peer approval / key expiry policy live in the Tailscale admin
// console, which the platform neither holds credentials for nor should — the
// zerotier Central split, verbatim.
func (h *CommandHandler) applyTailscaleUtility(params map[string]interface{}) error {
	authKey := paramStr(params, "auth_key", "")
	if err := validateTailscaleAuthKey(authKey); err != nil {
		return err
	}
	hostname := paramStr(params, "hostname", "")
	if hostname != "" && !tailscaleHostnameRe.MatchString(hostname) {
		return fmt.Errorf("hostname must be a DNS label (letters, digits, hyphens), got %q", hostname)
	}
	acceptRoutes := paramBool(params, "accept_routes", false)
	exitNode := paramBool(params, "advertise_exit_node", false)

	if err := ensureTailscaleInstalled(); err != nil {
		return err
	}
	if err := applyTailscaleForwarding(exitNode); err != nil {
		return err
	}
	if out, err := runWithEnv(nil, softwareCmdTimeout, "systemctl", "enable", "--now", "tailscaled"); err != nil {
		return fmt.Errorf("failed to enable tailscaled: %v: %s", err, truncateOutput(out))
	}

	// The daemon needs a moment on first start before the CLI socket answers.
	var state string
	for i := 0; i < 5; i++ {
		out, err := runWithEnv(nil, softwareCmdTimeout, "tailscale", "status", "--json")
		// `tailscale status` exits non-zero while logged out but still prints
		// the JSON; parse whatever arrived and only retry on no output at all.
		if s := parseTailscaleBackendState(out); s != "" {
			state = s
			break
		}
		_ = err
		time.Sleep(2 * time.Second)
	}

	action, err := tailscaleApplyAction(state, fileExistsAtPath(tailscaleManagedMarker))
	if err != nil {
		return err
	}
	switch action {
	case tailscaleActionUp:
		keyFile, cleanup, err := writeTailscaleAuthKeyFile(authKey)
		if err != nil {
			return err
		}
		defer cleanup()
		args := buildTailscaleUpArgs(keyFile, hostname, acceptRoutes, exitNode)
		if out, err := runWithEnv(nil, softwareCmdTimeout, "tailscale", args...); err != nil {
			return fmt.Errorf("tailscale up failed: %v: %s", err, truncateOutput(out))
		}
	case tailscaleActionSet:
		// Already logged in under our management: converge settings WITHOUT
		// the auth key — a single-use key must not be spent on a re-apply.
		args := buildTailscaleSetArgs(hostname, acceptRoutes, exitNode)
		if out, err := runWithEnv(nil, softwareCmdTimeout, "tailscale", args...); err != nil {
			return fmt.Errorf("tailscale set failed: %v: %s", err, truncateOutput(out))
		}
	}

	// Verify the backend actually reached Running — enable --now plus a green
	// `up` exit is the unit state, not the product.
	out, _ := runWithEnv(nil, softwareCmdTimeout, "tailscale", "status", "--json")
	if s := parseTailscaleBackendState(out); s != "Running" {
		return fmt.Errorf("tailscaled is not Running after apply (state %q)", s)
	}
	// Record that the login is ours only after it verifiably exists.
	if err := os.MkdirAll("/var/lib/orchestrator-agent", 0o755); err != nil {
		return fmt.Errorf("failed to create the agent state dir: %w", err)
	}
	if err := atomicWriteFile(tailscaleManagedMarker, []byte("managed by orchestrator (utility: tailscale)\n"), 0o644); err != nil {
		return fmt.Errorf("failed to write the tailscale managed marker: %w", err)
	}
	return nil
}

// validateTailscaleAuthKey re-validates on the device what the registry schema
// bounded platform-side (the renderDockerDaemonJSON second-line rule).
func validateTailscaleAuthKey(key string) error {
	if !tailscaleAuthKeyRe.MatchString(key) {
		return fmt.Errorf("auth_key must be a tskey-… pre-auth key")
	}
	return nil
}

const (
	tailscaleActionUp  = "up"
	tailscaleActionSet = "set"
)

// tailscaleApplyAction decides what the apply may do from the daemon's
// BackendState and whether OUR marker owns the login. The one refusal:
// a login we did not perform is an operator's session, and converging over
// it would swap a stranger's tailnet for ours — the pre-existing-daemon.json
// clobber, one utility over.
func tailscaleApplyAction(backendState string, managedByUs bool) (string, error) {
	if backendState == "Running" && !managedByUs {
		return "", fmt.Errorf("tailscaled is already logged in to a tailnet this platform did not join; " +
			"run `tailscale logout` on the device or remove the assignment")
	}
	if backendState == "Running" {
		return tailscaleActionSet, nil
	}
	// NeedsLogin, Stopped, NoState, or an unreadable state: a full `up` with
	// the auth key is the only path that can reach Running from any of them.
	return tailscaleActionUp, nil
}

// buildTailscaleUpArgs renders the complete flag set every time, so the login
// converges deterministically instead of accreting whatever earlier applies
// set (`tailscale up` itself refuses partial flag sets for the same reason).
//
// keyFile is read by tailscale itself through `--authkey=file:<path>`, so the
// key never appears in argv. It used to: `--authkey=tskey-...` sits in
// /proc/<pid>/cmdline, which is world-readable, for the whole of a login that
// can take two minutes — and the unprivileged contractor login an access entry
// hands out is exactly the reader that must not have it. Anyone who did could
// join the account's tailnet.
func buildTailscaleUpArgs(keyFile, hostname string, acceptRoutes, exitNode bool) []string {
	return []string{
		"up",
		"--authkey=file:" + keyFile,
		"--hostname=" + hostname,
		fmt.Sprintf("--accept-routes=%t", acceptRoutes),
		fmt.Sprintf("--advertise-exit-node=%t", exitNode),
		"--timeout=120s",
	}
}

// writeTailscaleAuthKeyFile puts the key in a 0600 file owned by root, in a
// directory only root can traverse, and returns a cleanup.
//
// os.CreateTemp gives 0600 already; the explicit Chmod is there because the
// mode is the entire point of this function and a future edit that swaps the
// helper must not silently widen it.
func writeTailscaleAuthKeyFile(authKey string) (path string, cleanup func(), err error) {
	f, err := os.CreateTemp("", "orchestrator-tskey-*")
	if err != nil {
		return "", func() {}, fmt.Errorf("creating the auth-key file: %w", err)
	}
	cleanup = func() {
		_ = os.Remove(f.Name())
	}
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		cleanup()
		return "", func() {}, fmt.Errorf("securing the auth-key file: %w", err)
	}
	if _, err := f.WriteString(authKey); err != nil {
		_ = f.Close()
		cleanup()
		return "", func() {}, fmt.Errorf("writing the auth-key file: %w", err)
	}
	if err := f.Close(); err != nil {
		cleanup()
		return "", func() {}, fmt.Errorf("closing the auth-key file: %w", err)
	}
	return f.Name(), cleanup, nil
}

// buildTailscaleSetArgs converges the managed settings on an existing login —
// no auth key, so a re-apply never spends a single-use key.
func buildTailscaleSetArgs(hostname string, acceptRoutes, exitNode bool) []string {
	return []string{
		"set",
		"--hostname=" + hostname,
		fmt.Sprintf("--accept-routes=%t", acceptRoutes),
		fmt.Sprintf("--advertise-exit-node=%t", exitNode),
	}
}

// parseTailscaleBackendState extracts BackendState from `tailscale status
// --json` output; empty on anything unparseable.
func parseTailscaleBackendState(out string) string {
	var doc struct {
		BackendState string `json:"BackendState"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &doc); err != nil {
		return ""
	}
	return doc.BackendState
}

// applyTailscaleForwarding manages OUR sysctl drop-in for exit-node routing:
// written when advertising (tailscale warns-and-degrades without it), removed
// when not — only ever our own file, never sysctl.conf.
func applyTailscaleForwarding(exitNode bool) error {
	if !exitNode {
		if err := os.Remove(tailscaleSysctlPath); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("failed to remove the forwarding drop-in: %w", err)
		}
		return nil
	}
	conf := "# Managed by orchestrator (utility: tailscale)\nnet.ipv4.ip_forward = 1\nnet.ipv6.conf.all.forwarding = 1\n"
	changed, err := writeIfChanged(tailscaleSysctlPath, []byte(conf), 0o644)
	if err != nil {
		return fmt.Errorf("failed to write the forwarding drop-in: %w", err)
	}
	if changed {
		if out, err := runWithEnv(nil, softwareCmdTimeout, "sysctl", "-p", tailscaleSysctlPath); err != nil {
			return fmt.Errorf("failed to apply the forwarding drop-in: %v: %s", err, truncateOutput(out))
		}
	}
	return nil
}

// ensureTailscaleInstalled installs the vendor apt source and the package.
// Skipped entirely when the package is already installed — an air-gapped site
// that preloaded the deb must not require reaching the vendor. On an install
// failure the source and keyring THIS run created are removed, so a dead
// mirror or unsupported codename does not leave a source list that fails
// every later apt run on the node; pre-existing files are left alone.
func ensureTailscaleInstalled() error {
	if out, err := runWithEnv(nil, softwareCmdTimeout, "dpkg-query", "-W", "-f", "${Status}", "tailscale"); err == nil &&
		strings.Contains(out, "install ok installed") {
		return nil
	}

	distro := osReleaseID()
	codename := osReleaseCodename()
	line, keyURL, err := tailscaleAptSource(distro, codename)
	if err != nil {
		return err
	}

	var created []string
	cleanup := func() {
		for _, f := range created {
			_ = os.Remove(f)
		}
	}

	if !fileExistsAtPath(tailscaleKeyringPath) {
		client := &http.Client{Timeout: 60 * time.Second}
		resp, err := client.Get(keyURL)
		if err != nil {
			return fmt.Errorf("failed to fetch the Tailscale signing key: %w", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("Tailscale signing key fetch answered %d", resp.StatusCode)
		}
		key, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		if err != nil {
			return fmt.Errorf("failed to read the Tailscale signing key: %w", err)
		}
		if err := atomicWriteFile(tailscaleKeyringPath, key, 0o644); err != nil {
			return err
		}
		created = append(created, tailscaleKeyringPath)
	}

	listPreexisted := fileExistsAtPath(tailscaleListPath)
	if _, err := writeIfChanged(tailscaleListPath, []byte(line), 0o644); err != nil {
		cleanup()
		return err
	}
	if !listPreexisted {
		created = append(created, tailscaleListPath)
	}

	if err := aptInstallIfAbsent("tailscale"); err != nil {
		cleanup()
		return err
	}
	return nil
}

// tailscaleAptSource renders the vendor source line and the keyring URL for
// this distro+codename, refusing distros the vendor does not host.
func tailscaleAptSource(distro, codename string) (line, keyURL string, err error) {
	switch distro {
	case "ubuntu", "debian", "raspbian":
	default:
		return "", "", fmt.Errorf("the tailscale utility supports Ubuntu/Debian/Raspbian, got os-release ID %q", distro)
	}
	if codename == "" {
		return "", "", fmt.Errorf("could not read VERSION_CODENAME from /etc/os-release")
	}
	line = fmt.Sprintf("deb [signed-by=%s] https://pkgs.tailscale.com/stable/%s %s main\n",
		tailscaleKeyringPath, distro, codename)
	keyURL = fmt.Sprintf("https://pkgs.tailscale.com/stable/%s/%s.noarmor.gpg", distro, codename)
	return line, keyURL, nil
}

// osReleaseID reads ID (e.g. "ubuntu") from /etc/os-release.
func osReleaseID() string {
	raw, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return ""
	}
	for _, l := range strings.Split(string(raw), "\n") {
		if v, ok := strings.CutPrefix(l, "ID="); ok {
			return strings.Trim(strings.TrimSpace(v), `"`)
		}
	}
	return ""
}

// fileExistsAtPath answers plain existence; a stat error other than not-exist
// counts as absent, which every caller here treats as "create it".
func fileExistsAtPath(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
