//go:build linux

package handlers

import (
	"os"
	"strings"
	"testing"
)

func TestValidateTailscaleAuthKey(t *testing.T) {
	if err := validateTailscaleAuthKey("tskey-auth-kABC123CNTRL-abcdefghijklmnop"); err != nil {
		t.Fatalf("a well-formed pre-auth key must pass: %v", err)
	}
	for _, bad := range []string{
		"",
		"not-a-key",
		"tskey-",                    // no tail
		"tskey-auth with spaces",    // whitespace
		"authkey-tskey-abcdefghijk", // prefix elsewhere
	} {
		if err := validateTailscaleAuthKey(bad); err == nil {
			t.Fatalf("key %q must be refused", bad)
		}
	}
}

func TestTailscaleApplyActionRefusesForeignLogin(t *testing.T) {
	// A running tailscaled without our marker is an operator's own session —
	// refused, never hijacked.
	if _, err := tailscaleApplyAction("Running", false); err == nil ||
		!strings.Contains(err.Error(), "logout") {
		t.Fatalf("a foreign login must be refused with the remedy named, got %v", err)
	}
	action, err := tailscaleApplyAction("Running", true)
	if err != nil || action != tailscaleActionSet {
		t.Fatalf("a managed running login converges via set, got %q %v", action, err)
	}
	for _, state := range []string{"NeedsLogin", "Stopped", "NoState", ""} {
		action, err := tailscaleApplyAction(state, false)
		if err != nil || action != tailscaleActionUp {
			t.Fatalf("state %q must take the up path, got %q %v", state, action, err)
		}
		// Managed marker present changes nothing below Running.
		action, err = tailscaleApplyAction(state, true)
		if err != nil || action != tailscaleActionUp {
			t.Fatalf("managed state %q must take the up path, got %q %v", state, action, err)
		}
	}
}

func TestTailscaleUpAndSetArgs(t *testing.T) {
	up := strings.Join(buildTailscaleUpArgs("/tmp/orchestrator-tskey-123", "blade-7", true, false), " ")
	for _, want := range []string{"--authkey=file:/tmp/orchestrator-tskey-123", "--hostname=blade-7", "--accept-routes=true", "--advertise-exit-node=false", "--timeout="} {
		if !strings.Contains(up, want) {
			t.Fatalf("up args missing %q: %s", want, up)
		}
	}
	set := strings.Join(buildTailscaleSetArgs("", false, true), " ")
	if strings.Contains(set, "authkey") {
		t.Fatal("set must never carry the auth key — a re-apply must not spend a single-use key")
	}
	for _, want := range []string{"--hostname=", "--accept-routes=false", "--advertise-exit-node=true"} {
		if !strings.Contains(set, want) {
			t.Fatalf("set args missing %q: %s", want, set)
		}
	}
}

func TestParseTailscaleBackendState(t *testing.T) {
	if s := parseTailscaleBackendState(`{"BackendState":"NeedsLogin","Self":{}}`); s != "NeedsLogin" {
		t.Fatalf("got %q", s)
	}
	if s := parseTailscaleBackendState("tailscaled is not running"); s != "" {
		t.Fatalf("unparseable output must yield empty, got %q", s)
	}
	if s := parseTailscaleBackendState(""); s != "" {
		t.Fatalf("empty output must yield empty, got %q", s)
	}
}

func TestTailscaleAptSource(t *testing.T) {
	line, keyURL, err := tailscaleAptSource("ubuntu", "noble")
	if err != nil {
		t.Fatalf("ubuntu/noble must render: %v", err)
	}
	if !strings.Contains(line, "https://pkgs.tailscale.com/stable/ubuntu noble main") ||
		!strings.Contains(line, "signed-by="+tailscaleKeyringPath) {
		t.Fatalf("source line wrong: %s", line)
	}
	if keyURL != "https://pkgs.tailscale.com/stable/ubuntu/noble.noarmor.gpg" {
		t.Fatalf("key URL wrong: %s", keyURL)
	}
	if _, _, err := tailscaleAptSource("fedora", "40"); err == nil {
		t.Fatal("an unhosted distro must be refused")
	}
	if _, _, err := tailscaleAptSource("ubuntu", ""); err == nil {
		t.Fatal("an empty codename must be refused")
	}
}

// The pre-auth key must never reach argv.
//
// /proc/<pid>/cmdline is world-readable and a `tailscale up` can take two
// minutes, so `--authkey=tskey-...` handed the key to every local user for the
// whole login — including the unprivileged contractor login an access entry
// manufactures, who could then join the account's tailnet.
func TestTheAuthKeyNeverReachesArgv(t *testing.T) {
	const key = "tskey-auth-abcdefghij-secret"
	path, cleanup, err := writeTailscaleAuthKeyFile(key)
	if err != nil {
		t.Fatalf("writeTailscaleAuthKeyFile: %v", err)
	}
	defer cleanup()

	args := strings.Join(buildTailscaleUpArgs(path, "blade-7", false, false), " ")
	if strings.Contains(args, key) {
		t.Fatalf("the auth key is in argv: %s", args)
	}
	if !strings.Contains(args, "--authkey=file:") {
		t.Fatalf("the key is not passed by file: %s", args)
	}

	// The file itself carries the key, readable by nobody else.
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read key file: %v", err)
	}
	if string(content) != key {
		t.Fatalf("key file holds %q, want the key", content)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("key file mode is %v, want 0600 — anything wider hands the key to the same local user", perm)
	}

	// And it is gone afterwards.
	cleanup()
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("the auth-key file survived cleanup: %v", err)
	}
}
