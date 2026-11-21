package handlers

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const envBegin = "# >>> orchestrator:environment >>>"
const envEnd = "# <<< orchestrator:environment <<<"

// fakeRoot builds a root filesystem with an /etc/environment as an older agent
// left it: an operator line, a pre-marker copy merged into the body, and the
// managed block.
func fakeRoot(t *testing.T, environment string, mode os.FileMode) string {
	t.Helper()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	if environment != "" {
		if err := os.WriteFile(filepath.Join(root, "etc", "environment"), []byte(environment), mode); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// assertNoStrayCopies fails if a directory holds anything but the named files —
// a temp or backup file beside a rewritten file would carry the values too.
func assertNoStrayCopies(t *testing.T, dir string, allowed ...string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	ok := map[string]bool{}
	for _, a := range allowed {
		ok[a] = true
	}
	for _, e := range entries {
		if !ok[e.Name()] {
			t.Fatalf("unexpected file %s left in %s", e.Name(), dir)
		}
	}
}

// Env secrets land in a root-only file under the agent's own directory, never in
// /etc/environment, which pam_env exports into every login session.
func TestReconcileEnvSecretsWritesRootOnlyFile(t *testing.T) {
	root := fakeRoot(t, "PATH=\"/usr/bin:/bin\"\n", 0o644)
	env := map[string]string{"B_TOKEN": "two", "A_TOKEN": "one"}
	if _, err := reconcileEnvSecretsOnRoot(root, env); err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(root, "etc", "orchestrator", "env")
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %o, want 0600", fi.Mode().Perm())
	}
	got := readFile(t, path)
	if !strings.Contains(got, "A_TOKEN=\"one\"\nB_TOKEN=\"two\"\n") {
		t.Fatalf("unexpected content:\n%s", got)
	}
	assertNoStrayCopies(t, filepath.Join(root, "etc", "orchestrator"), "env")

	envFile := readFile(t, filepath.Join(root, "etc", "environment"))
	if envFile != "PATH=\"/usr/bin:/bin\"\n" {
		t.Fatalf("/etc/environment changed: %q", envFile)
	}
	fi, _ = os.Stat(filepath.Join(root, "etc", "environment"))
	if fi.Mode().Perm() != 0o644 {
		t.Fatalf("stock /etc/environment re-moded to %o", fi.Mode().Perm())
	}
}

// The incoming set is the resolved effective set: a detached key disappears,
// and an empty set removes the file.
func TestReconcileEnvSecretsPrunesAndRemoves(t *testing.T) {
	root := fakeRoot(t, "", 0)
	path := filepath.Join(root, "etc", "orchestrator", "env")
	if _, err := reconcileEnvSecretsOnRoot(root, map[string]string{"KEPT": "a", "DETACHED": "b"}); err != nil {
		t.Fatal(err)
	}
	if _, err := reconcileEnvSecretsOnRoot(root, map[string]string{"KEPT": "a"}); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, path); strings.Contains(got, "DETACHED") || !strings.Contains(got, `KEPT="a"`) {
		t.Fatalf("detached key not pruned:\n%s", got)
	}
	if _, err := reconcileEnvSecretsOnRoot(root, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("empty set must remove the file, stat err=%v", err)
	}
	// And an empty set on a host that never had one is a no-op.
	if _, err := reconcileEnvSecretsOnRoot(root, map[string]string{}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "etc", "environment")); !os.IsNotExist(err) {
		t.Fatalf("/etc/environment must not be created, stat err=%v", err)
	}
}

// An apply removes everything an older agent wrote into /etc/environment — the
// managed block and the pre-marker copies of the keys that block names — while
// an operator's own lines survive byte-for-byte, and no copy of the old file is
// left beside it.
func TestReconcileEnvSecretsScrubsLegacyEnvironment(t *testing.T) {
	legacy := "PATH=\"/usr/bin:/bin\"\n" +
		"# operator note\n" +
		"HAND_ADDED=keep-me\n" +
		"PREMARKER_APPLIED=old-copy\n" +
		"\n" + envBegin + "\n" +
		"PREMARKER_APPLIED=block-value\n" +
		"DETACHED_SINCE=block-secret\n" +
		envEnd + "\n"
	root := fakeRoot(t, legacy, 0o600)

	warning, err := reconcileEnvSecretsOnRoot(root, map[string]string{"FRESH": "fresh"})
	if err != nil || warning != "" {
		t.Fatalf("warning=%q err=%v", warning, err)
	}

	got := readFile(t, filepath.Join(root, "etc", "environment"))
	want := "PATH=\"/usr/bin:/bin\"\n# operator note\nHAND_ADDED=keep-me\n\n"
	if got != want {
		t.Fatalf("/etc/environment after scrub:\n got %q\nwant %q", got, want)
	}
	for _, secret := range []string{"old-copy", "block-value", "block-secret", "orchestrator:environment"} {
		if strings.Contains(got, secret) {
			t.Fatalf("%q left in /etc/environment:\n%s", secret, got)
		}
	}
	fi, _ := os.Stat(filepath.Join(root, "etc", "environment"))
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("rewritten /etc/environment mode = %o, want its previous 0600", fi.Mode().Perm())
	}
	assertNoStrayCopies(t, filepath.Join(root, "etc"), "environment", "orchestrator")

	if env := readFile(t, filepath.Join(root, "etc", "orchestrator", "env")); !strings.Contains(env, `FRESH="fresh"`) ||
		strings.Contains(env, "DETACHED_SINCE") {
		t.Fatalf("root-only file must carry exactly the incoming set:\n%s", env)
	}
}

// Without a managed block nothing in /etc/environment is evidence of the agent,
// so the file is not touched at all — not even an operator's line whose key the
// platform also delivers (a proxy, PATH). Login sessions and cron keep it.
func TestReconcileEnvSecretsLeavesOperatorLineSharingADeliveredKey(t *testing.T) {
	operator := "PATH=\"/usr/local/bin:/usr/bin:/bin\"\nhttp_proxy=http://proxy.example:3128\n# keep\n"
	root := fakeRoot(t, operator, 0o644)

	warning, err := reconcileEnvSecretsOnRoot(root, map[string]string{
		"http_proxy": "http://other.example:8080",
		"PATH":       "/opt/bin",
	})
	if err != nil || warning != "" {
		t.Fatalf("warning=%q err=%v", warning, err)
	}
	if got := readFile(t, filepath.Join(root, "etc", "environment")); got != operator {
		t.Fatalf("/etc/environment changed without a managed block:\n got %q\nwant %q", got, operator)
	}
	fi, _ := os.Stat(filepath.Join(root, "etc", "environment"))
	if fi.Mode().Perm() != 0o644 {
		t.Fatalf("/etc/environment re-moded to %o", fi.Mode().Perm())
	}
	if env := readFile(t, filepath.Join(root, "etc", "orchestrator", "env")); !strings.Contains(env, `http_proxy="http://other.example:8080"`) {
		t.Fatalf("delivered value missing from the root-only file:\n%s", env)
	}
}

// With a managed block, the block goes, and so does an outside line whose key
// the block names: the block proves the agent delivered that key, agents older
// than the marker merged their keys into the file body, and the marker-era
// agents took a same-key body line into the block when they applied it. Such a
// line is therefore a copy the agent wrote, and keeping it would keep a
// delivered value in every login session. An outside line whose key is only
// delivered now (not named by the block) has no such evidence and is kept.
func TestReconcileEnvSecretsWithBlockRemovesOnlyTheKeysTheBlockNames(t *testing.T) {
	legacy := "http_proxy=http://body-copy.example:3128\n" +
		"NO_PROXY=localhost\n" +
		envBegin + "\n" +
		"http_proxy=http://block.example:3128\n" +
		envEnd + "\n"
	root := fakeRoot(t, legacy, 0o644)

	if _, err := reconcileEnvSecretsOnRoot(root, map[string]string{
		"http_proxy": "http://block.example:3128",
		"NO_PROXY":   "delivered",
	}); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, filepath.Join(root, "etc", "environment")); got != "NO_PROXY=localhost\n" {
		t.Fatalf("/etc/environment after scrub: %q", got)
	}
}

// Broken markers make the managed region unidentifiable: the file is refused
// as the patch_file idiom refuses it, and the refusal is recognisable.
func TestScrubLegacyEnvironmentRefusesMalformedMarkers(t *testing.T) {
	for _, original := range malformedEnvironments {
		if _, _, err := scrubLegacyEnvironment([]byte(original)); !errors.Is(err, errLegacyEnvironmentMarkers) {
			t.Fatalf("expected a marker refusal for %q, got %v", original, err)
		}
	}
}

var malformedEnvironments = []string{
	"PATH=/bin\n" + envBegin + "\nA=1\n",                                   // begin without end
	"A=1\n" + envEnd + "\n",                                                // end without begin
	envEnd + "\nOPERATOR=1\n" + envBegin + "\nX=1\n",                       // end before begin
	envBegin + "\n" + envEnd + "\n" + envBegin + "\nX=1\n" + envEnd + "\n", // duplicated pair
}

// The legacy scrub is cleanup of a file the agent no longer writes, so an
// unidentifiable block does not fail the apply: the root-only file is
// delivered, /etc/environment is left byte-for-byte, and the warning — which
// reaches the command's result — says why without quoting any value.
func TestReconcileEnvSecretsWarnsAndContinuesOnMalformedMarkers(t *testing.T) {
	for _, original := range malformedEnvironments {
		root := fakeRoot(t, original, 0o644)
		warning, err := reconcileEnvSecretsOnRoot(root, map[string]string{"TOKEN": "s3cret-value"})
		if err != nil {
			t.Fatalf("malformed markers failed the apply for %q: %v", original, err)
		}
		if !strings.Contains(warning, "/etc/environment was left unchanged") || !strings.Contains(warning, "marker") {
			t.Fatalf("warning for %q does not say what was skipped: %q", original, warning)
		}
		if strings.Contains(warning, "s3cret-value") || strings.Contains(warning, "X=1") {
			t.Fatalf("warning quotes file or secret content: %q", warning)
		}
		if got := readFile(t, filepath.Join(root, "etc", "environment")); got != original {
			t.Fatalf("/etc/environment modified: got %q want %q", got, original)
		}
		if env := readFile(t, filepath.Join(root, "etc", "orchestrator", "env")); !strings.Contains(env, `TOKEN="s3cret-value"`) {
			t.Fatalf("root-only file not delivered:\n%s", env)
		}
	}
}

// At agent start, a set an older agent left in /etc/environment moves into the
// root-only file and leaves /etc/environment, without waiting for an apply.
func TestMigrateLegacyEnvironmentMovesTheLastAppliedSet(t *testing.T) {
	legacy := "HAND_ADDED=keep-me\n" + envBegin + "\nTOKEN=it's $HOME\n" + envEnd + "\n"
	root := fakeRoot(t, legacy, 0o600)

	migrated, err := migrateLegacyEnvironmentOnRoot(root)
	if err != nil || !migrated {
		t.Fatalf("migrated=%v err=%v", migrated, err)
	}
	if got := readFile(t, filepath.Join(root, "etc", "environment")); got != "HAND_ADDED=keep-me\n" {
		t.Fatalf("/etc/environment after migration: %q", got)
	}
	if got := readFile(t, filepath.Join(root, "etc", "orchestrator", "env")); !strings.Contains(got, "TOKEN=\"it's \\$HOME\"") {
		t.Fatalf("value not carried over:\n%s", got)
	}

	// A second start finds nothing to do.
	migrated, err = migrateLegacyEnvironmentOnRoot(root)
	if err != nil || migrated {
		t.Fatalf("second run: migrated=%v err=%v", migrated, err)
	}
}

// A root-only file written by a newer apply is authoritative: migration only
// removes the stale legacy copy.
func TestMigrateLegacyEnvironmentKeepsNewerFile(t *testing.T) {
	root := fakeRoot(t, envBegin+"\nTOKEN=stale\n"+envEnd+"\n", 0o600)
	if err := writeEnvSecretsOnRoot(root, map[string]string{"TOKEN": "current"}); err != nil {
		t.Fatal(err)
	}
	if _, err := migrateLegacyEnvironmentOnRoot(root); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, filepath.Join(root, "etc", "orchestrator", "env")); !strings.Contains(got, `TOKEN="current"`) {
		t.Fatalf("newer file overwritten:\n%s", got)
	}
	if got := readFile(t, filepath.Join(root, "etc", "environment")); strings.Contains(got, "stale") {
		t.Fatalf("legacy copy survived: %q", got)
	}
}

// The file is documented for `set -a; . file; set +a` in a root shell; that
// must yield each value verbatim — quotes, $, backticks and spaces included —
// and execute nothing.
func TestEnvSecretsFileSourcesVerbatimInShell(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("no sh")
	}
	values := map[string]string{
		"PLAIN":  "abc",
		"QUOTES": `it's "quoted"`,
		"SHELLY": "$HOME `id` $(id) *",
		"SPACES": "  lead and trail  ",
		"EMPTY":  "",
	}
	root := t.TempDir()
	if err := writeEnvSecretsOnRoot(root, values); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "etc", "orchestrator", "env")
	for name, want := range values {
		out, err := exec.Command("sh", "-c", `set -a; . "$1"; set +a; printf '%s' "$(printenv `+name+`)"`, "sh", path).Output()
		if err != nil {
			t.Fatalf("sourcing failed: %v", err)
		}
		if string(out) != want {
			t.Fatalf("%s = %q, want %q", name, out, want)
		}
	}
}

func TestWriteEnvSecretsRejectsUnsafeInput(t *testing.T) {
	root := t.TempDir()
	for _, env := range []map[string]string{
		{"BAD-NAME": "bad-name-value"},
		{"OK": "line\nbreak"},
		{"OK": "carriage\rreturn"},
		{"OK": "nul\x00byte"},
	} {
		err := writeEnvSecretsOnRoot(root, env)
		if err == nil {
			t.Fatalf("expected refusal for %q", env)
		}
		// The refusal reaches the command's result: it names the key, never
		// the value.
		for name, value := range env {
			if !strings.Contains(err.Error(), name) {
				t.Fatalf("refusal %q does not name the key %q", err, name)
			}
			if strings.Contains(err.Error(), value) {
				t.Fatalf("refusal %q quotes the value", err)
			}
		}
	}
	if _, err := os.Stat(filepath.Join(root, "etc", "orchestrator", "env")); !os.IsNotExist(err) {
		t.Fatalf("a refused set must write nothing, stat err=%v", err)
	}
}

// systemd's EnvironmentFile= and a shell agree on a double-quoted value with
// these four characters escaped; they do NOT agree on the shell's
// single-quote idiom, which systemd hands to a unit as a different value. No
// test here can ask systemd, so the rendered form is pinned.
func TestQuoteEnvValueIsTheFormSystemdAndAShellBothRead(t *testing.T) {
	for in, want := range map[string]string{
		"plain":         `"plain"`,
		"":              `""`,
		"it's":          `"it's"`,
		`a"b`:           `"a\"b"`,
		`back\slash`:    `"back\\slash"`,
		"$HOME":         `"\$HOME"`,
		"`id`":          "\"\\`id\\`\"",
		"*glob* #x !y ": `"*glob* #x !y "`,
	} {
		if got := quoteEnvValue(in); got != want {
			t.Errorf("quoteEnvValue(%q) = %s, want %s", in, got, want)
		}
	}
}
