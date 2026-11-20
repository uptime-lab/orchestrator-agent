//go:build !windows

package handlers

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The script body carries resolved secrets; argv is world-readable through
// /proc/<pid>/cmdline. Nothing of the body may reach the argument vector.
func TestRunScriptBodyNeverReachesArgv(t *testing.T) {
	runScriptParentDirs = []string{t.TempDir()}
	t.Cleanup(func() { runScriptParentDirs = []string{"/run", ""} })

	const marker = "RUN_SCRIPT_SECRET_MARKER_5c1e"
	script := "TOKEN=" + marker + "\necho \"$TOKEN\"\n"

	cmd, cleanup, err := newScriptCommand(context.Background(), script)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()

	for i, arg := range cmd.Args {
		if strings.Contains(arg, marker) {
			t.Fatalf("argv[%d] carries the script body: %q", i, arg)
		}
	}
	if len(cmd.Args) != 2 || cmd.Args[0] != "/bin/sh" {
		t.Fatalf("unexpected argv shape: %q", cmd.Args)
	}

	// The staged copy is private: 0600 in a 0700 directory.
	staged := cmd.Args[1]
	fi, err := os.Stat(staged)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("staged script mode = %v, want 0600", fi.Mode().Perm())
	}
	di, err := os.Stat(filepath.Dir(staged))
	if err != nil {
		t.Fatal(err)
	}
	if di.Mode().Perm() != 0o700 {
		t.Errorf("staging directory mode = %v, want 0700", di.Mode().Perm())
	}

	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	if err := cmd.Run(); err != nil {
		t.Fatalf("script failed: %v", err)
	}
	if got := strings.TrimSpace(stdout.String()); got != marker {
		t.Fatalf("stdout = %q, want %q", got, marker)
	}

	cleanup()
	if _, err := os.Stat(filepath.Dir(staged)); !os.IsNotExist(err) {
		t.Fatalf("staging directory survived cleanup: %v", err)
	}
}

// What the script observes is unchanged: the shell's exit status is the
// script's, and its stdin is empty rather than the script text.
func TestRunScriptKeepsExitStatusAndEmptyStdin(t *testing.T) {
	runScriptParentDirs = []string{t.TempDir()}
	t.Cleanup(func() { runScriptParentDirs = []string{"/run", ""} })

	cmd, cleanup, err := newScriptCommand(context.Background(),
		"rest=$(cat)\nprintf '[%s]' \"$rest\"\nexit 7\n")
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()

	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	err = cmd.Run()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != 7 {
		t.Fatalf("exit status = %v, want 7", err)
	}
	if got := stdout.String(); got != "[]" {
		t.Fatalf("the script read %q from stdin, want nothing", got)
	}
}
