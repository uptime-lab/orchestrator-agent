package handlers

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"agent/pkg/domain/refusal"
)

// runScriptParentDirs are where a run_script body is staged, in order of
// preference. /run is a tmpfs on every systemd host and on the recovery
// bootstrap, so the resolved text never reaches persistent storage; the
// default temp directory is the fallback for a host without it.
var runScriptParentDirs = []string{"/run", ""}

// newScriptCommand builds the shell invocation for a run_script body without
// putting the body in the process's argv.
//
// The body routinely carries resolved {{secrets.*}} values, and argv is
// /proc/<pid>/cmdline — readable by every local account on a host whose /proc
// is mounted without hidepid, which is the stock configuration. The body is
// written to a 0600 file inside a fresh 0700 directory owned by the agent, and
// the shell reads it from there: /bin/sh <file>. Nothing about how the script
// runs changes otherwise — same interpreter, stdin stays unset (/dev/null),
// the exit status is the shell's — except that $0 names the staged file rather
// than the shell.
//
// The returned cleanup removes the directory and must run after the command
// has finished, because the shell reads its script incrementally.
//
// The shell leads its own process group, and cancelling ctx kills the group.
//
// A body containing a NUL byte is refused before anything is staged: no shell
// script can contain one, and the shells disagree about what they do with it
// (stop reading, or drop it), so the device would run something other than
// what was sent.
func newScriptCommand(ctx context.Context, script string) (*exec.Cmd, func(), error) {
	if strings.ContainsRune(script, 0) {
		return nil, func() {}, refusal.Wrap(errors.New("the script contains a NUL byte; a shell script cannot carry one"))
	}
	path, cleanup, err := stageScriptBody(script)
	if err != nil {
		return nil, func() {}, err
	}
	cmd := exec.CommandContext(ctx, "/bin/sh", path)
	// A timeout or cancel ends everything the script started, not only the
	// shell.
	inOwnProcessGroup(cmd)
	return cmd, cleanup, nil
}

// stageScriptBody writes script into a private directory and returns the
// file's path and a cleanup that removes the directory.
func stageScriptBody(script string) (string, func(), error) {
	var lastErr error
	for _, parent := range runScriptParentDirs {
		if parent != "" {
			if st, err := os.Stat(parent); err != nil || !st.IsDir() {
				continue
			}
		}
		// MkdirTemp creates the directory 0700 with an unpredictable name, so
		// no other account can enter it, list it, or plant the file first.
		dir, err := os.MkdirTemp(parent, "orchestrator-run-script-")
		if err != nil {
			lastErr = err
			continue
		}
		cleanup := func() { _ = os.RemoveAll(dir) }
		path := filepath.Join(dir, "script.sh")
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			cleanup()
			lastErr = err
			continue
		}
		if _, err := f.WriteString(script); err != nil {
			_ = f.Close()
			cleanup()
			return "", func() {}, fmt.Errorf("failed to stage the script: %w", err)
		}
		if err := f.Close(); err != nil {
			cleanup()
			return "", func() {}, fmt.Errorf("failed to stage the script: %w", err)
		}
		return path, cleanup, nil
	}
	return "", func() {}, fmt.Errorf("failed to stage the script: %w", lastErr)
}
