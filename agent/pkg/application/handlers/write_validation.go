//go:build !windows

package handlers

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// writeValidator names the check a written file must pass before the write
// is allowed to stand. A file whose service reads it on every use (sudo) or at
// its next start (sshd) turns a typo into a lost login, so the device's own
// validator decides — only the device knows which sudo and sshd it runs.
type writeValidator int

const (
	writeValidatorNone writeValidator = iota
	// writeValidatorSudoers: `visudo -cf` on the candidate, before the write.
	writeValidatorSudoers
	// writeValidatorSSHD: `sshd -t` on the whole configuration after the
	// write, the previous content restored on a rejection. A drop-in cannot be
	// checked on its own: `sshd -t -f <fragment>` misses conflicts with the
	// main file and the other drop-ins.
	writeValidatorSSHD
)

func writeValidatorFor(path string) writeValidator {
	clean := filepath.Clean(path)
	switch {
	case clean == "/etc/ssh/sshd_config", filepath.Dir(clean) == "/etc/ssh/sshd_config.d":
		return writeValidatorSSHD
	case filepath.Dir(clean) == "/etc/sudoers.d":
		return writeValidatorSudoers
	}
	return writeValidatorNone
}

// checkSudoersCandidate runs `visudo -cf` on content staged in a private
// file and returns visudo's message when it rejects it. A host without visudo
// has no sudo for the file to break, so nothing is refused there.
func checkSudoersCandidate(content []byte) error {
	visudo, err := exec.LookPath("visudo")
	if err != nil {
		return nil
	}
	dir, err := os.MkdirTemp("", "orchestrator-sudoers-")
	if err != nil {
		return fmt.Errorf("could not stage the sudoers file for checking: %w", err)
	}
	defer os.RemoveAll(dir)
	candidate := filepath.Join(dir, "candidate")
	if err := os.WriteFile(candidate, content, 0o440); err != nil {
		return fmt.Errorf("could not stage the sudoers file for checking: %w", err)
	}
	check := exec.Command(visudo, "-cf", candidate)
	var out bytes.Buffer
	check.Stdout, check.Stderr = &out, &out
	if err := check.Run(); err != nil {
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			return fmt.Errorf("could not run visudo: %w", err)
		}
		msg := strings.TrimSpace(strings.ReplaceAll(out.String(), candidate, "the file"))
		return fmt.Errorf("visudo rejected the file, nothing was written: %s", msg)
	}
	return nil
}
