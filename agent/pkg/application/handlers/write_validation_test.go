//go:build !windows

package handlers

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWriteValidatorIsChosenByPath(t *testing.T) {
	for path, want := range map[string]writeValidator{
		"/etc/ssh/sshd_config":                 writeValidatorSSHD,
		"/etc/ssh/sshd_config.d/50-local.conf": writeValidatorSSHD,
		"/etc/sudoers.d/ops":                   writeValidatorSudoers,
		"/etc/ssh/ssh_config":                  writeValidatorNone,
		"/etc/hosts":                           writeValidatorNone,
		"/etc/sudoers.d":                       writeValidatorNone,
	} {
		if got := writeValidatorFor(path); got != want {
			t.Errorf("writeValidatorFor(%s) = %v, want %v", path, got, want)
		}
	}
}

// stubOnPath puts an executable script named name first on PATH.
func stubOnPath(t *testing.T, name, body string) {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/sh\n"+body), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

// A sudoers drop-in is checked BEFORE it is written: sudo reads every file in
// /etc/sudoers.d on each invocation, so a broken one breaks sudo at once.
// visudo's own message is what the refusal carries.
func TestSudoersCandidateIsCheckedWithVisudo(t *testing.T) {
	stubOnPath(t, "visudo", `grep -q "ALL=(ALL)" "$2" && exit 0
echo "$2:1:5: syntax error" >&2; exit 1
`)
	if err := checkSudoersCandidate([]byte("ops ALL=(ALL) ALL\n")); err != nil {
		t.Fatalf("a valid grant was refused: %v", err)
	}
	err := checkSudoersCandidate([]byte("ops ALLL=\n"))
	if err == nil {
		t.Fatal("a sudoers file visudo rejects was accepted")
	}
	if !strings.Contains(err.Error(), "syntax error") {
		t.Errorf("the refusal does not carry visudo's message: %v", err)
	}
}

// A host without sudo has nothing a sudoers file can break.
func TestSudoersCandidateWithoutVisudoIsNotRefused(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	if err := checkSudoersCandidate([]byte("anything\n")); err != nil {
		t.Fatalf("refused without a validator: %v", err)
	}
}
