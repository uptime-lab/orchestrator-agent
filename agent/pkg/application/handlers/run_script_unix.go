//go:build !windows

package handlers

import (
	"os/exec"
	"syscall"
)

// inOwnProcessGroup starts cmd as the leader of a new process group and makes
// its context's cancel kill that whole group. exec.CommandContext alone kills
// only the direct child, so whatever a script started would outlive a timeout
// or a cancel and keep running as root, re-parented to init.
func inOwnProcessGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
}
