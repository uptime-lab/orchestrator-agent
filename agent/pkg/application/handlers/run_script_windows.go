//go:build windows

package handlers

import "os/exec"

// inOwnProcessGroup is a no-op where there are no POSIX process groups; the
// agent ships for Linux only.
func inOwnProcessGroup(*exec.Cmd) {}
