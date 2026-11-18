//go:build linux

package handlers

import (
	"io"
	"log/slog"
	"os/exec"
	"testing"
	"time"

	"github.com/creack/pty"
)

func terminalTestHandler() *TerminalHandler {
	return NewTerminalHandler(
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		func(string, []byte) {},
		func(string, int32, string) {},
	)
}

// startTrackedSession puts a real PTY-backed process into the handler's session
// map, the way an open frame would. A real process is the point: the leak is a
// login shell and its descriptors, not a map entry.
func startTrackedSession(t *testing.T, h *TerminalHandler, sessionID string) *exec.Cmd {
	t.Helper()
	cmd := exec.Command("sleep", "300")
	ptmx, err := pty.Start(cmd)
	if err != nil {
		t.Fatalf("starting a pty session: %v", err)
	}
	h.mu.Lock()
	h.sessions[sessionID] = &ptySession{ptmx: ptmx, cmd: cmd}
	h.mu.Unlock()
	return cmd
}

// A dropped stream must end every open session. Nothing on the agent used to
// notice: a session was removed only by an explicit TerminalClose from the
// platform or by the shell exiting, and the platform's own cleanup DELETES its
// side — so the close frame that would have ended the device's half is never
// sent. Each leak is a root login shell, its PTY descriptors and a goroutine.
func TestCloseAllSessionsEndsEveryShell(t *testing.T) {
	h := terminalTestHandler()
	first := startTrackedSession(t, h, "session-a")
	second := startTrackedSession(t, h, "session-b")

	h.CloseAllSessions("test")

	h.mu.Lock()
	remaining := len(h.sessions)
	h.mu.Unlock()
	if remaining != 0 {
		t.Errorf("%d session(s) still tracked after the stream dropped", remaining)
	}

	for name, cmd := range map[string]*exec.Cmd{"session-a": first, "session-b": second} {
		done := make(chan error, 1)
		go func() { done <- cmd.Wait() }()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Errorf("%s: the shell is still running after the stream dropped", name)
		}
	}
}

// Idempotent and cheap when there is nothing to do — it runs on every
// disconnect, and most disconnects have no terminal open.
func TestCloseAllSessionsOnNoSessions(t *testing.T) {
	h := terminalTestHandler()
	h.CloseAllSessions("test")
	h.CloseAllSessions("test")
}

// A session opened AFTER the sweep is not affected by it: the map is replaced,
// not marked, so a reconnect starts clean.
func TestSessionsOpenedAfterASweepSurvive(t *testing.T) {
	h := terminalTestHandler()
	startTrackedSession(t, h, "old")
	h.CloseAllSessions("test")

	cmd := startTrackedSession(t, h, "new")
	defer func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
	}()

	h.mu.Lock()
	_, tracked := h.sessions["new"]
	h.mu.Unlock()
	if !tracked {
		t.Error("a session opened after the sweep was not tracked")
	}
}
