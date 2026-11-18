//go:build linux

package handlers

import (
	"io"
	"log/slog"
	"os"
	"os/exec"
	"testing"
	"time"

	proto "agent/pkg/infrastructure/grpc/proto"
)

// Terminal input must never block the caller.
//
// ptmx.Write blocks once the PTY's ~4 KiB queue fills, which it does whenever
// the foreground process is not reading stdin. Writing from the frame loop
// therefore stopped the agent's ENTIRE inbound loop on a large paste — no
// commands, no heartbeat handling, and no TerminalClose, which is the one frame
// that would have released it. The node stayed online and heartbeating while
// accepting nothing.
//
// The test drives a session whose PTY nobody drains and asserts that Handle
// returns anyway.
func TestTerminalInputDoesNotBlockTheFrameLoop(t *testing.T) {
	// A pipe stands in for the PTY: its buffer fills and then blocks writers,
	// which is exactly the property under test, and unlike a real PTY it needs
	// no /dev/ptmx in the test environment.
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	defer func() { _ = r.Close() }()

	h := NewTerminalHandler(slog.New(slog.NewTextHandler(io.Discard, nil)),
		func(string, []byte) {}, func(string, int32, string) {})
	session := &ptySession{ptmx: w, cmd: &exec.Cmd{}, input: make(chan []byte, terminalInputQueue)}
	h.mu.Lock()
	h.sessions["s1"] = session
	h.mu.Unlock()
	h.startInputPump("s1", session)

	// Far more than a pipe buffer, in frames, with nothing reading the far end.
	payload := make([]byte, 8192)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < terminalInputQueue*4; i++ {
			h.Handle(&proto.PlatformToNode{
				Payload: &proto.PlatformToNode_TerminalInput{
					TerminalInput: &proto.TerminalInput{SessionId: "s1", Data: payload},
				},
			})
		}
	}()

	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("the frame loop is blocked writing to a PTY nobody is reading; the node accepts nothing until something else kills the session")
	}

	// And a TerminalClose still gets through, which is the frame that actually
	// releases the situation.
	closed := make(chan struct{})
	go func() {
		defer close(closed)
		h.Handle(&proto.PlatformToNode{
			Payload: &proto.PlatformToNode_TerminalClose{
				TerminalClose: &proto.TerminalClose{SessionId: "s1"},
			},
		})
	}()
	select {
	case <-closed:
	case <-time.After(10 * time.Second):
		t.Fatal("TerminalClose could not be delivered")
	}
}
