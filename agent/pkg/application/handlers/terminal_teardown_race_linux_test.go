//go:build linux

package handlers

import (
	"io"
	"log/slog"
	"os/exec"
	"runtime"
	"sync"
	"testing"

	proto "agent/pkg/infrastructure/grpc/proto"
)

// Terminal input arriving as the shell exits used to panic the
// agent: the frame loop looked the session up under the handler mutex, let go
// of it, and sent on the session's input channel — while the shell-exit
// goroutine removed the session and CLOSED that channel. A send on a closed
// channel panics regardless of the `select { default: }` around it, nothing
// above the dispatch point recovered, and the process went down with every
// in-flight command on the node.
//
// The test interleaves exactly those two paths, many times, and requires no
// panic. It is run under -race as part of the Linux suite; the panic itself
// does not need the detector, only enough iterations to land in the window.
func TestTerminalInputRacingShellExitDoesNotPanic(t *testing.T) {
	h := NewTerminalHandler(slog.New(slog.NewTextHandler(io.Discard, nil)),
		func(string, []byte) {}, func(string, int32, string) {})
	frame := &proto.PlatformToNode{
		Payload: &proto.PlatformToNode_TerminalInput{
			TerminalInput: &proto.TerminalInput{SessionId: "s", Data: []byte("x")},
		},
	}

	const rounds = 5000
	for i := 0; i < rounds; i++ {
		// No PTY: the enqueue never touches ptmx, and a nil one keeps the test
		// free of /dev/ptmx. The channel is what the race is about.
		session := &ptySession{cmd: &exec.Cmd{}, input: make(chan []byte, terminalInputQueue)}
		h.mu.Lock()
		h.sessions["s"] = session
		h.mu.Unlock()

		var wg sync.WaitGroup
		wg.Add(2)
		// The frame loop: look up, then enqueue.
		go func() {
			defer wg.Done()
			h.Handle(frame)
		}()
		// The shell-exit goroutine: remove from the map, then tear down.
		go func() {
			defer wg.Done()
			runtime.Gosched()
			h.removeSession("s")
			session.teardown()
		}()
		wg.Wait()
	}
}

// After teardown an enqueue reports the session closed and delivers nothing;
// a second teardown is a no-op. Both are what let three callers (shell exit,
// explicit close, dying stream) share one cleanup path.
func TestTerminalSessionTeardownIsIdempotentAndClosesEnqueue(t *testing.T) {
	session := &ptySession{cmd: &exec.Cmd{}, input: make(chan []byte, 1)}
	if taken, closed := session.enqueue([]byte("a")); !taken || closed {
		t.Fatalf("enqueue before teardown: taken=%v closed=%v", taken, closed)
	}
	if !session.teardown() {
		t.Fatal("first teardown reported nothing to do")
	}
	if session.teardown() {
		t.Fatal("second teardown claimed to do the work again")
	}
	if taken, closed := session.enqueue([]byte("b")); taken || !closed {
		t.Fatalf("enqueue after teardown: taken=%v closed=%v", taken, closed)
	}
	// The channel is closed, so the writer goroutine's range ends; the frame
	// that was accepted before teardown is still there for it to drain.
	if got, ok := <-session.input; !ok || string(got) != "a" {
		t.Fatalf("queued frame lost: %q ok=%v", got, ok)
	}
	if _, ok := <-session.input; ok {
		t.Fatal("input channel was not closed by teardown")
	}
}
