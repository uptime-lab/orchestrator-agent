//go:build linux

package handlers

import (
	"io"
	"log/slog"
	"os"
	"os/exec"
	"sync"
	"syscall"

	proto "agent/pkg/infrastructure/grpc/proto"

	"github.com/creack/pty"
)

// terminalOutputBuf bounds a single read from the PTY.
const terminalOutputBuf = 4096

// TerminalHandler manages interactive PTY sessions bridged from the platform.
// Each session runs a login shell in a PTY; output is streamed up via sendOutput
// and the session end is reported via sendClosed.
type TerminalHandler struct {
	logger     *slog.Logger
	sendOutput func(sessionID string, data []byte)
	sendClosed func(sessionID string, exitCode int32, errMsg string)

	mu       sync.Mutex
	sessions map[string]*ptySession
}

type ptySession struct {
	ptmx *os.File
	cmd  *exec.Cmd
	// input carries keystrokes to a per-session writer goroutine, so a PTY that
	// is not draining cannot block the agent's inbound-frame loop. See
	// startInputPump.
	input chan []byte
	// mu serialises the ENQUEUE against the CLOSE of input, and closed records
	// that the close happened. A sync.Once on the close made it
	// idempotent but synchronised nothing: the frame loop looked the session up
	// under the handler mutex, released it, and then sent on input — while the
	// shell-exit goroutine closed that very channel. A send on a closed channel
	// is a panic a `select { default: }` does not catch, and nothing above the
	// dispatch point recovered it, so a keystroke racing a shell exit took the
	// whole agent process down and the node with it.
	mu     sync.Mutex
	closed bool
}

// terminalInputQueue bounds what one session may hold before keystrokes are
// dropped. A few dozen frames is far more than an operator can type ahead, and
// the point is the BOUND, not the depth.
const terminalInputQueue = 64

// The enqueue does NOT wait. A first attempt at this gave it a 200 ms grace,
// and the test that drives a PTY nobody drains showed why that is wrong: under
// a sustained flood every frame pays the grace, so 256 frames cost 51 seconds of
// the inbound loop — a slower version of the same wedge. The queue above is the
// burst absorber; once it is full the session is genuinely not reading, and
// waiting only spreads the damage.

// startInputPump owns every write to the PTY for one session.
//
// Terminal input used to be written from the frame loop itself, and ptmx.Write
// BLOCKS once the PTY's ~4 KiB queue fills — which it does whenever the
// foreground process is not reading stdin (a `less`, a paused build, a shell
// waiting on a subprocess). Pasting more than that into the web terminal
// therefore stopped the agent's ENTIRE inbound loop: no commands, no heartbeat
// handling, and above all no TerminalClose, which is the one frame that would
// have released it. The node stayed online and heartbeating while accepting
// nothing.
func (h *TerminalHandler) startInputPump(sessionID string, s *ptySession) {
	go func() {
		for data := range s.input {
			if _, err := s.ptmx.Write(data); err != nil {
				h.logger.Debug("failed to write to pty", "session", sessionID, "error", err)
				return
			}
		}
	}()
}

// enqueue hands one frame to the writer goroutine without blocking. It reports
// whether the frame was taken; a false with closed=true means the session has
// been torn down, a false with closed=false that the queue is full.
//
// The send happens UNDER s.mu, the same lock teardown closes the channel under,
// so the two can never interleave: either the send sees an open channel, or it
// sees closed and does not send. That is the whole fix — the
// buffered, non-blocking send was never the problem; the missing lock was.
func (s *ptySession) enqueue(data []byte) (taken bool, closed bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.input == nil {
		return false, true
	}
	select {
	case s.input <- data:
		return true, false
	default:
		return false, false
	}
}

// teardown is the ONE cleanup path for a session: it marks it closed and closes
// the input channel under s.mu (ending the writer goroutine), then closes the
// PTY and kills the shell. Idempotent, so the shell exiting, an explicit
// TerminalClose and a dying stream may all reach it; it reports whether this
// call was the one that did the work.
//
// Kill after a natural exit is a no-op error (the process is already reaped)
// and is not checked. Closing ptmx on natural exit is deliberate: the read pump
// has already seen EOF, but the descriptor was previously left open until the
// next explicit close or CloseAllSessions.
func (s *ptySession) teardown() bool {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return false
	}
	s.closed = true
	// A nil channel means no pump was started for this session — a session
	// built directly rather than through open(). Closing it would panic, and
	// there is nothing to stop.
	if s.input != nil {
		close(s.input)
	}
	s.mu.Unlock()
	if s.ptmx != nil {
		_ = s.ptmx.Close()
	}
	if s.cmd != nil && s.cmd.Process != nil {
		_ = s.cmd.Process.Kill()
	}
	return true
}

func NewTerminalHandler(
	logger *slog.Logger,
	sendOutput func(sessionID string, data []byte),
	sendClosed func(sessionID string, exitCode int32, errMsg string),
) *TerminalHandler {
	return &TerminalHandler{
		logger:     logger.With("handler", "terminal"),
		sendOutput: sendOutput,
		sendClosed: sendClosed,
		sessions:   make(map[string]*ptySession),
	}
}

// Handle dispatches a terminal control frame from the platform.
func (h *TerminalHandler) Handle(msg *proto.PlatformToNode) {
	switch {
	case msg.GetTerminalOpen() != nil:
		h.open(msg.GetTerminalOpen())
	case msg.GetTerminalInput() != nil:
		h.input(msg.GetTerminalInput())
	case msg.GetTerminalClose() != nil:
		h.close(msg.GetTerminalClose().GetSessionId(), 0, "")
	}
}

// ensurePTS makes sure a usable PTY subsystem exists before we allocate a
// pseudo-terminal. Minimal netboot rootfs images (the Buildroot bootstrap)
// mount devtmpfs on /dev but never mount devpts, so /dev/ptmx is absent and
// pty.Start fails with "open /dev/ptmx: no such file or directory". Mount
// devpts and expose /dev/ptmx ourselves. This is idempotent and a no-op on
// systemd-managed systems (Ubuntu) where /dev/ptmx already exists.
func ensurePTS(logger *slog.Logger) {
	if _, err := os.Stat("/dev/ptmx"); err == nil {
		return // already usable
	}
	if err := os.MkdirAll("/dev/pts", 0o755); err != nil {
		logger.Warn("failed to create /dev/pts", "error", err)
	}
	// mount -t devpts devpts /dev/pts -o gid=5,mode=620,ptmxmode=0666
	if err := syscall.Mount("devpts", "/dev/pts", "devpts", 0, "gid=5,mode=620,ptmxmode=0666"); err != nil {
		logger.Warn("failed to mount devpts", "error", err)
	}
	// Expose the top-level /dev/ptmx as a symlink into the devpts instance
	// (accessible because we mounted with ptmxmode=0666).
	if _, err := os.Stat("/dev/ptmx"); err != nil {
		if err := os.Symlink("pts/ptmx", "/dev/ptmx"); err != nil {
			logger.Warn("failed to create /dev/ptmx symlink", "error", err)
		}
	}
}

func (h *TerminalHandler) open(open *proto.TerminalOpen) {
	sessionID := open.GetSessionId()
	// Ensure a PTY subsystem exists (netboot bootstrap has no devpts mounted).
	ensurePTS(h.logger)
	// Launch the user's login shell. Fall back to /bin/sh.
	shell := os.Getenv("SHELL")
	if shell == "" {
		shell = "/bin/sh"
	}
	cmd := exec.Command(shell, "-l")
	cmd.Env = append(os.Environ(), "TERM=xterm-256color")

	ptmx, err := pty.Start(cmd)
	if err != nil {
		h.logger.Error("failed to start pty", "session", sessionID, "error", err)
		h.sendClosed(sessionID, 1, err.Error())
		return
	}
	if open.GetRows() > 0 && open.GetCols() > 0 {
		_ = pty.Setsize(ptmx, &pty.Winsize{Rows: uint16(open.GetRows()), Cols: uint16(open.GetCols())})
	}

	session := &ptySession{ptmx: ptmx, cmd: cmd, input: make(chan []byte, terminalInputQueue)}
	h.mu.Lock()
	h.sessions[sessionID] = session
	h.mu.Unlock()
	h.startInputPump(sessionID, session)
	h.logger.Info("terminal session opened", "session", sessionID)

	// Read pump: stream PTY output until EOF/close, then report exit.
	go func() {
		buf := make([]byte, terminalOutputBuf)
		for {
			n, err := ptmx.Read(buf)
			if n > 0 {
				chunk := make([]byte, n)
				copy(chunk, buf[:n])
				h.sendOutput(sessionID, chunk)
			}
			if err != nil {
				break
			}
		}
		exitCode := int32(0)
		errMsg := ""
		if werr := cmd.Wait(); werr != nil {
			if ee, ok := werr.(*exec.ExitError); ok {
				exitCode = int32(ee.ExitCode())
			} else if err != io.EOF {
				errMsg = werr.Error()
			}
		}
		// Remove from the map FIRST, then tear down. A frame that looked the
		// session up before the removal still enqueues under the session lock,
		// which teardown takes before closing the channel — so the order here
		// is about cleanup, not about the race. Idempotent: an explicit close
		// or CloseAllSessions may already have torn this session down.
		h.removeSession(sessionID)
		// Only the teardown that actually did the work reports the close: after
		// an explicit TerminalClose the platform has already dropped the
		// session, and a second TerminalClosed from here only produced a
		// "session not owned by this node" warning per close on the backend.
		if session.teardown() {
			h.sendClosed(sessionID, exitCode, errMsg)
		}
		h.logger.Info("terminal session closed", "session", sessionID, "exit_code", exitCode)
	}()
}

func (h *TerminalHandler) input(in *proto.TerminalInput) {
	h.mu.Lock()
	s := h.sessions[in.GetSessionId()]
	h.mu.Unlock()
	if s == nil {
		return
	}
	if in.GetIsResize() {
		if in.GetRows() > 0 && in.GetCols() > 0 {
			_ = pty.Setsize(s.ptmx, &pty.Winsize{Rows: uint16(in.GetRows()), Cols: uint16(in.GetCols())})
		}
		return
	}
	// Hand it to the session's writer. A full queue means the PTY is not
	// draining, and the keystrokes are DROPPED rather than allowed to block the
	// frame loop: losing typed input is a visible annoyance, while blocking here
	// takes the whole node off the platform until something else kills the
	// session. A session torn down between the lookup above and this enqueue
	// is simply gone — never a send on its closed channel.
	taken, closed := s.enqueue(append([]byte(nil), in.GetData()...))
	if !taken && !closed {
		h.logger.Warn("dropping terminal input: the session is not reading it",
			"session", in.GetSessionId(), "bytes", len(in.GetData()))
	}
}

func (h *TerminalHandler) close(sessionID string, exitCode int32, errMsg string) {
	s := h.removeSession(sessionID)
	if s == nil {
		return
	}
	s.teardown()
	h.sendClosed(sessionID, exitCode, errMsg)
}

// CloseAllSessions ends every open session. Called when the stream to the
// platform drops.
//
// A session was removed only by an explicit TerminalClose from the platform or
// by the shell exiting, and nothing on the agent noticed a dead stream:
// handleDisconnection only nils the stream, and the reconnect path never
// reached this handler. The platform cleans its own half — and its cleanup
// DELETES the session, so the close frame that would have ended this one is
// never sent. Each leak is a root login shell, its PTY file descriptors and a
// goroutine, on a device with a few hundred megabytes of RAM; a flaky link
// accumulates one per terminal the operator ever opened.
//
// It does NOT report the closes upward. The stream they would travel on is the
// one that just died, and the platform has already settled its side; a report is
// either undeliverable or a duplicate. The count goes to the log instead, which
// is where someone diagnosing a node with no free memory will look.
func (h *TerminalHandler) CloseAllSessions(reason string) {
	h.mu.Lock()
	orphaned := h.sessions
	h.sessions = make(map[string]*ptySession)
	h.mu.Unlock()

	if len(orphaned) == 0 {
		return
	}
	for sessionID, s := range orphaned {
		// The writer goroutine goes with the session; leaving it parked on a
		// channel nobody feeds would reproduce the leak this function exists to
		// close, one goroutine at a time.
		s.teardown()
		h.logger.Debug("terminal session ended with the stream", "session_id", sessionID, "reason", reason)
	}
	h.logger.Info("closed orphaned terminal sessions", "count", len(orphaned), "reason", reason)
}

func (h *TerminalHandler) removeSession(sessionID string) *ptySession {
	h.mu.Lock()
	defer h.mu.Unlock()
	s := h.sessions[sessionID]
	delete(h.sessions, sessionID)
	return s
}
