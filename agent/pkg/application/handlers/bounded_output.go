package handlers

import (
	"fmt"
	"strings"
)

// MaxResultOutputBytes is the ceiling on any single process-output value the
// agent puts into a command result map.
//
// The bound exists for the TRANSPORT, not for tidiness. A result travels in one
// gRPC frame on the node's single bidirectional stream, and the backend runs
// grpc-go's default 4 MiB receive limit. An oversized frame is not a failed
// command — it is a failed STREAM: the connection is torn down, the result is
// lost, the node_command sits in in_progress until the abandonment sweep, and
// the workflow execution never reaches completed_at, so it permanently consumes
// one of the per-account active-execution slots. A `run_script` block doing
// `journalctl -b` or a verbose build is ordinary usage, not abuse, and that was
// enough to make the operator's fleet blink offline with no diagnosis anywhere.
//
// 128 KiB per value keeps a two-value (stdout+stderr) result an order of
// magnitude under the receive limit while staying far larger than any output a
// human reads. It is also a memory bound: the agent runs on a Pi, and the
// previous strings.Builder grew to whatever the script emitted.
const MaxResultOutputBytes = 128 * 1024

// boundedBuffer is an io.Writer that keeps at most Max bytes while counting
// everything it was offered, so the excess can be reported rather than hidden.
//
// It keeps the HEAD, not the tail. Keeping the tail would mean buffering the
// whole stream to know where the tail is, which defeats the memory half of the
// bound; and a head-truncated value is at least a valid prefix of what the
// script produced, which matters because `stdout` is addressable from a
// playbook as {{blocks.<id>.outputs.stdout}}.
type boundedBuffer struct {
	Max     int
	buf     []byte
	written int64
}

// Write never reports a short write or an error. The script is writing to its
// own stdout; failing that write because the agent stopped keeping the bytes
// would turn a verbose script into a broken one (`head` closing a pipe is
// exactly how SIGPIPE surprises get made).
func (b *boundedBuffer) Write(p []byte) (int, error) {
	// Captured before p is resliced below: returning len(p) after truncating it
	// is a short write, which is precisely the failure this method promises not
	// to produce.
	offered := len(p)
	b.written += int64(offered)
	if room := b.Max - len(b.buf); room > 0 {
		if len(p) > room {
			p = p[:room]
		}
		b.buf = append(b.buf, p...)
	}
	return offered, nil
}

// Truncated reports whether anything was dropped.
func (b *boundedBuffer) Truncated() bool { return b.written > int64(len(b.buf)) }

// String returns what was kept, with an explicit marker when bytes were
// dropped. The marker is deliberately part of the value: a silently truncated
// output that a later playbook step compares against is a wrong answer
// delivered as a right one.
func (b *boundedBuffer) String() string {
	// The UTF-8 scrub is a transport requirement, not cosmetics: the value
	// rides a proto3 string in CommandStatusUpdate, proto3 refuses to marshal
	// invalid UTF-8, and grpc-go tears down the whole stream on a marshal
	// error. A script cat-ing binary (or the byte-cap splitting a rune) must
	// cost bytes, never the connection.
	kept := strings.ToValidUTF8(string(b.buf), "�")
	if !b.Truncated() {
		return kept
	}
	return kept + fmt.Sprintf(
		"\n[truncated by orchestrator-agent: kept %d of %d bytes]",
		len(b.buf), b.written)
}

// newBoundedBuffer returns a buffer bounded at MaxResultOutputBytes.
func newBoundedBuffer() *boundedBuffer {
	return &boundedBuffer{Max: MaxResultOutputBytes}
}
