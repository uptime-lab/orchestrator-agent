package grpc

import (
	"context"
	"io"
	"log/slog"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	proto "agent/pkg/infrastructure/grpc/proto"
)

// refusingStream answers every Recv with the same error and counts the calls.
// A dead stream does exactly this: the refusal is immediate, so nothing paces
// the loop except the loop itself.
type refusingStream struct {
	proto.NodeCommunication_EstablishStreamClient
	err   error
	calls int64
}

func (s *refusingStream) Recv() (*proto.PlatformToNode, error) {
	atomic.AddInt64(&s.calls, 1)
	return nil, s.err
}

func (s *refusingStream) Send(*proto.NodeToPlatform) error { return nil }

func listenForCommandsAgainst(t *testing.T, streamErr error, window time.Duration) int64 {
	t.Helper()
	stream := &refusingStream{err: streamErr}
	c := &PlatformClient{
		logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		stream:     stream,
		connected:  true,
		shutdownCh: make(chan struct{}),
	}

	ctx, cancel := context.WithTimeout(context.Background(), window)
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		c.ListenForCommands(ctx, func(*proto.Command) error { return nil })
	}()
	select {
	case <-done:
	case <-time.After(window + 2*time.Second):
		t.Fatal("ListenForCommands did not return after its context expired")
	}
	return atomic.LoadInt64(&stream.calls)
}

// A NON-recoverable refusal must not spin.
//
// signalDisconnectionIfNeeded deliberately does nothing for Unauthenticated and
// PermissionDenied — the platform is not going to change its mind — but the
// generic branch also left `connected` true, so the outer loop immediately
// spawned another Recv on the same dead stream and got the same error back with
// nothing in between. A node whose row was deleted or whose account was purged
// takes exactly that path while it is still powered: a core at 100% and
// continuous journald writes to SD/eMMC, until journald's own rate limiting
// starts suppressing the agent's real messages.
func TestANonRecoverableRefusalDoesNotSpin(t *testing.T) {
	for _, code := range []codes.Code{codes.Unauthenticated, codes.PermissionDenied} {
		t.Run(code.String(), func(t *testing.T) {
			calls := listenForCommandsAgainst(t, status.Error(code, "refused"), 300*time.Millisecond)
			// One Recv is the refusal itself; the loop then idles at 100 ms, so
			// a handful more would still be sane. Hundreds is the bug — the
			// pre-fix measurement was ~123,000 in this window.
			if calls > 20 {
				t.Errorf("Recv was called %d times in 300ms; the listen loop is spinning on a dead stream", calls)
			}
		})
	}
}

// The recoverable path is unchanged: it signals a disconnection and stops,
// leaving recovery to the reconnect controller rather than to this loop.
func TestARecoverableErrorStillOnlyReadsOnce(t *testing.T) {
	calls := listenForCommandsAgainst(t, io.EOF, 300*time.Millisecond)
	if calls > 20 {
		t.Errorf("Recv was called %d times in 300ms after a recoverable error", calls)
	}
}
