package grpc

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"
)

// The protocol has no acks: stream.Send(ConnectionInit) returns as
// soon as the frame is buffered locally, before the platform has looked at the
// token. So "connected" at that instant is a guess, and resetting the backoff
// on a guess lets a rejected agent retry at the base interval forever, which
// floods the platform's log.

func testController(t *testing.T) *ConnectionController {
	t.Helper()
	return NewConnectionController(context.Background(), slog.New(slog.NewTextHandler(io.Discard, nil)))
}

// The core regression: connecting must NOT forgive the backoff by itself.
func TestConnectDoesNotResetBackoffImmediately(t *testing.T) {
	c := testController(t)
	c.stateMu.Lock()
	c.currentAttempt = 5
	c.stateMu.Unlock()

	c.SetConnected()

	if got := c.GetCurrentAttempt(); got != 5 {
		t.Fatalf("attempts = %d after connecting, want 5 kept — a stream that just opened has not proved anything", got)
	}
}

// A connection closed on sight must leave the backoff climbing, so the retry
// interval grows toward the 30s ceiling instead of sitting at the 1s base.
func TestRejectedConnectionKeepsTheBackoffClimbing(t *testing.T) {
	c := testController(t)
	c.stateMu.Lock()
	c.currentAttempt = 3
	c.stableTimer = nil
	c.stateMu.Unlock()

	c.SetConnected()
	c.SignalDisconnection() // the platform refused the token

	if got := c.GetCurrentAttempt(); got != 3 {
		t.Fatalf("attempts = %d, want 3 — a refused connection must not be worth a reset", got)
	}
	c.stateMu.RLock()
	timer := c.stableTimer
	c.stateMu.RUnlock()
	if timer != nil {
		t.Error("the pending reset survived the disconnect; it can still fire and forgive a dead connection")
	}

	// And the wait actually grows: 1s base doubling per attempt, capped at 30s.
	if backoff := c.computeBackoff(); backoff < 8*time.Second {
		t.Errorf("backoff = %v after 3 failed attempts, want >= 8s", backoff)
	}
}

// The other half: a connection that HOLDS must eventually be forgiven, or a
// device that reconnects after a long outage would keep a 30s penalty forever.
func TestHeldConnectionForgivesTheBackoff(t *testing.T) {
	c := testController(t)
	c.stateMu.Lock()
	c.currentAttempt = 7
	c.stateMu.Unlock()
	c.SetConnected()

	// Fire the reset the way the timer would, without waiting a minute.
	c.stateMu.RLock()
	epoch := c.disconnectEpoch
	c.stateMu.RUnlock()
	c.forgiveBackoffIfStable(epoch)

	if got := c.GetCurrentAttempt(); got != 0 {
		t.Fatalf("attempts = %d, want 0 — a connection that held must reset", got)
	}
}

// The epoch guard is what makes the timer safe: a reset armed for one
// connection must not land on its successor, which may be mid-retry.
func TestStaleResetIsIgnored(t *testing.T) {
	c := testController(t)
	c.SetConnected()
	c.stateMu.RLock()
	staleEpoch := c.disconnectEpoch
	c.stateMu.RUnlock()

	c.SignalDisconnection() // bumps the epoch
	c.stateMu.Lock()
	c.currentAttempt = 4
	c.state = StateConnected // a NEW connection, still unproven
	c.stateMu.Unlock()

	c.forgiveBackoffIfStable(staleEpoch)

	if got := c.GetCurrentAttempt(); got != 4 {
		t.Fatalf("attempts = %d, want 4 — a reset from a previous connection landed on this one", got)
	}
}

// A disconnected controller must not have its backoff forgiven even at the
// right epoch: the timer can fire in the gap before the state is re-read.
func TestResetIsIgnoredWhileDisconnected(t *testing.T) {
	c := testController(t)
	c.stateMu.Lock()
	c.currentAttempt = 2
	c.state = StateDisconnected
	epoch := c.disconnectEpoch
	c.stateMu.Unlock()

	c.forgiveBackoffIfStable(epoch)

	if got := c.GetCurrentAttempt(); got != 2 {
		t.Fatalf("attempts = %d, want 2 kept while disconnected", got)
	}
}
