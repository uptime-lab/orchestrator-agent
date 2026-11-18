package grpc

import (
	"context"
	"io"
	"log/slog"
	"sync/atomic"
	"testing"
	"time"
)

func TestComputeBackoffNeverOverflowsOrExceedsMax(t *testing.T) {
	c := NewConnectionController(context.Background(), nil)

	// Walk attempt across the full uint range of interest, including values well
	// past the point where 1<<attempt overflows time.Duration.
	for _, attempt := range []uint{0, 1, 5, 10, 31, 32, 33, 63, 64, 100, 1000} {
		c.stateMu.Lock()
		c.currentAttempt = attempt
		c.stateMu.Unlock()

		got := c.computeBackoff()
		if got <= 0 {
			t.Fatalf("attempt=%d: backoff must be positive, got %v (busy-loop risk)", attempt, got)
		}
		if got > c.maxInterval {
			t.Fatalf("attempt=%d: backoff %v exceeds maxInterval %v", attempt, got, c.maxInterval)
		}
	}
}

func TestComputeBackoffGrowsThenClamps(t *testing.T) {
	c := NewConnectionController(context.Background(), nil)

	c.stateMu.Lock()
	c.currentAttempt = 0
	c.stateMu.Unlock()
	if got := c.computeBackoff(); got != c.baseInterval {
		t.Fatalf("attempt=0 should return baseInterval %v, got %v", c.baseInterval, got)
	}

	// A large attempt must be pinned exactly at maxInterval.
	c.stateMu.Lock()
	c.currentAttempt = 50
	c.stateMu.Unlock()
	if got := c.computeBackoff(); got != c.maxInterval {
		t.Fatalf("large attempt should clamp to maxInterval %v, got %v", c.maxInterval, got)
	}
}

// TestReconnectRefusedWhenConnectionDiesMidAttempt reproduces the field hang:
// the platform proxy accepts the dial while the backend is still down, so the
// freshly created stream errors and signals disconnection WHILE the reconnect
// attempt is still completing. The attempt's success must be refused (epoch
// changed) and the loop must retry until an attempt survives — previously the
// stale success overwrote DISCONNECTED and the agent hung "connected" with no
// stream until a manual restart.
func TestReconnectRefusedWhenConnectionDiesMidAttempt(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	c := NewConnectionController(ctx, logger)
	c.stateMu.Lock()
	c.baseInterval = time.Millisecond
	c.maxInterval = 2 * time.Millisecond
	c.stateMu.Unlock()

	var attempts atomic.Int32
	c.SetOnReconnect(func(_ context.Context) error {
		n := attempts.Add(1)
		// Mimic PlatformClient.Connect: the dial "succeeds" and marks connected.
		c.SetConnected()
		if n == 1 {
			// The stream dies immediately (proxy up, backend down) before the
			// attempt declares success.
			c.SignalDisconnection()
		}
		return nil
	})

	// Start connected, then lose the connection.
	c.SetConnected()
	c.StartReconnectionLoop(ctx)
	c.SignalDisconnection()

	deadline := time.After(2 * time.Second)
	for {
		if attempts.Load() >= 2 && c.GetState() == StateConnected {
			break
		}
		select {
		case <-deadline:
			t.Fatalf("want >=2 attempts ending connected, got attempts=%d state=%s",
				attempts.Load(), c.GetState())
		case <-time.After(5 * time.Millisecond):
		}
	}

	if got := attempts.Load(); got < 2 {
		t.Fatalf("first attempt must be refused and retried, got %d attempts", got)
	}
}

// TestSignalWhileAlreadyDisconnectedStillNudgesLoop covers the second lost-signal
// window: a disconnect signaled while the state is already DISCONNECTED (e.g. the
// heartbeat watchdog) must still wake the reconnection loop.
func TestSignalWhileAlreadyDisconnectedStillNudgesLoop(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	c := NewConnectionController(ctx, logger)
	c.stateMu.Lock()
	c.baseInterval = time.Millisecond
	c.maxInterval = 2 * time.Millisecond
	c.stateMu.Unlock()

	var attempts atomic.Int32
	c.SetOnReconnect(func(_ context.Context) error {
		attempts.Add(1)
		c.SetConnected()
		return nil
	})

	// State is DISCONNECTED from construction; the loop is idle with no signal.
	c.StartReconnectionLoop(ctx)
	c.SignalDisconnection() // watchdog nudge while already disconnected

	deadline := time.After(2 * time.Second)
	for c.GetState() != StateConnected {
		select {
		case <-deadline:
			t.Fatalf("nudge while already disconnected did not trigger reconnection (attempts=%d)", attempts.Load())
		case <-time.After(5 * time.Millisecond):
		}
	}
}
