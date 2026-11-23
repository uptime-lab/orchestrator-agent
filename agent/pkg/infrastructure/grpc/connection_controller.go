package grpc

import (
	"context"
	"log/slog"
	"sync"
	"time"
)

// ConnectionState represents the current state of the gRPC connection
type ConnectionState int

const (
	// StateHalted indicates intentional disconnection (shutdown requested)
	StateHalted ConnectionState = iota
	// StateDisconnected indicates no active connection, reconnection may be in progress
	StateDisconnected
	// StateConnected indicates active gRPC stream with heartbeats flowing
	StateConnected
)

func (s ConnectionState) String() string {
	switch s {
	case StateHalted:
		return "HALTED"
	case StateDisconnected:
		return "DISCONNECTED"
	case StateConnected:
		return "CONNECTED"
	default:
		return "UNKNOWN"
	}
}

const (
	// DefaultBaseInterval is the initial retry interval
	DefaultBaseInterval = 1 * time.Second
	// DefaultMaxInterval is the maximum retry interval (30 seconds as per requirements)
	DefaultMaxInterval = 30 * time.Second
	// stabilityPeriod is how long a new connection must SURVIVE before its
	// backoff counter is forgiven.
	//
	// The agent cannot tell a good connection from a rejected one at the moment
	// it opens: the protocol has no acks, so `stream.Send(ConnectionInit)`
	// returns as soon as the frame is buffered locally — before the platform has
	// looked at the token. Resetting the backoff there would make an agent whose
	// credential the platform refuses retry at the BASE interval forever: dial,
	// declare success, get closed, reset to attempt 0, dial again ~1s later. That
	// floods the platform's log, which is the real damage — the log stops being
	// usable as evidence for the next failure.
	//
	// 60s is chosen against the failure it must not break: a legitimate agent
	// reconnecting after an outage holds its stream indefinitely, so it always
	// clears this. A rejected one is closed within milliseconds and never does,
	// so it climbs to the 30s ceiling and stays there.
	stabilityPeriod = 60 * time.Second
)

// ConnectionController manages connection state and reconnection logic with exponential backoff
type ConnectionController struct {
	state       ConnectionState
	targetState ConnectionState
	stateMu     sync.RWMutex

	// Backoff configuration
	baseInterval   time.Duration
	maxInterval    time.Duration
	currentAttempt uint

	// disconnectEpoch increments on every SignalDisconnection. A reconnect
	// attempt captures it before dialing and refuses to declare success if it
	// changed underneath — the freshly created stream may already be dead
	// (e.g. the proxy accepted the dial while the backend was still down).
	disconnectEpoch uint64
	// attemptActive is true while attemptReconnection is running, so watchdogs
	// can tell "loop is already retrying" apart from "loop is idle and a
	// disconnect signal was lost".
	attemptActive bool
	// stableTimer forgives the backoff once a connection has held for
	// stabilityPeriod. Armed on connect, stopped on disconnect — so a stream
	// the platform closes on sight never reaches the reset.
	stableTimer *time.Timer

	// Context management
	parentCtx       context.Context
	reconnectCtx    context.Context
	reconnectCancel context.CancelFunc

	// Callbacks
	onStateChange   func(old, new ConnectionState)
	onReconnect     func(ctx context.Context) error
	onDisconnected  func()

	// Channel to signal disconnection
	disconnectCh chan struct{}

	logger *slog.Logger
}

// NewConnectionController creates a new connection controller
func NewConnectionController(parentCtx context.Context, logger *slog.Logger) *ConnectionController {
	return &ConnectionController{
		state:          StateDisconnected,
		targetState:    StateDisconnected,
		baseInterval:   DefaultBaseInterval,
		maxInterval:    DefaultMaxInterval,
		currentAttempt: 0,
		parentCtx:      parentCtx,
		disconnectCh:   make(chan struct{}, 1),
		logger:         logger,
	}
}

// SetOnStateChange sets the callback for state changes
func (c *ConnectionController) SetOnStateChange(callback func(old, new ConnectionState)) {
	c.onStateChange = callback
}

// SetOnReconnect sets the callback for reconnection attempts
func (c *ConnectionController) SetOnReconnect(callback func(ctx context.Context) error) {
	c.onReconnect = callback
}

// SetOnDisconnected sets the callback when disconnection is detected
func (c *ConnectionController) SetOnDisconnected(callback func()) {
	c.onDisconnected = callback
}

// GetState returns the current connection state
func (c *ConnectionController) GetState() ConnectionState {
	c.stateMu.RLock()
	defer c.stateMu.RUnlock()
	return c.state
}

// IsConnected returns true if currently connected
func (c *ConnectionController) IsConnected() bool {
	return c.GetState() == StateConnected
}

// armStabilityReset schedules the backoff reset for a connection that is still
// only PROVISIONALLY good. Caller must hold stateMu.
//
// The counter is not cleared here on purpose. Clearing it at connect time is
// what made an auth-rejected agent retry at the base interval forever:
// the platform's refusal arrives after the local Send has already
// returned, so every "success" was worth one more reset. Surviving
// stabilityPeriod is the closest thing to an ack this protocol has.
func (c *ConnectionController) armStabilityReset() {
	if c.stableTimer != nil {
		c.stableTimer.Stop()
	}
	epoch := c.disconnectEpoch
	c.stableTimer = time.AfterFunc(stabilityPeriod, func() {
		c.forgiveBackoffIfStable(epoch)
	})
}

// forgiveBackoffIfStable clears the attempt counter if the connection armed at
// epoch is still the live one. Split out from the timer so the decision is
// testable without waiting a minute of wall clock.
func (c *ConnectionController) forgiveBackoffIfStable(epoch uint64) {
	c.stateMu.Lock()
	defer c.stateMu.Unlock()
	// Both guards matter: the epoch proves this is still the SAME connection,
	// and the state proves it is still up. A timer that fired for a connection
	// which has since died must not forgive its successor's backoff — that
	// successor may be the very retry loop this fix exists to slow down.
	if c.disconnectEpoch != epoch || c.state != StateConnected {
		return
	}
	if c.currentAttempt == 0 {
		return
	}
	c.logger.Info("Connection held; resetting reconnect backoff",
		"held_for", stabilityPeriod.String(), "attempts_forgiven", c.currentAttempt)
	c.currentAttempt = 0
}

// stopStabilityReset cancels a pending backoff reset. Caller must hold stateMu.
func (c *ConnectionController) stopStabilityReset() {
	if c.stableTimer != nil {
		c.stableTimer.Stop()
		c.stableTimer = nil
	}
}

// SetConnected transitions to connected state and arms the backoff reset
func (c *ConnectionController) SetConnected() {
	c.stateMu.Lock()
	defer c.stateMu.Unlock()

	oldState := c.state
	if oldState == StateConnected {
		return
	}

	c.state = StateConnected
	c.armStabilityReset()

	c.logger.Info("Connection state changed",
		"old_state", oldState.String(),
		"new_state", c.state.String())

	if c.onStateChange != nil {
		go c.onStateChange(oldState, c.state)
	}
}

// SignalDisconnection signals that the connection was lost and reconnection should begin
func (c *ConnectionController) SignalDisconnection() {
	c.stateMu.Lock()

	if c.state == StateHalted || c.targetState == StateHalted {
		c.stateMu.Unlock()
		return
	}

	// Bump the epoch unconditionally: an in-flight reconnect attempt must see
	// that its connection died even if the state was already DISCONNECTED at
	// that instant (the stream can fail before the attempt marks itself done).
	c.disconnectEpoch++

	alreadyDisconnected := c.state == StateDisconnected
	oldState := c.state
	c.state = StateDisconnected
	// A connection that died owes nothing: drop its pending forgiveness so a
	// stream the platform closed on sight cannot clear the backoff a moment
	// later. The epoch bump above already invalidates it; stopping the timer
	// also stops it firing at all.
	c.stopStabilityReset()
	c.stateMu.Unlock()

	if !alreadyDisconnected {
		c.logger.Info("Connection lost, transitioning to disconnected",
			"old_state", oldState.String(),
			"new_state", StateDisconnected.String())

		if c.onStateChange != nil {
			go c.onStateChange(oldState, StateDisconnected)
		}

		if c.onDisconnected != nil {
			c.onDisconnected()
		}
	}

	// Always nudge the reconnection loop. A redundant signal is consumed
	// harmlessly by the "already connected" check; a lost one strands the
	// agent offline until a manual restart.
	select {
	case c.disconnectCh <- struct{}{}:
	default:
		// Channel already has a signal
	}
}

// currentEpoch returns the disconnect epoch for correlating a reconnect
// attempt with disconnections that happen while it runs.
func (c *ConnectionController) currentEpoch() uint64 {
	c.stateMu.RLock()
	defer c.stateMu.RUnlock()
	return c.disconnectEpoch
}

// setConnectedIfEpoch transitions to connected only if no disconnection was
// signaled since epoch was captured. Returns false when the connection died
// while the attempt was still completing — the caller must keep retrying
// instead of declaring success over a dead stream.
func (c *ConnectionController) setConnectedIfEpoch(epoch uint64) bool {
	c.stateMu.Lock()
	if c.disconnectEpoch != epoch {
		c.stateMu.Unlock()
		return false
	}
	oldState := c.state
	if oldState == StateConnected {
		c.stateMu.Unlock()
		return true
	}
	c.state = StateConnected
	c.armStabilityReset()
	c.stateMu.Unlock()

	c.logger.Info("Connection state changed",
		"old_state", oldState.String(),
		"new_state", StateConnected.String())

	if c.onStateChange != nil {
		go c.onStateChange(oldState, StateConnected)
	}
	return true
}

// Halt stops all reconnection attempts and transitions to halted state
func (c *ConnectionController) Halt() {
	c.stateMu.Lock()
	defer c.stateMu.Unlock()

	oldState := c.state
	c.state = StateHalted
	c.targetState = StateHalted

	// Cancel any ongoing reconnection attempts
	if c.reconnectCancel != nil {
		c.reconnectCancel()
		c.reconnectCancel = nil
	}

	c.logger.Info("Connection controller halted",
		"old_state", oldState.String())

	if c.onStateChange != nil && oldState != StateHalted {
		go c.onStateChange(oldState, StateHalted)
	}
}

// StartReconnectionLoop starts the reconnection loop that monitors for disconnections
// and attempts to reconnect with exponential backoff
func (c *ConnectionController) StartReconnectionLoop(ctx context.Context) {
	c.stateMu.Lock()
	c.targetState = StateConnected
	c.reconnectCtx, c.reconnectCancel = context.WithCancel(ctx)
	reconnectCtx := c.reconnectCtx
	c.stateMu.Unlock()

	go func() {
		for {
			select {
			case <-reconnectCtx.Done():
				c.logger.Debug("Reconnection loop stopped due to context cancellation")
				return
			case <-c.parentCtx.Done():
				c.logger.Debug("Reconnection loop stopped due to parent context cancellation")
				return
			case <-c.disconnectCh:
				c.attemptReconnection(reconnectCtx)
			}
		}
	}()
}

// ReconnectInProgress reports whether the reconnection loop is actively
// retrying. Used by watchdogs to avoid nudging (and epoch-invalidating) a
// loop that is already doing its job.
func (c *ConnectionController) ReconnectInProgress() bool {
	c.stateMu.RLock()
	defer c.stateMu.RUnlock()
	return c.attemptActive
}

// attemptReconnection attempts to reconnect with exponential backoff
func (c *ConnectionController) attemptReconnection(ctx context.Context) {
	c.stateMu.Lock()
	c.attemptActive = true
	c.stateMu.Unlock()
	defer func() {
		c.stateMu.Lock()
		c.attemptActive = false
		c.stateMu.Unlock()
	}()

	for {
		// Check if we should stop
		select {
		case <-ctx.Done():
			return
		case <-c.parentCtx.Done():
			return
		default:
		}

		// Check state
		c.stateMu.RLock()
		state := c.state
		targetState := c.targetState
		c.stateMu.RUnlock()

		if state == StateHalted || targetState == StateHalted {
			c.logger.Debug("Reconnection aborted due to halt state")
			return
		}

		if state == StateConnected {
			c.logger.Debug("Already connected, stopping reconnection attempts")
			return
		}

		// Calculate backoff
		backoff := c.computeBackoff()
		c.stateMu.Lock()
		c.currentAttempt++
		attempt := c.currentAttempt
		c.stateMu.Unlock()

		c.logger.Info("Attempting reconnection",
			"attempt", attempt,
			"backoff", backoff.String())

		// Wait for backoff interval
		select {
		case <-ctx.Done():
			return
		case <-c.parentCtx.Done():
			return
		case <-time.After(backoff):
		}

		// Check state again after waiting
		c.stateMu.RLock()
		state = c.state
		targetState = c.targetState
		c.stateMu.RUnlock()

		if state == StateHalted || targetState == StateHalted {
			return
		}

		// Attempt reconnection. Capture the epoch first: if the connection the
		// attempt creates dies before we get here (proxy up, backend down →
		// instant stream error), SignalDisconnection bumps the epoch and the
		// success below is refused instead of overwriting the DISCONNECTED
		// state — the exact race that used to strand agents "connected" with
		// no stream until a manual restart.
		if c.onReconnect != nil {
			epoch := c.currentEpoch()
			err := c.onReconnect(ctx)
			if err != nil {
				c.logger.Warn("Reconnection attempt failed",
					"attempt", attempt,
					"error", err,
					"next_backoff", c.computeBackoff().String())
				continue
			}

			if !c.setConnectedIfEpoch(epoch) {
				c.logger.Warn("Connection died while the reconnect attempt was completing; retrying",
					"attempt", attempt)
				continue
			}
			c.logger.Info("Reconnection successful", "attempt", attempt)
			return
		}
	}
}

// computeBackoff calculates the next backoff interval using exponential backoff
func (c *ConnectionController) computeBackoff() time.Duration {
	c.stateMu.RLock()
	attempt := c.currentAttempt
	c.stateMu.RUnlock()

	if attempt == 0 {
		return c.baseInterval
	}

	// Guard against shift overflow: once attempt is large, 1<<attempt overflows
	// time.Duration (int64) to 0 or a negative value, which would bypass the
	// maxInterval clamp below and turn a long outage into a tight reconnect loop.
	// Past this point the backoff is already pinned at maxInterval anyway.
	const maxShift = 32
	if attempt > maxShift {
		return c.maxInterval
	}

	// Calculate exponential backoff: baseInterval * 2^attempt
	backoff := c.baseInterval * time.Duration(1<<attempt)

	if backoff <= 0 || backoff > c.maxInterval {
		return c.maxInterval
	}

	return backoff
}

// GetCurrentAttempt returns the current reconnection attempt number
func (c *ConnectionController) GetCurrentAttempt() uint {
	c.stateMu.RLock()
	defer c.stateMu.RUnlock()
	return c.currentAttempt
}

// NOTE: there is deliberately no ResetAttempts. One existed, with zero callers
// and a doc comment reading "called on successful connection" — which is
// exactly the instruction that made an auth-rejected agent retry forever at the
// base interval. A connection is not successful because it opened; it is
// successful because it HELD (see armStabilityReset). Leaving a one-line
// bypass next to the fix is how the fix gets undone.
