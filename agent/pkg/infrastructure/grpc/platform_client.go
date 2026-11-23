package grpc

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"agent/pkg/domain/node"
	"agent/pkg/domain/redact"
	"agent/pkg/domain/refusal"
	proto "agent/pkg/infrastructure/grpc/proto"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/status"
)

// processInstanceID names this agent PROCESS for the platform: generated once
// per process start, sent in every ConnectionInit this process makes. Same id
// across a reconnect means the process survived the stream break and is still
// executing whatever it acknowledged; a different id means a restart, so that
// work is gone. It must never be persisted — surviving a restart is exactly
// what it must not do.
var processInstanceID = uuid.New().String()

// maxGRPCMessageBytes is the explicit per-frame ceiling for the platform
// stream, kept in step with the platform's own limit of the same name. A frame
// larger than the peer accepts kills the stream rather than the command, so the
// two sides agreeing is what makes an oversized payload a local, recoverable
// error instead of a dropped node.
const maxGRPCMessageBytes = 8 * 1024 * 1024

// PlatformClient implements the platform client port using gRPC
type PlatformClient struct {
	grpcEndpoint string
	logger       *slog.Logger
	version      string
	conn         *grpc.ClientConn
	client       proto.NodeCommunicationClient
	stream       proto.NodeCommunication_EstablishStreamClient
	mu           sync.RWMutex
	connected    bool

	// sendMu serializes EVERY write to the gRPC stream (Send and CloseSend).
	// grpc-go forbids concurrent SendMsg on one stream and does not detect it, and
	// the agent writes from as many goroutines as it has activities — heartbeat,
	// command-status reports, the metrics ticker, terminal frames, file-changed
	// events, the connection handshake. Two of them colliding corrupts the client
	// stream or panics, which drops the node offline and loses the in-flight
	// command result. This is the agent-side counterpart of the platform's own
	// per-connection stream writer. Kept separate from mu, which is an
	// RWMutex guarding connection STATE — a write must not be blocked by, or block,
	// a state read.
	sendMu sync.Mutex

	// Reconnection support
	controller    *ConnectionController
	messageQueue  *MessageQueue
	connectionReq *node.ConnectionRequest // Stored for reconnection
	platformURL   string                  // Stored for reconnection
	// identityGeneration counts every replacement of connectionReq (an
	// explicit Connect, an identity handover). A reconnect carries the
	// generation it copied its request under and re-checks it under c.mu
	// right before presenting, so a snapshot taken before a handover is
	// discarded in favour of the current identity rather than published
	// over it. Guarded by mu.
	identityGeneration uint64
	reconnectMu        sync.Mutex // Protects reconnection state
	isReconnecting     bool
	shutdownCh         chan struct{} // Signals shutdown to stop reconnection

	// heartbeatInterval paces StartHeartbeat and its reconnect watchdog;
	// zero means defaultHeartbeatInterval. A field only so a test can run
	// the watchdog in milliseconds.
	heartbeatInterval time.Duration

	// deviceCapHold answers how long to wait after a device-cap refusal
	// before asking again; nil means jitteredDeviceCapHold. capHoldUntil is
	// the end of the current hold (guarded by mu) and capRefusals counts
	// consecutive refusals, so only the first is a WARN.
	deviceCapHold func() time.Duration
	capHoldUntil  time.Time
	capRefusals   int

	// terminalHandler receives interactive-terminal control frames from the
	// platform (open/input/close). Set via SetTerminalHandler.
	terminalHandler func(*proto.PlatformToNode)

	// terminalDisconnect ends every open terminal session when the stream dies.
	// Set via SetTerminalDisconnectHandler; nil means the sessions leak, which
	// is what happened before this existed.
	terminalDisconnect func(reason string)

	// identityHandler receives the node's own credentials after a master-token
	// handshake, so the agent can stop using the shared enrolment token. Set via
	// SetIdentityHandler; nil means the assignment is ignored, which is the
	// correct behaviour for a node that already runs in node-specific mode.
	identityHandler func(nodeID, accountID, uniqueToken string)

	// reconnectHooks are test seams in reconnect(): afterSnapshot runs once
	// the stored identity has been copied out, beforeConnect sees the request
	// about to be presented. Nil in production.
	reconnectHooks struct {
		afterSnapshot func()
		beforeConnect func(req node.ConnectionRequest)
	}
}

// sendOn serializes one write to the stream. Callers already hold their own
// snapshot of c.stream (taken under c.mu); this guarantees no two of them call
// SendMsg concurrently, which is the property grpc-go requires and does not
// enforce. It deliberately serializes across streams too — the cost is nil (a
// write is brief) and it keeps the rule impossible to get wrong.
func (c *PlatformClient) sendOn(stream proto.NodeCommunication_EstablishStreamClient, msg *proto.NodeToPlatform) error {
	c.sendMu.Lock()
	defer c.sendMu.Unlock()
	return stream.Send(msg)
}

// closeSend serializes CloseSend against any in-flight Send — grpc-go forbids
// that race as much as it forbids two concurrent Sends. Callers hold c.mu (so no
// new sender can snapshot the stream), and any sender already past its snapshot
// is holding sendMu, which this waits for.
func (c *PlatformClient) closeSend(stream proto.NodeCommunication_EstablishStreamClient) {
	c.sendMu.Lock()
	defer c.sendMu.Unlock()
	stream.CloseSend()
}

// SetTerminalHandler registers the callback for terminal control frames.
func (c *PlatformClient) SetTerminalHandler(h func(*proto.PlatformToNode)) {
	c.mu.Lock()
	c.terminalHandler = h
	c.mu.Unlock()
}

// SetTerminalDisconnectHandler registers what to do with open terminal sessions
// when the stream dies.
//
// Separate from the frame handler because it is triggered by the absence of
// frames, not by one: a session lives until the platform sends TerminalClose or
// the shell exits, and a dropped stream produces neither. The platform's own
// cleanup deletes its side, so the close frame that would end the device's half
// is never sent — leaving a root login shell, its PTY descriptors and a
// goroutine behind for every terminal the operator had open.
func (c *PlatformClient) SetTerminalDisconnectHandler(h func(reason string)) {
	c.mu.Lock()
	c.terminalDisconnect = h
	c.mu.Unlock()
}

// AdoptReconnectIdentity replaces the credentials future RECONNECTS will present.
//
// The live stream is deliberately left alone — it is already authenticated, and
// swapping credentials underneath it buys nothing. What this fixes is the NEXT
// connect: `connectionReq` is captured on the first Connect and replayed verbatim
// by reconnect(), so without this a master-token node keeps re-presenting the
// SHARED enrolment token for the rest of the process's life. When that token
// expires the node is refused on every retry, and the reconnect loop retries
// forever without ever returning — so nothing restarts the process to pick up the
// identity that was written to disk minutes after adoption. The device goes
// offline permanently and cannot be recovered remotely, which is the exact
// failure the identity handover exists to prevent.
//
// Safe to call from the identity handler: that runs with c.mu released.
func (c *PlatformClient) AdoptReconnectIdentity(nodeID, accountID uuid.UUID, uniqueToken string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.connectionReq == nil {
		return // never connected; the first Connect will carry the new identity
	}
	updated := *c.connectionReq
	updated.NodeID = nodeID
	updated.AccountID = accountID
	updated.UniqueToken = uniqueToken
	c.connectionReq = &updated
	// Advance the generation so a reconnect that copied the request BEFORE
	// this call discards its copy when it comes to publish.
	c.identityGeneration++
	c.logger.Info("reconnect identity adopted; the shared enrolment token will not be presented again",
		"node_id", nodeID)
}

// SetIdentityHandler registers the callback that persists an identity handed
// over by the platform.
func (c *PlatformClient) SetIdentityHandler(h func(nodeID, accountID, uniqueToken string)) {
	c.mu.Lock()
	c.identityHandler = h
	c.mu.Unlock()
}

// transportCredentials selects gRPC transport security based on the platform URL:
// TLS (system roots) for https platforms (public/SaaS), plaintext otherwise
// (trusted self-hosted LAN). This keeps HTTP and gRPC transport security aligned
// without a separate adoption flag.
func transportCredentials(platformURL string, logger *slog.Logger) grpc.DialOption {
	if strings.HasPrefix(strings.ToLower(platformURL), "https") {
		return grpc.WithTransportCredentials(credentials.NewClientTLSFromCert(nil, ""))
	}
	if logger != nil {
		logger.Warn("connecting to gRPC WITHOUT TLS (plaintext); platform URL is not https")
	}
	return grpc.WithTransportCredentials(insecure.NewCredentials())
}

// NewPlatformClient creates a new gRPC-based platform client
func NewPlatformClient(grpcEndpoint string, logger *slog.Logger, version string) *PlatformClient {
	return &PlatformClient{
		grpcEndpoint: grpcEndpoint,
		logger:       logger,
		version:      version,
		connected:    false,
		messageQueue: NewMessageQueue(DefaultQueueSize, logger),
		shutdownCh:   make(chan struct{}),
	}
}

// SetConnectionController sets the connection controller for reconnection management
func (c *PlatformClient) SetConnectionController(controller *ConnectionController) {
	c.controller = controller

	// Set up callbacks
	controller.SetOnReconnect(func(ctx context.Context) error {
		return c.reconnect(ctx)
	})

	controller.SetOnDisconnected(func() {
		c.handleDisconnection()
	})
}

// GetConnectionController returns the connection controller
func (c *PlatformClient) GetConnectionController() *ConnectionController {
	return c.controller
}

// GetMessageQueue returns the message queue
func (c *PlatformClient) GetMessageQueue() *MessageQueue {
	return c.messageQueue
}

// Connect establishes a gRPC connection and bidirectional stream with an
// identity the CALLER vouches for (the adoption file at start-up). It is
// authoritative: it replaces the stored request and advances the identity
// generation, so a reconnect snapshot older than this call is stale.
func (c *PlatformClient) Connect(ctx context.Context, platformURL string, req node.ConnectionRequest) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Store connection details for reconnection
	c.platformURL = platformURL
	reqCopy := req
	c.connectionReq = &reqCopy
	c.identityGeneration++

	return c.connectLocked(ctx, platformURL, req)
}

// connectLocked dials, opens the stream and sends the handshake for req.
// Caller holds c.mu. It does not touch the stored identity: which request is
// presented is decided by the caller, under the same lock hold.
func (c *PlatformClient) connectLocked(ctx context.Context, platformURL string, req node.ConnectionRequest) error {
	// Connect to gRPC server (TLS for https/SaaS platforms, plaintext for LAN).
	// Client keepalive detects silently dead transports (e.g. the platform
	// container restarted without a FIN reaching us); the server enforcement
	// policy permits pings every >=10s, so 60s is well within limits.
	conn, err := grpc.NewClient(c.grpcEndpoint,
		transportCredentials(platformURL, c.logger),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:                60 * time.Second,
			Timeout:             20 * time.Second,
			PermitWithoutStream: true,
		}),
		// Match the platform's explicit per-frame ceiling in both directions
		// rather than inheriting grpc-go's asymmetric defaults (4 MiB receive,
		// effectively unlimited send). The send side is the one that bit: an
		// unbounded run_script result was handed to the transport, the platform
		// refused the frame, and the STREAM died — taking the result with it and
		// leaving the workflow run pinned. The command result itself is now
		// bounded far below this (see handlers.MaxResultOutputBytes); this is
		// the backstop for anything else that grows.
		grpc.WithDefaultCallOptions(
			grpc.MaxCallRecvMsgSize(maxGRPCMessageBytes),
			grpc.MaxCallSendMsgSize(maxGRPCMessageBytes),
		),
	)
	if err != nil {
		return fmt.Errorf("failed to connect to gRPC server: %w", err)
	}

	c.conn = conn
	c.client = proto.NewNodeCommunicationClient(conn)

	// Establish bidirectional stream
	stream, err := c.client.EstablishStream(ctx)
	if err != nil {
		conn.Close()
		return fmt.Errorf("failed to establish stream: %w", err)
	}

	c.stream = stream
	c.connected = true

	// Send initial connection message
	connectionMsg := &proto.NodeToPlatform{
		NodeId:      req.NodeID.String(),
		AccountId:   req.AccountID.String(),
		UniqueToken: req.UniqueToken,
		Payload: &proto.NodeToPlatform_Connection{
			Connection: &proto.ConnectionInit{
				Fingerprint: &proto.HardwareFingerprint{
					MacAddress:     req.Fingerprint.MacAddress,
					HardwareSerial: req.Fingerprint.HardwareSerial,
				},
				AgentVersion:    c.version,
				AgentKind:       req.AgentKind,
				AgentInstanceId: processInstanceID,
				LedSources:      req.LEDSources,
			},
		},
	}

	if err := c.sendOn(stream, connectionMsg); err != nil {
		c.cleanup()
		return fmt.Errorf("failed to send connection message: %w", err)
	}

	// Mark as connected in controller if available
	if c.controller != nil {
		c.controller.SetConnected()
	}

	// Deliver anything queued while we were offline. The watchdog breaker
	// queues its disarm report BEFORE the first connect, and reconnect() is the
	// only other flusher — without this the report waits for a reconnect that
	// may never come. Deferred to a goroutine because Connect holds c.mu and
	// the send path locks it again.
	go c.flushMessageQueue()

	c.logger.Info("gRPC connection established", "endpoint", c.grpcEndpoint)
	return nil
}

// reconnect attempts to re-establish the connection using stored credentials
func (c *PlatformClient) reconnect(ctx context.Context) error {
	if err := c.waitOutDeviceCapHold(ctx); err != nil {
		return err
	}
	c.reconnectMu.Lock()
	if c.isReconnecting {
		c.reconnectMu.Unlock()
		return fmt.Errorf("reconnection already in progress")
	}
	c.isReconnecting = true
	c.reconnectMu.Unlock()

	defer func() {
		c.reconnectMu.Lock()
		c.isReconnecting = false
		c.reconnectMu.Unlock()
	}()

	// Snapshot the stored identity UNDER c.mu, with the generation it belongs
	// to, and tear the old connection down in the same hold.
	// Before this the request was read without the mutex and handed to
	// Connect, which republished whatever it was given: a reconnect that
	// copied the shared enrolment token and published after the identity
	// handover put that token back for the rest of the process's life.
	c.mu.Lock()
	if c.connectionReq == nil {
		c.mu.Unlock()
		return fmt.Errorf("no connection request stored for reconnection")
	}
	req := *c.connectionReq
	platformURL := c.platformURL
	generation := c.identityGeneration
	c.cleanup()
	c.mu.Unlock()

	c.logger.Info("Attempting to reconnect", "endpoint", c.grpcEndpoint)

	if h := c.reconnectHooks.afterSnapshot; h != nil {
		h()
	}

	// Attempt new connection. The snapshot is re-validated under the lock
	// right before it is presented: locking only the read would not close
	// the race, since an identity adopted between the copy and the publish
	// is newer than the copy. A stale snapshot is dropped for the current
	// identity — never the other way round.
	c.mu.Lock()
	if c.identityGeneration != generation {
		req = *c.connectionReq
		platformURL = c.platformURL
		c.logger.Info("reconnect snapshot superseded by a newer identity; presenting the current one",
			"node_id", req.NodeID)
	}
	if h := c.reconnectHooks.beforeConnect; h != nil {
		h(req)
	}
	err := c.connectLocked(ctx, platformURL, req)
	c.mu.Unlock()
	if err != nil {
		return fmt.Errorf("reconnection failed: %w", err)
	}

	// Flush queued messages
	c.flushMessageQueue()

	return nil
}

// handleDisconnection cleans up resources when disconnection is detected
func (c *PlatformClient) handleDisconnection() {
	c.mu.Lock()
	c.connected = false
	// Don't fully cleanup - we want to keep the stored connection details
	if c.stream != nil {
		c.closeSend(c.stream)
		c.stream = nil
	}
	onTerminalLoss := c.terminalDisconnect
	c.mu.Unlock()

	// Outside the lock: the handler kills processes and closes descriptors, and
	// holding the connection-state mutex across that would block every sender
	// and every state read for as long as it takes.
	if onTerminalLoss != nil {
		onTerminalLoss("the stream to the platform was lost")
	}
}

// flushMessageQueue sends all queued messages after reconnection
func (c *PlatformClient) flushMessageQueue() {
	if c.messageQueue == nil {
		return
	}

	messages := c.messageQueue.Drain()
	if len(messages) == 0 {
		return
	}

	c.logger.Info("Flushing queued messages", "count", len(messages))

	for _, msg := range messages {
		var err error
		switch msg.Type {
		case MessageTypeStatusUpdate:
			if msg.StatusUpdate != nil {
				p := msg.StatusUpdate
				err = c.SendStatusUpdate(p.NodeID, p.AccountID, p.UniqueToken, p.Status, p.Message)
			}
		case MessageTypeCommandStatus:
			if msg.CommandStatus != nil {
				p := msg.CommandStatus
				// WithResult, not the plain form: replaying through the
				// result-less call is what dropped the outputs in the first place.
				err = c.SendCommandStatusWithResult(p.NodeID, p.AccountID, p.UniqueToken, p.CommandID, p.Status, p.Progress, p.Details, p.Result)
			}
		case MessageTypeSystemInfo:
			if msg.SystemInfo != nil {
				p := msg.SystemInfo
				err = c.SendSystemInfo(p.NodeID, p.AccountID, p.UniqueToken, p.SystemInfoUpdate)
			}
		case MessageTypeFileChanged:
			if msg.FileChanged != nil {
				p := msg.FileChanged
				err = c.SendFileChangedEvent(p.NodeID, p.AccountID, p.UniqueToken, p.Path, p.Content, p.Hash, p.Version, p.Status, p.ErrorMessage)
			}
		}

		if err != nil {
			c.logger.Warn("Failed to send queued message",
				"type", msg.Type.String(),
				"error", err)
		}
	}
}

// isRecoverableError determines if an error should trigger reconnection
func (c *PlatformClient) isRecoverableError(err error) bool {
	if err == nil {
		return false
	}

	// EOF means stream was closed
	if errors.Is(err, io.EOF) {
		return true
	}

	// Context cancellation is not recoverable (intentional shutdown)
	if errors.Is(err, context.Canceled) {
		return false
	}

	// Check gRPC status codes
	st, ok := status.FromError(err)
	if !ok {
		// Not a gRPC error, assume recoverable
		return true
	}

	switch st.Code() {
	case codes.Unavailable:
		// Server unavailable - recoverable
		return true
	case codes.ResourceExhausted:
		// The platform answers two different things with this code: a
		// transient bound (too many streams, the pre-auth gate), which a
		// backoff clears, and the instance's device cap, which no amount of
		// retrying changes until an operator frees a slot or applies an
		// entitlement. The cap refusal carries a fixed message so the two can
		// be told apart here. It is not an immediate reconnect: the receive
		// loop holds for the long jittered retry (holdAfterDeviceCapRefusal)
		// with the process still running, and the heartbeat watchdog stands
		// down for that hold. The refusal at the device's ACCOUNT limit is
		// the same kind of answer with its own fixed message.
		return !isDeviceLimitMessage(st.Message())
	case codes.Aborted:
		// Operation aborted - recoverable
		return true
	case codes.Canceled:
		// Intentional cancellation - not recoverable
		return false
	case codes.Unauthenticated:
		// Auth failure - not recoverable without new credentials
		return false
	case codes.PermissionDenied:
		// Access denied - not recoverable
		return false
	default:
		// Unknown errors - try to recover
		return true
	}
}

// deviceCapRefusalMessage is the fixed status message the platform sends with
// ResourceExhausted when the install's admitted-device cap is reached; it must
// byte-match the platform's entitlement.GRPCRefusalMessage.
const deviceCapRefusalMessage = "device cap reached"

// accountLimitRefusalMessage is the fixed status message the platform sends
// with ResourceExhausted when the device's ACCOUNT holds as many devices as
// its own limit allows; it must byte-match the platform's
// entitlement.GRPCAccountLimitMessage. It is held for like the device cap:
// only an operator or the account's owner frees a slot.
const accountLimitRefusalMessage = "account device limit reached"

// isDeviceLimitMessage reports whether a ResourceExhausted message is one of
// the platform's two admission-limit refusals.
func isDeviceLimitMessage(msg string) bool {
	return msg == deviceCapRefusalMessage || msg == accountLimitRefusalMessage
}

const (
	// deviceCapHoldBase is how long a device refused at the cap waits before
	// asking again. The cap moves only when an operator removes a device or
	// applies an entitlement, so retrying every few seconds buys nothing and
	// costs the platform a parked handshake each time; fifteen minutes keeps
	// a device that WILL be admitted from waiting long once a slot is free.
	deviceCapHoldBase = 15 * time.Minute
	// deviceCapHoldJitter spreads a fleet refused together (a master-SD
	// batch) so it does not come back together.
	deviceCapHoldJitter = 3 * time.Minute
)

// jitteredDeviceCapHold is deviceCapHoldBase ± deviceCapHoldJitter.
func jitteredDeviceCapHold() time.Duration {
	return deviceCapHoldBase - deviceCapHoldJitter + time.Duration(rand.Int64N(int64(2*deviceCapHoldJitter)+1))
}

// holdAfterDeviceCapRefusal is what the agent does when the platform refuses
// it at the install's device cap: the process stays up (an exit would only
// hand the same refusal to the service manager's restart loop), the stream
// stays down, and ONE reconnect is scheduled after a long jittered hold. The
// heartbeat watchdog stands down for the hold (inDeviceCapHold). The first
// refusal of a streak is one WARN line; the repeats are INFO.
//
// accountLimit says the refusal was at the device's account limit rather
// than the install's cap; only the WARN's wording differs.
func (c *PlatformClient) holdAfterDeviceCapRefusal(ctx context.Context, accountLimit bool) {
	hold := c.deviceCapHold
	if hold == nil {
		hold = jitteredDeviceCapHold
	}
	d := hold()
	c.mu.Lock()
	c.capHoldUntil = time.Now().Add(d)
	c.capRefusals++
	refusals := c.capRefusals
	c.mu.Unlock()

	if refusals == 1 {
		reason := "the install is at its device cap"
		if accountLimit {
			reason = "its account is at its device limit"
		}
		c.logger.Warn("the platform refused this device: "+reason+". "+
			"The agent keeps running and asks again periodically; it is admitted once a device "+
			"is removed or the limit is raised",
			"retry_in", d.Round(time.Second).String())
	} else {
		c.logger.Info("still refused at the device cap; asking again later",
			"retry_in", d.Round(time.Second).String(), "refusals", refusals)
	}

	go func() {
		select {
		case <-time.After(d):
			// A reconnect already waiting out the hold (one started by a send
			// that failed on the refused stream) dials by itself; a signal
			// now would bump the epoch under it and cost a second dial.
			if c.controller != nil && !c.controller.ReconnectInProgress() {
				c.controller.SignalDisconnection()
			}
		case <-ctx.Done():
		case <-c.shutdownCh:
		}
	}()
}

// waitOutDeviceCapHold blocks a reconnect until the current device-cap hold
// ends. Every path that can start a reconnect — a send failing on the
// refused stream, the heartbeat watchdog, a stray signal — goes through
// reconnect, so this is the one place the hold is enforced on the dial.
func (c *PlatformClient) waitOutDeviceCapHold(ctx context.Context) error {
	for {
		c.mu.RLock()
		until := c.capHoldUntil
		c.mu.RUnlock()
		wait := time.Until(until)
		if wait <= 0 {
			return nil
		}
		select {
		case <-time.After(wait):
		case <-ctx.Done():
			return ctx.Err()
		case <-c.shutdownCh:
			return fmt.Errorf("shutting down")
		}
	}
}

// inDeviceCapHold reports whether a device-cap hold is running.
func (c *PlatformClient) inDeviceCapHold() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return time.Now().Before(c.capHoldUntil)
}

// isDeviceCapRefusal reports whether err is the platform's refusal at its
// device cap or at the device's account limit.
func isDeviceCapRefusal(err error) bool {
	st, ok := status.FromError(err)
	return ok && st.Code() == codes.ResourceExhausted && isDeviceLimitMessage(st.Message())
}

// isAccountLimitRefusal reports whether err is the platform's refusal at the
// device's account limit.
func isAccountLimitRefusal(err error) bool {
	st, ok := status.FromError(err)
	return ok && st.Code() == codes.ResourceExhausted && st.Message() == accountLimitRefusalMessage
}

// signalDisconnectionIfNeeded checks error and signals controller if reconnection is needed
func (c *PlatformClient) signalDisconnectionIfNeeded(err error) {
	if c.controller == nil {
		return
	}

	if c.isRecoverableError(err) {
		c.controller.SignalDisconnection()
	}
}

// defaultHeartbeatInterval is the heartbeat cadence the platform expects.
const defaultHeartbeatInterval = 30 * time.Second

// StartHeartbeat starts sending heartbeats at regular intervals
func (c *PlatformClient) StartHeartbeat(ctx context.Context, nodeID, accountID, uniqueToken string) {
	interval := c.heartbeatInterval
	if interval <= 0 {
		interval = defaultHeartbeatInterval
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	sequenceNumber := uint64(0)
	consecutiveSkips := 0

	for {
		select {
		case <-ctx.Done():
			c.logger.Info("Heartbeat stopped due to context cancellation")
			return
		case <-c.shutdownCh:
			c.logger.Info("Heartbeat stopped due to shutdown signal")
			return
		case <-ticker.C:
			// Check if we're connected before sending
			c.mu.RLock()
			connected := c.connected
			c.mu.RUnlock()

			if !connected {
				consecutiveSkips++
				c.logger.Debug("Skipping heartbeat, not connected")
				// Watchdog: still disconnected after two intervals AND the
				// reconnection loop is idle — a disconnect signal was lost and
				// nothing else will ever re-signal (send paths never run while
				// disconnected). Otherwise an agent can stay offline until a
				// manual restart. A retrying loop is left
				// alone so the nudge cannot invalidate its attempts.
				// A device held after a device-cap refusal is disconnected on
				// purpose, and the hold's own timer asks again.
				if consecutiveSkips >= 2 && c.controller != nil && !c.controller.ReconnectInProgress() && !c.inDeviceCapHold() {
					c.logger.Warn("Heartbeats skipped while disconnected and no reconnection in progress; nudging reconnection",
						"consecutive_skips", consecutiveSkips)
					c.controller.SignalDisconnection()
				}
				continue
			}
			consecutiveSkips = 0

			if err := c.sendHeartbeat(nodeID, accountID, uniqueToken, sequenceNumber); err != nil {
				// Check if it's a context cancellation (native or gRPC wrapped)
				if errors.Is(err, context.Canceled) {
					c.logger.Info("Heartbeat stopped", "reason", "context canceled")
					return
				}
				if st, ok := status.FromError(err); ok && st.Code() == codes.Canceled {
					// Check if parent context is done (actual shutdown) vs stream canceled
					select {
					case <-ctx.Done():
						c.logger.Info("Heartbeat stopped", "reason", "gRPC context canceled (shutdown)")
						return
					default:
						// Stream canceled but agent running - signal disconnect and continue
						// The heartbeat loop will skip while not connected
						c.logger.Warn("Heartbeat stream canceled, signaling disconnection")
						c.mu.Lock()
						c.connected = false
						c.mu.Unlock()
						if c.controller != nil {
							c.controller.SignalDisconnection()
						}
						continue
					}
				}

				c.logger.Error("failed to send heartbeat", "error", err)

				// Signal disconnection for reconnection
				c.signalDisconnectionIfNeeded(err)

				// Don't return - continue loop to allow reconnection to succeed
				// The next iteration will skip if not connected
			} else {
				sequenceNumber++
			}
		}
	}
}

// ListenForCommands listens for commands from the platform
func (c *PlatformClient) ListenForCommands(ctx context.Context, commandHandler func(*proto.Command) error) {
	for {
		// Check context before starting receive loop
		select {
		case <-ctx.Done():
			c.logger.Info("Command listening stopped due to context cancellation")
			return
		case <-c.shutdownCh:
			c.logger.Info("Command listening stopped due to shutdown signal")
			return
		default:
		}

		// Check if we're connected
		c.mu.RLock()
		connected := c.connected
		stream := c.stream
		c.mu.RUnlock()

		if !connected || stream == nil {
			// Wait a bit before checking again
			select {
			case <-ctx.Done():
				return
			case <-c.shutdownCh:
				return
			case <-time.After(100 * time.Millisecond):
				continue
			}
		}

		// Use a channel to receive messages in a non-blocking way
		recvChan := make(chan struct {
			msg *proto.PlatformToNode
			err error
		}, 1)

		// Start a goroutine to handle Recv() which blocks
		recvDone := make(chan struct{})
		go func() {
			defer close(recvDone)
			for {
				c.mu.RLock()
				currentStream := c.stream
				c.mu.RUnlock()

				if currentStream == nil {
					recvChan <- struct {
						msg *proto.PlatformToNode
						err error
					}{nil, fmt.Errorf("stream is nil")}
					return
				}

				msg, err := currentStream.Recv()
				select {
				case recvChan <- struct {
					msg *proto.PlatformToNode
					err error
				}{msg, err}:
					if err != nil {
						return
					}
				case <-ctx.Done():
					return
				}
			}
		}()

		// Process messages until error or context cancellation
		continueOuterLoop := false
		for !continueOuterLoop {
			select {
			case <-ctx.Done():
				c.logger.Info("Command listening stopped due to context cancellation")
				select {
				case <-recvDone:
				case <-time.After(1 * time.Second):
					c.logger.Warn("Recv goroutine did not exit in time")
				}
				return
			case <-c.shutdownCh:
				c.logger.Info("Command listening stopped due to shutdown signal")
				select {
				case <-recvDone:
				case <-time.After(1 * time.Second):
				}
				return
			case result := <-recvChan:
				if result.err != nil {
					// Check if it's a context cancellation (normal shutdown)
					// Need to check both native context.Canceled and gRPC codes.Canceled
					if errors.Is(result.err, context.Canceled) {
						c.logger.Info("Command listening stopped", "reason", "context canceled")
						return
					}
					if st, ok := status.FromError(result.err); ok && st.Code() == codes.Canceled {
						// Check if parent context is done (actual shutdown) vs stream canceled (reconnect needed)
						select {
						case <-ctx.Done():
							c.logger.Info("Command listening stopped", "reason", "gRPC context canceled (shutdown)")
							return
						default:
							// Stream was canceled but agent should keep running - trigger reconnection
							c.logger.Warn("Stream canceled, triggering reconnection")
							c.mu.Lock()
							c.connected = false
							c.mu.Unlock()
							if c.controller != nil {
								c.controller.SignalDisconnection()
							}
							// Wait for recv goroutine to finish
							select {
							case <-recvDone:
							case <-time.After(1 * time.Second):
							}
							continueOuterLoop = true
							continue
						}
					}

					capRefused := isDeviceCapRefusal(result.err)
					if !capRefused {
						c.logger.Error("failed to receive message", "error", result.err)
					}

					// Mark the connection down BEFORE deciding whether to reconnect.
					//
					// Without this the loop spins at full speed on a NON-recoverable
					// error: signalDisconnectionIfNeeded does nothing for
					// Unauthenticated or PermissionDenied — that refusal is deliberate,
					// the platform is not going to change its mind — so `connected`
					// stayed true, the outer loop immediately spawned another Recv on
					// the same dead stream, and it returned the same error instantly.
					// Measured against a real gRPC server: Unauthenticated produced
					// 122,962 "failed to receive message" lines in 300 ms, one goroutine
					// each, where a recoverable io.EOF produced exactly one.
					//
					// A node whose row was deleted or whose account was purged takes
					// exactly that path while it is still powered, so the cost is a core
					// at 100% and continuous journald writes to SD/eMMC — and journald's
					// own rate limiting then suppresses the agent's real messages,
					// destroying the log of the node being diagnosed.
					//
					// It costs the recoverable path nothing (handleDisconnection clears
					// the same flag on its way through). What it buys is the outer
					// loop's `!connected` branch, which idles at 100 ms instead of
					// re-reading a corpse. The Canceled branch above has always done
					// this; the omission here was positional, not a decision.
					c.mu.Lock()
					c.connected = false
					c.mu.Unlock()

					// Signal disconnection for reconnection attempt — except at
					// the device cap, which only an operator lifts: hold for
					// the long retry instead.
					if capRefused {
						c.holdAfterDeviceCapRefusal(ctx, isAccountLimitRefusal(result.err))
					} else {
						c.signalDisconnectionIfNeeded(result.err)
					}

					// Wait for recv goroutine to finish
					select {
					case <-recvDone:
					case <-time.After(1 * time.Second):
					}

					// Break inner loop to restart with reconnection check
					continueOuterLoop = true
					continue
				}

				if result.msg != nil {
					// A frame from the platform means this device is admitted:
					// a later refusal is news again, worth its WARN.
					c.mu.Lock()
					c.capRefusals = 0
					c.mu.Unlock()
					if assignment := result.msg.GetIdentityAssignment(); assignment != nil {
						// The platform is telling a master-token-adopted node
						// who it is, so it can stop depending on the shared
						// enrolment token. Handled inline like a terminal frame
						// rather than as a command: it carries no command_id,
						// needs no status report, and must not go through the
						// single command goroutine, which a long-running
						// handler can occupy for minutes.
						c.mu.RLock()
						h := c.identityHandler
						c.mu.RUnlock()
						if h != nil {
							c.guarded("identity", "", func() {
								h(assignment.NodeId, assignment.AccountId, assignment.UniqueToken)
							})
						}
					} else if command := result.msg.GetCommand(); command != nil {
						c.logger.Info("command received", "command_id", command.CommandId)
						c.guarded("command", command.CommandId, func() {
							if err := commandHandler(command); err != nil {
								c.logCommandHandlerError(command.CommandId, err)
							}
						})
					} else if isTerminalFrame(result.msg) {
						c.mu.RLock()
						h := c.terminalHandler
						c.mu.RUnlock()
						if h != nil {
							c.guarded("terminal", "", func() { h(result.msg) })
						}
					}
				}
			}
		}
	}
}

// logCommandHandlerError logs the error a command handler returned: at WARN
// when the handler refused the command (its input, its type or a policy
// turned it away, and the refusal was reported), at ERROR when the command ran
// and failed.
//
// The logging boundary redacts too: a handler that returns a raw *url.Error
// (an operator-authored URL with a credential in it) must not depend on every
// call site remembering to.
func (c *PlatformClient) logCommandHandlerError(commandID string, err error) {
	if refusal.Is(err) {
		c.logger.Warn("command refused", "command_id", commandID, "error", redact.Error(err))
		return
	}
	c.logger.Error("command handler failed", "command_id", commandID, "error", redact.Error(err))
}

// guarded runs one inbound-frame handler and contains a panic in it.
//
// Handlers run INLINE on the receive loop, so before this a panic in any
// command or terminal handler unwound the whole process: the node dropped off
// the platform, every in-flight command died with it, and systemd restarted an
// agent that had just lost its state (one such panic was a
// keystroke racing a shell exit). A contained panic is logged with its stack.
// This is the BACKSTOP: a command's own entry point (CommandHandler.HandleCommand)
// recovers first and reports the command FAILED, because only that layer holds
// the node identity a status report needs — and because the platform's
// abandonment sweep excludes the device-exclusive slugs, so a command left
// in_progress here could otherwise hold the node in maintenance until a
// manual restart. Only the terminal and identity frames, which carry no
// command, are settled by this recover alone.
func (c *PlatformClient) guarded(kind, commandID string, fn func()) {
	defer func() {
		if r := recover(); r != nil {
			c.logger.Error("inbound handler panicked; the agent keeps running",
				"handler", kind, "command_id", commandID, "panic", fmt.Sprint(r),
				"stack", string(debug.Stack()))
		}
	}()
	fn()
}

// SendStatusUpdate sends a status update to the platform
func (c *PlatformClient) SendStatusUpdate(nodeID, accountID, uniqueToken, status, message string) error {
	c.mu.RLock()
	connected := c.connected
	stream := c.stream
	c.mu.RUnlock()

	if !connected || stream == nil {
		// Queue message for later delivery
		if c.messageQueue != nil {
			c.messageQueue.EnqueueStatusUpdate(nodeID, accountID, uniqueToken, status, message)
			c.logger.Debug("Status update queued (not connected)", "status", status)
			return nil
		}
		return fmt.Errorf("not connected to platform")
	}

	statusMsg := &proto.NodeToPlatform{
		NodeId:      nodeID,
		AccountId:   accountID,
		UniqueToken: uniqueToken,
		Payload: &proto.NodeToPlatform_StatusUpdate{
			StatusUpdate: &proto.StatusUpdate{
				Status:    status,
				Message:   message,
				Timestamp: time.Now().Unix(),
			},
		},
	}

	if err := c.sendOn(stream, statusMsg); err != nil {
		// Queue on send failure and signal disconnection
		if c.messageQueue != nil {
			c.messageQueue.EnqueueStatusUpdate(nodeID, accountID, uniqueToken, status, message)
		}
		c.signalDisconnectionIfNeeded(err)
		return fmt.Errorf("failed to send status update: %w", err)
	}

	c.logger.Info("status update sent", "status", status, "message", message)
	return nil
}

// SendCommandStatus sends a command status update to the platform
func (c *PlatformClient) SendCommandStatus(nodeID, accountID, uniqueToken, commandID, status string, progress int32, details string) error {
	return c.SendCommandStatusWithResult(nodeID, accountID, uniqueToken, commandID, status, progress, details, nil)
}

// SendCommandStatusWithResult sends a command status update carrying structured
// outputs, on the live stream or through the offline queue.
//
// The queue used to drop the result map, which the previous version of this
// comment described as intentional ("delivered only on the live stream"). It was
// silent data loss: the terminal status still arrived, as `success` with no
// outputs, so a read_file -> write_file playbook wrote an empty value and stayed
// green. A brief stream blip during any run_script/read_file block
// reproduced it.
func (c *PlatformClient) SendCommandStatusWithResult(nodeID, accountID, uniqueToken, commandID, status string, progress int32, details string, result map[string]string) error {
	c.mu.RLock()
	connected := c.connected
	stream := c.stream
	c.mu.RUnlock()

	if !connected || stream == nil {
		// Queue message for later delivery
		if c.messageQueue != nil {
			c.messageQueue.EnqueueCommandStatusWithResult(nodeID, accountID, uniqueToken, commandID, status, progress, details, result)
			c.logger.Debug("Command status queued (not connected)", "command_id", commandID, "status", status, "result_keys", len(result))
			return nil
		}
		return fmt.Errorf("not connected to platform")
	}

	commandStatusMsg := &proto.NodeToPlatform{
		NodeId:      nodeID,
		AccountId:   accountID,
		UniqueToken: uniqueToken,
		Payload: &proto.NodeToPlatform_CommandStatusUpdate{
			CommandStatusUpdate: &proto.CommandStatusUpdate{
				CommandId: commandID,
				Status:    status,
				Progress:  progress,
				Details:   details,
				Timestamp: time.Now().Unix(),
				Result:    result,
			},
		},
	}

	if err := c.sendOn(stream, commandStatusMsg); err != nil {
		// Queue on send failure and signal disconnection
		if c.messageQueue != nil {
			c.messageQueue.EnqueueCommandStatusWithResult(nodeID, accountID, uniqueToken, commandID, status, progress, details, result)
		}
		c.signalDisconnectionIfNeeded(err)
		return fmt.Errorf("failed to send command status update: %w", err)
	}

	c.logger.Info("command status update sent", "command_id", commandID, "status", status, "progress", progress)
	return nil
}

// SendSystemInfo sends system information (storage, network, hardware, OS) to the platform
func (c *PlatformClient) SendSystemInfo(nodeID, accountID, uniqueToken string, systemInfoUpdate *proto.SystemInfoUpdate) error {
	c.mu.RLock()
	connected := c.connected
	stream := c.stream
	c.mu.RUnlock()

	if !connected || stream == nil {
		// Queue message for later delivery
		if c.messageQueue != nil {
			c.messageQueue.EnqueueSystemInfo(nodeID, accountID, uniqueToken, systemInfoUpdate)
			c.logger.Debug("System info queued (not connected)")
			return nil
		}
		return fmt.Errorf("not connected to platform")
	}

	systemInfoMsg := &proto.NodeToPlatform{
		NodeId:      nodeID,
		AccountId:   accountID,
		UniqueToken: uniqueToken,
		Payload: &proto.NodeToPlatform_SystemInfoUpdate{
			SystemInfoUpdate: systemInfoUpdate,
		},
	}

	if err := c.sendOn(stream, systemInfoMsg); err != nil {
		// Queue on send failure and signal disconnection
		if c.messageQueue != nil {
			c.messageQueue.EnqueueSystemInfo(nodeID, accountID, uniqueToken, systemInfoUpdate)
		}
		c.signalDisconnectionIfNeeded(err)
		return fmt.Errorf("failed to send system info update: %w", err)
	}

	deviceCount := 0
	if systemInfoUpdate.StorageDevices != nil {
		deviceCount = len(systemInfoUpdate.StorageDevices)
	}

	bootOrderCount := 0
	bootOrder := []string{}
	currentBootDevice := ""
	if systemInfoUpdate.Hardware != nil && systemInfoUpdate.Hardware.Boot != nil {
		if systemInfoUpdate.Hardware.Boot.BootDevicesOrder != nil {
			bootOrderCount = len(systemInfoUpdate.Hardware.Boot.BootDevicesOrder)
			bootOrder = systemInfoUpdate.Hardware.Boot.BootDevicesOrder
		}
		currentBootDevice = systemInfoUpdate.Hardware.Boot.CurrentBootDevice
	}

	c.logger.Info("system info update sent",
		"device_count", deviceCount,
		"has_network", systemInfoUpdate.Network != nil,
		"has_hardware", systemInfoUpdate.Hardware != nil,
		"has_os", systemInfoUpdate.Os != nil,
		"current_boot_device", currentBootDevice,
		"boot_order_count", bootOrderCount,
		"boot_order", bootOrder)
	return nil
}

// SendMetrics sends a live resource-utilization sample. Unlike system info, a
// stale metrics sample is worthless, so when not connected it is dropped rather
// than queued.
func (c *PlatformClient) SendMetrics(nodeID, accountID, uniqueToken string, metrics *proto.MetricsUpdate) error {
	c.mu.RLock()
	connected := c.connected
	stream := c.stream
	c.mu.RUnlock()

	if !connected || stream == nil {
		// Drop silently — the next tick will carry fresh values.
		return nil
	}

	msg := &proto.NodeToPlatform{
		NodeId:      nodeID,
		AccountId:   accountID,
		UniqueToken: uniqueToken,
		Payload:     &proto.NodeToPlatform_MetricsUpdate{MetricsUpdate: metrics},
	}
	if err := c.sendOn(stream, msg); err != nil {
		c.signalDisconnectionIfNeeded(err)
		return fmt.Errorf("failed to send metrics update: %w", err)
	}
	return nil
}

// SendNodeEvent sends a spontaneous device event (physical button press).
// Dropped when disconnected — replaying a press after a reconnect would claim
// a human touched the machine at a moment nobody did.
func (c *PlatformClient) SendNodeEvent(nodeID, accountID, uniqueToken, eventType, pressKind string) error {
	c.mu.RLock()
	connected := c.connected
	stream := c.stream
	c.mu.RUnlock()

	if !connected || stream == nil {
		return nil
	}

	msg := &proto.NodeToPlatform{
		NodeId:      nodeID,
		AccountId:   accountID,
		UniqueToken: uniqueToken,
		Payload: &proto.NodeToPlatform_NodeEvent{NodeEvent: &proto.NodeEvent{
			EventType: eventType,
			PressKind: pressKind,
			Ts:        time.Now().Unix(),
		}},
	}
	if err := c.sendOn(stream, msg); err != nil {
		c.signalDisconnectionIfNeeded(err)
		return fmt.Errorf("failed to send node event: %w", err)
	}
	return nil
}

// isTerminalFrame reports whether a platform message is a terminal control frame.
func isTerminalFrame(msg *proto.PlatformToNode) bool {
	return msg.GetTerminalOpen() != nil ||
		msg.GetTerminalInput() != nil ||
		msg.GetTerminalClose() != nil
}

// SendTerminalOutput streams PTY output bytes for a session up to the platform.
// Dropped (not queued) when disconnected — terminal data is useless if replayed.
func (c *PlatformClient) SendTerminalOutput(nodeID, accountID, uniqueToken, sessionID string, data []byte) error {
	return c.sendTerminalFrame(&proto.NodeToPlatform{
		NodeId:      nodeID,
		AccountId:   accountID,
		UniqueToken: uniqueToken,
		Payload: &proto.NodeToPlatform_TerminalOutput{
			TerminalOutput: &proto.TerminalOutput{SessionId: sessionID, Data: data},
		},
	})
}

// SendTerminalClosed notifies the platform that a session ended.
func (c *PlatformClient) SendTerminalClosed(nodeID, accountID, uniqueToken, sessionID string, exitCode int32, errMsg string) error {
	return c.sendTerminalFrame(&proto.NodeToPlatform{
		NodeId:      nodeID,
		AccountId:   accountID,
		UniqueToken: uniqueToken,
		Payload: &proto.NodeToPlatform_TerminalClosed{
			TerminalClosed: &proto.TerminalClosed{SessionId: sessionID, ExitCode: exitCode, Error: errMsg},
		},
	})
}

func (c *PlatformClient) sendTerminalFrame(msg *proto.NodeToPlatform) error {
	c.mu.RLock()
	connected := c.connected
	stream := c.stream
	c.mu.RUnlock()
	if !connected || stream == nil {
		return nil
	}
	if err := c.sendOn(stream, msg); err != nil {
		c.signalDisconnectionIfNeeded(err)
		return fmt.Errorf("failed to send terminal frame: %w", err)
	}
	return nil
}

// SendFileChangedEvent sends a file changed event to the platform
func (c *PlatformClient) SendFileChangedEvent(nodeID, accountID, uniqueToken, path, content, hash string, version int32, fileStatus, errorMessage string) error {
	c.mu.RLock()
	connected := c.connected
	stream := c.stream
	c.mu.RUnlock()

	if !connected || stream == nil {
		// Queue message for later delivery
		if c.messageQueue != nil {
			c.messageQueue.EnqueueFileChanged(nodeID, accountID, uniqueToken, path, content, hash, version, fileStatus, errorMessage)
			c.logger.Debug("File changed event queued (not connected)", "path", path)
			return nil
		}
		return fmt.Errorf("not connected to platform")
	}

	fileChangedEvent := &proto.FileChangedEvent{
		Path:         path,
		Content:      content,
		Hash:         hash,
		Version:      version,
		Status:       fileStatus,
		Timestamp:    time.Now().Unix(),
		ErrorMessage: errorMessage,
	}

	fileMsg := &proto.NodeToPlatform{
		NodeId:      nodeID,
		AccountId:   accountID,
		UniqueToken: uniqueToken,
		Payload: &proto.NodeToPlatform_FileChangedEvent{
			FileChangedEvent: fileChangedEvent,
		},
	}

	if err := c.sendOn(stream, fileMsg); err != nil {
		// Queue on send failure and signal disconnection
		if c.messageQueue != nil {
			c.messageQueue.EnqueueFileChanged(nodeID, accountID, uniqueToken, path, content, hash, version, fileStatus, errorMessage)
		}
		c.signalDisconnectionIfNeeded(err)
		return fmt.Errorf("failed to send file changed event: %w", err)
	}

	c.logger.Info("file changed event sent",
		"path", path,
		"version", version,
		"status", fileStatus)
	return nil
}

// Close closes the gRPC connection and stops reconnection attempts
func (c *PlatformClient) Close() error {
	// Signal shutdown to stop reconnection attempts
	if c.controller != nil {
		c.controller.Halt()
	}

	// Signal shutdown to heartbeat and command listener
	close(c.shutdownCh)

	c.mu.Lock()
	defer c.mu.Unlock()

	return c.cleanup()
}

// sendHeartbeat sends a heartbeat message
func (c *PlatformClient) sendHeartbeat(nodeID, accountID, uniqueToken string, sequenceNumber uint64) error {
	c.mu.RLock()
	connected := c.connected
	stream := c.stream
	c.mu.RUnlock()

	if !connected || stream == nil {
		return fmt.Errorf("not connected to platform")
	}

	heartbeatMsg := &proto.NodeToPlatform{
		NodeId:      nodeID,
		AccountId:   accountID,
		UniqueToken: uniqueToken,
		Payload: &proto.NodeToPlatform_Heartbeat{
			Heartbeat: &proto.Heartbeat{
				SequenceNumber: sequenceNumber,
				Timestamp:      time.Now().Unix(),
			},
		},
	}

	return c.sendOn(stream, heartbeatMsg)
}

// cleanup closes connections and resets state
func (c *PlatformClient) cleanup() error {
	c.connected = false

	if c.stream != nil {
		c.closeSend(c.stream)
		c.stream = nil
	}

	if c.conn != nil {
		err := c.conn.Close()
		c.conn = nil
		return err
	}

	return nil
}
