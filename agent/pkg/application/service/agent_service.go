package service

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"agent/pkg/application/handlers"
	ports "agent/pkg/application/ports/out"
	"agent/pkg/domain/node"
	grpcclient "agent/pkg/infrastructure/grpc"
	proto "agent/pkg/infrastructure/grpc/proto"
	"agent/pkg/infrastructure/hardware"
	"agent/pkg/netstate"
)

// AgentService orchestrates the agent's main functionality
type AgentService struct {
	adoptionConfig    *node.AdoptionConfig
	fingerprintReader ports.FingerprintReader
	storageReader     *hardware.StorageReader
	systemInfoReader  *hardware.SystemInfoReader
	metricsReader     *hardware.MetricsReader
	fileReader        *hardware.FileReader
	fileWatcher       *hardware.FileWatcher
	platformClient    ports.PlatformClient
	commandHandler    *handlers.CommandHandler
	logger            *slog.Logger
	isRaspberryPi     bool
	// watcherMode marks the telemetry-only binary: no command
	// handling, no terminal, no watchdog liveness file. It is set by the
	// constructor, never by configuration — "cannot manage" is a property of
	// the binary, not a flag an attacker could clear.
	watcherMode          bool
	ctx                  context.Context // Main context for cancellation during shutdown
	connectionController *grpcclient.ConnectionController

	// connectedOnce records that this process has reached the platform at least
	// once. Read from the liveness goroutine, so it is atomic. See
	// livenessShouldReport for what turns on it.
	connectedOnce atomic.Bool
}

// NewAgentService creates a new agent service with dependency injection
func NewAgentService(
	adoptionConfig *node.AdoptionConfig,
	fingerprintReader ports.FingerprintReader,
	platformClient ports.PlatformClient,
	commandHandler *handlers.CommandHandler,
	logger *slog.Logger,
) *AgentService {
	return &AgentService{
		adoptionConfig:    adoptionConfig,
		fingerprintReader: fingerprintReader,
		storageReader:     hardware.NewStorageReader(),
		systemInfoReader:  hardware.NewSystemInfoReader(logger),
		metricsReader:     hardware.NewMetricsReader(logger),
		platformClient:    platformClient,
		commandHandler:    commandHandler,
		logger:            logger,
	}
}

// NewWatcherService builds the telemetry-only variant: heartbeat,
// system info and metrics, and nothing else. There is no command handler
// parameter on purpose — the watcher binary does not link the command
// execution code, so "it cannot manage the node" is structural.
func NewWatcherService(
	adoptionConfig *node.AdoptionConfig,
	fingerprintReader ports.FingerprintReader,
	platformClient ports.PlatformClient,
	logger *slog.Logger,
) *AgentService {
	return &AgentService{
		adoptionConfig:    adoptionConfig,
		fingerprintReader: fingerprintReader,
		storageReader:     hardware.NewStorageReader(),
		systemInfoReader:  hardware.NewSystemInfoReader(logger),
		metricsReader:     hardware.NewMetricsReader(logger),
		platformClient:    platformClient,
		logger:            logger,
		watcherMode:       true,
	}
}

// Run executes the main agent orchestration
func (s *AgentService) Run(ctx context.Context) error {
	s.ctx = ctx // Store context for use in reportSystemInfo
	s.logger.Info("Starting agent", "node_id", s.adoptionConfig.NodeID)

	// Local watchdog circuit breaker. Runs before anything talks to the
	// platform: a node caught in a watchdog reboot loop may never stay up long
	// enough to be told to stop, so the decision has to be local.
	if s.commandHandler != nil {
		s.commandHandler.CheckWatchdogBreaker()
	}

	// Liveness file for the watchdog daemon's agent-health supervision. It is
	// touched on its own ticker rather than piggybacking the 30-second platform
	// heartbeat: the daemon compares mtime age against `change`, and a cadence
	// that close to the threshold turns a single slow beat into a reboot.
	//
	// Not in watcher mode: the watcher runs unprivileged (it cannot create
	// /run/orchestrator-agent), and nothing may arm a watchdog on a watcher
	// node — the platform refuses the command and the binary could not apply
	// it. A watchdog armed by a PREVIOUS full agent must be disarmed before
	// switching, or it will reboot the node when the liveness file goes stale.
	if !s.watcherMode {
		go s.touchLivenessFile(ctx)
	}

	// Set up connection controller for reconnection support
	s.setupConnectionController(ctx)

	// Everything the command handler needs that does not require a stream, wired
	// BEFORE the first dial — the dial is now retried, and these must not be
	// skipped by an attempt that failed. See wireCommandHandler.
	if !s.watcherMode {
		s.wireCommandHandler()
	}

	// Connect to the platform, retrying in process.
	//
	// This used to return on the FIRST failure, so the whole process exited and
	// systemd restarted it 10s later — for as long as the failure lasted. That is
	// the wrong retry: it is unjittered, three times more frequent than the
	// agent's own 30s backoff ceiling, and phase-synchronised across a fleet, so a
	// platform outage returns as a thundering herd. It was also inconsistent with
	// the agent's own stated policy — isRecoverableError already classifies
	// codes.Unavailable as recoverable; the initial path simply never asked.
	if err := s.connectWithRetry(ctx); err != nil {
		return fmt.Errorf("connection failed: %w", err)
	}

	s.logger.Info("Node connected successfully, starting heartbeat and command handling")

	// Report the state that needed a live stream.
	s.afterConnect(ctx)

	// Start reconnection loop
	if s.connectionController != nil {
		s.connectionController.StartReconnectionLoop(ctx)
	}

	// Start heartbeat and command handling
	var wg sync.WaitGroup
	wg.Add(2)

	// Start heartbeat goroutine
	go func() {
		defer wg.Done()
		s.startHeartbeat(ctx)
		s.logger.Info("Heartbeat goroutine stopped")
	}()

	// Start the receive loop. The watcher runs it too, with a handler that
	// refuses every command.
	//
	// It used to run nothing at all, on the reasoning that the platform refuses
	// to dispatch to a watcher (belt) and this binary carries no handler
	// (suspenders). Both are true, and the conclusion was still wrong: the
	// receive loop is ALSO the only reader of IdentityAssignment, the frame that
	// hands a master-token adoptee its own credentials. A Watcher enrolled from a
	// master token therefore kept presenting the SHARED token for its whole life,
	// and once that token expired it was refused on every reconnect —
	// permanently offline, recoverable only by physically netbooting it. The
	// registered identity handler was dead code, which is why nothing showed it.
	go func() {
		defer wg.Done()
		if s.watcherMode {
			s.platformClient.ListenForCommands(ctx, s.refuseCommandOnWatcher)
			s.logger.Info("Watcher receive loop stopped")
			return
		}
		s.startCommandHandling(ctx)
		s.logger.Info("Command handling goroutine stopped")
	}()

	// Start live metrics sampling loop
	wg.Add(1)
	go func() {
		defer wg.Done()
		s.startMetricsLoop(ctx)
		s.logger.Info("Metrics loop stopped")
	}()

	// Watch the SoC's power/thermal mask and re-report when it CHANGES. Without
	// this `hardware.power` is only as fresh as the last connect, so a brownout
	// that does not break the stream is never reported — which is the case
	// this poll exists for. Returns immediately on hardware that cannot
	// answer, so this costs nothing on a non-Pi.
	wg.Add(1)
	go func() {
		defer wg.Done()
		s.startPowerWatch(ctx)
		s.logger.Info("Power watch stopped")
	}()

	// Start file watcher if Raspberry Pi
	if s.isRaspberryPi && s.fileReader != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.startFileWatcher(ctx)
			s.logger.Info("File watcher stopped")
		}()
	}

	// Monitor for shutdown signal and close connection to unblock goroutines
	go func() {
		<-ctx.Done()
		s.logger.Info("Received shutdown signal, stopping agent")
		// Close the platform connection gracefully to unblock Recv() calls
		// platformClient is guaranteed to implement the interface (set in constructor)
		if err := s.platformClient.Close(); err != nil {
			s.logger.Error("Error closing platform connection", "error", err)
		} else {
			s.logger.Info("Platform connection closed")
		}
	}()

	// Wait for all goroutines to finish
	wg.Wait()
	s.logger.Info("All goroutines stopped, agent shutdown complete")
	return nil
}

// setupConnectionController initializes the connection controller for reconnection support
func (s *AgentService) setupConnectionController(ctx context.Context) {
	// Create connection controller
	s.connectionController = grpcclient.NewConnectionController(ctx, s.logger)

	// Set up state change callback
	s.connectionController.SetOnStateChange(func(oldState, newState grpcclient.ConnectionState) {
		s.logger.Info("Connection state changed",
			"old_state", oldState.String(),
			"new_state", newState.String())

		// Re-report system info after successful reconnection
		if newState == grpcclient.StateConnected && oldState == grpcclient.StateDisconnected {
			s.logger.Info("Reconnected, re-reporting system info")
			go func() {
				// Use a timeout context for reporting
				reportCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				defer cancel()

				if err := s.reportSystemInfo(reportCtx); err != nil {
					s.logger.Warn("Failed to report system info after reconnection", "error", err)
				}
			}()
		}
	})

	// Wire up the connection controller to the platform client if it supports it
	if pc, ok := s.platformClient.(*grpcclient.PlatformClient); ok {
		pc.SetConnectionController(s.connectionController)
		s.logger.Debug("Connection controller attached to platform client")

		// The watcher offers no shell: no terminal handler is wired, so a
		// TerminalOpen (which the platform refuses to send anyway) would be
		// ignored rather than answered.
		if s.watcherMode {
			return
		}

		// Wire the interactive-terminal handler: PTY output/exit is streamed
		// back to the platform using the node's adoption identity.
		nodeID := s.adoptionConfig.NodeID.String()
		accountID := s.adoptionConfig.AccountID.String()
		token := s.adoptionConfig.GetEffectiveToken()
		termHandler := handlers.NewTerminalHandler(
			s.logger,
			func(sessionID string, data []byte) {
				_ = pc.SendTerminalOutput(nodeID, accountID, token, sessionID, data)
			},
			func(sessionID string, exitCode int32, errMsg string) {
				_ = pc.SendTerminalClosed(nodeID, accountID, token, sessionID, exitCode, errMsg)
			},
		)
		pc.SetTerminalHandler(termHandler.Handle)
		// A dropped stream ends the sessions on the device too. Without this the
		// shells outlive the connection they were opened over, and the platform
		// cannot end them: its own cleanup deletes its side, so no TerminalClose
		// is ever sent.
		pc.SetTerminalDisconnectHandler(termHandler.CloseAllSessions)
		s.logger.Debug("Terminal handler attached to platform client")
	}
}

// Initial-connect retry policy. The ceiling matches the reconnect controller's
// so a node behaves the same before and after its first successful connect.
// Vars, not consts, so tests can shrink them; nothing else reassigns them.
var (
	initialConnectBaseDelay = 1 * time.Second
	initialConnectMaxDelay  = 30 * time.Second
	// initialConnectWindow is how long to keep trying before giving up and
	// letting the process exit.
	//
	// Not infinite, deliberately. Exiting re-reads the adoption file — which
	// something else may have rewritten (SD provisioning seeds it per serial, a
	// re-adopt replaces it) — and it lets systemd recycle any wedged internal
	// state, which crash-restarting has been giving us for free. Keeping systemd
	// as the last resort while removing the 10-second hammer is the point.
	initialConnectWindow = 30 * time.Minute

	// hasDefaultRoute is indirected for the same reason: /proc is not readable on
	// a dev machine, and the "host cannot route" branch is the one worth testing.
	hasDefaultRoute = netstate.HasDefaultRoute
)

// connectWithRetry dials the platform until it succeeds, the context is
// cancelled, or initialConnectWindow elapses.
func (s *AgentService) connectWithRetry(ctx context.Context) error {
	deadline := time.Now().Add(initialConnectWindow)
	delay := initialConnectBaseDelay

	for attempt := 1; ; attempt++ {
		err := s.connect(ctx)
		if err == nil {
			s.connectedOnce.Store(true)
			if attempt > 1 {
				s.logger.Info("connected to the platform after retrying", "attempts", attempt)
			}
			return nil
		}
		if ctx.Err() != nil {
			return err // shutting down; report the last failure, do not retry
		}
		if time.Now().After(deadline) {
			s.logger.Error("giving up on the initial connection; exiting so the supervisor can restart us",
				append([]any{"attempts", attempt, "window", initialConnectWindow.String(), "error", err},
					clockHintAttrs(err)...)...)
			return err
		}

		s.logger.Warn("initial connection failed; retrying",
			append([]any{"attempt", attempt, "retry_in", delay.String(), "error", err},
				clockHintAttrs(err)...)...)
		select {
		case <-ctx.Done():
			return err
		case <-time.After(delay):
		}
		if delay < initialConnectMaxDelay {
			delay *= 2
			if delay > initialConnectMaxDelay {
				delay = initialConnectMaxDelay
			}
		}
	}
}

// certificateValidityText is the x509 verifier's wording for a certificate
// outside its validity period. It is matched as text because grpc-go folds the
// TLS handshake failure into a status message: no typed error survives to
// errors.As.
const certificateValidityText = "certificate has expired or is not yet valid"

// clockHintAttrs adds a pointer to the device clock when TLS refused the
// platform's certificate as outside its validity period. A board without a
// battery-backed clock boots at a stale time and dials before NTP has set it;
// the refusal then reads like a PKI fault although it clears by itself once
// the clock is synchronized. The x509 text already carries the device's time.
func clockHintAttrs(err error) []any {
	if err == nil || !strings.Contains(err.Error(), certificateValidityText) {
		return nil
	}
	return []any{"clock_hint", "the device clock is outside the platform certificate's validity period: " +
		"if the current time in the error is wrong, the clock is not set yet (no battery-backed clock, NTP not synchronized) " +
		"and this clears once it is; if it is right, the platform's certificate has expired"}
}

// connect handles the node connection process
func (s *AgentService) connect(ctx context.Context) error {
	s.logger.Info("Harvesting hardware fingerprint")

	// Harvest hardware fingerprint
	fingerprint, err := s.fingerprintReader.Harvest()
	if err != nil {
		return fmt.Errorf("failed to harvest fingerprint: %w", err)
	}

	s.logger.Info("Hardware fingerprint harvested",
		"mac_address", fingerprint.MacAddress,
		"hardware_serial", fingerprint.HardwareSerial)

	// Create connection request
	// Use GetEffectiveToken() which returns MasterToken or UniqueToken depending on auth mode
	if s.adoptionConfig.IsMasterTokenMode() {
		s.logger.Info("Using master token authentication mode")
	}

	agentKind := "full"
	var ledSources []string
	if s.watcherMode {
		agentKind = "watcher"
	} else {
		// The LED v2 advertisement: what the reader registry can render, so
		// the platform offers exactly that and never hand-tracks agent
		// capabilities. The watcher advertises nothing — it renders nothing.
		ledSources = handlers.LEDSupportedSources()
	}
	req := node.ConnectionRequest{
		NodeID:      s.adoptionConfig.NodeID,
		AccountID:   s.adoptionConfig.AccountID,
		UniqueToken: s.adoptionConfig.GetEffectiveToken(),
		Fingerprint: fingerprint,
		AgentKind:   agentKind,
		LEDSources:  ledSources,
	}

	s.logger.Info("Connecting to platform", "grpc_endpoint", s.adoptionConfig.GRPCEndpoint)

	// Connect to platform via gRPC. The second argument is the PLATFORM URL —
	// its scheme decides TLS (https → TLS). Passing the scheme-less gRPC
	// endpoint here would silently downgrade every SaaS connection to
	// plaintext (which a TLS-terminating proxy then answers with HTTP 404).
	err = s.platformClient.Connect(ctx, s.adoptionConfig.PlatformURL, req)

	if err != nil {
		return fmt.Errorf("platform connection failed: %w", err)
	}

	return nil
}

// wireCommandHandler gives the command handler everything it needs that does NOT
// require a live stream.
//
// Split out of connect() and hoisted above it on purpose. connect() is retried
// until it succeeds, and every one of these is local — so leaving them below the
// dial would mean a node whose first attempts failed could come up online with an
// unconfigured handler: no storage reader (install_os device validation), no
// hardware reporter, no file reader. That is a worse bug than the one the retry
// fixes, and it would be silent.
func (s *AgentService) wireCommandHandler() {
	// Provide adoption config to command handler for use in agent installation on
	// new volumes — but never REPLACE one. The identity handoff may since have
	// swapped in this node's own credential. Overwriting it would put the shared
	// master token back, and install_os writes this onto the disk it images.
	if !s.commandHandler.HasAdoptionConfig() {
		s.commandHandler.SetAdoptionConfig(s.adoptionConfig)
	}

	// Set storage reader on command handler for device validation
	s.commandHandler.SetStorageReader(s.storageReader)

	// Set hardware info reporter callback on command handler
	// Use a wrapper that provides context (use background context with timeout for callbacks)
	s.commandHandler.SetHardwareInfoReporter(func() error {
		// Use background context with timeout for hardware reporting from command handlers
		// This ensures operations can be cancelled if needed
		reportCtx := context.Background()
		if s.ctx != nil {
			// If main context exists and is cancelled, use it to cancel hardware reporting
			select {
			case <-s.ctx.Done():
				reportCtx = s.ctx // Use cancelled context to fail fast
			default:
				// Use background context with timeout for safety
				var cancel context.CancelFunc
				reportCtx, cancel = context.WithTimeout(context.Background(), 30*time.Second)
				defer cancel()
			}
		}
		return s.reportSystemInfo(reportCtx)
	})

	// Check if this is a Raspberry Pi
	isPi, err := s.systemInfoReader.IsRaspberryPi()
	if err != nil {
		s.logger.Warn("failed to check if Raspberry Pi", "error", err)
	} else {
		s.isRaspberryPi = isPi
		if isPi {
			s.logger.Info("Raspberry Pi detected, initializing file support")
			s.fileReader = hardware.NewFileReader()
			s.commandHandler.SetFileReader(s.fileReader)
		}
	}
}

// afterConnect reports the state that needs a live stream. Both calls already
// tolerate failure, which is why they are the only part of the old connect() that
// stays behind the dial.
func (s *AgentService) afterConnect(ctx context.Context) {
	// Report system info (includes storage devices, network, hardware, OS)
	if err := s.reportSystemInfo(ctx); err != nil {
		s.logger.Warn("failed to report system info", "error", err)
	}

	// Report files if Raspberry Pi (edge case: check config files first)
	if s.isRaspberryPi && s.fileReader != nil {
		if err := s.reportFiles(); err != nil {
			s.logger.Warn("failed to report files", "error", err)
		}
	}
}

// reportSystemInfo detects and reports system information (storage, network, hardware, OS) to the platform
func (s *AgentService) reportSystemInfo(ctx context.Context) error {
	if s.storageReader == nil {
		return fmt.Errorf("storage reader not initialized")
	}

	// Collect storage devices
	devices, err := s.storageReader.DetectDevices()
	if err != nil {
		return fmt.Errorf("failed to detect storage devices: %w", err)
	}

	// Collect system info (network, hardware, OS)
	var systemInfoComponents *hardware.SystemInfoComponents
	if s.systemInfoReader != nil {
		systemInfoComponents, err = s.systemInfoReader.CollectSystemInfo(ctx)
		if err != nil {
			s.logger.Warn("failed to collect system info", "error", err)
			// Continue with storage devices only if system info collection fails
			systemInfoComponents = &hardware.SystemInfoComponents{}
		}
	} else {
		systemInfoComponents = &hardware.SystemInfoComponents{}
	}

	// Build SystemInfoUpdate message
	systemInfoUpdate := &proto.SystemInfoUpdate{
		StorageDevices: devices,
		Network:        systemInfoComponents.Network,
		Hardware:       systemInfoComponents.Hardware,
		Os:             systemInfoComponents.OS,
	}

	// Send system info via platform client
	// platformClient is guaranteed to implement the interface (set in constructor)
	if err := s.platformClient.SendSystemInfo(
		s.adoptionConfig.NodeID.String(),
		s.adoptionConfig.AccountID.String(),
		s.adoptionConfig.GetEffectiveToken(),
		systemInfoUpdate,
	); err != nil {
		return fmt.Errorf("failed to send system info: %w", err)
	}
	bootOrderCount := 0
	bootOrder := []string{}
	currentBootDevice := ""
	if systemInfoComponents.Hardware != nil && systemInfoComponents.Hardware.Boot != nil {
		if systemInfoComponents.Hardware.Boot.BootDevicesOrder != nil {
			bootOrderCount = len(systemInfoComponents.Hardware.Boot.BootDevicesOrder)
			bootOrder = systemInfoComponents.Hardware.Boot.BootDevicesOrder
		}
		currentBootDevice = systemInfoComponents.Hardware.Boot.CurrentBootDevice
	}

	s.logger.Info("system info reported",
		"device_count", len(devices),
		"has_network", systemInfoComponents.Network != nil,
		"has_hardware", systemInfoComponents.Hardware != nil,
		"has_os", systemInfoComponents.OS != nil,
		"current_boot_device", currentBootDevice,
		"boot_order_count", bootOrderCount,
		"boot_order", bootOrder)

	return nil
}

// touchLivenessFile keeps /run/orchestrator-agent/alive fresh so the watchdog
// daemon can tell "the agent is running" from "the agent is wedged". /run is
// tmpfs, so the file is absent until this starts — the watchdog unit is ordered
// after the agent for exactly that reason.
func (s *AgentService) touchLivenessFile(ctx context.Context) {
	const (
		livenessDir  = "/run/orchestrator-agent"
		livenessFile = "/run/orchestrator-agent/alive"
		interval     = 10 * time.Second
	)
	if err := os.MkdirAll(livenessDir, 0o755); err != nil {
		s.logger.Debug("liveness directory unavailable; agent-health supervision will not work", "error", err)
		return
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		if s.livenessShouldReport() {
			now := time.Now()
			f, err := os.OpenFile(livenessFile, os.O_CREATE|os.O_WRONLY, 0o644)
			if err == nil {
				_ = f.Close()
				_ = os.Chtimes(livenessFile, now, now)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// livenessShouldReport decides whether to keep telling the watchdog daemon this
// agent is healthy.
//
// Touching the file unconditionally, from a ticker started before the first
// connect ever ran, would hide the worst failure from the one supervisor meant
// to catch it: a node whose network manager never starts crash-loops every 10s,
// refreshing the liveness file 12-30x faster than the agent-health preset's
// 120-300s threshold, so an armed watchdog sees a perfectly healthy agent.
//
// Withholding it is what makes the watchdog act — and a watchdog reboot is
// genuinely the right answer there, because the netplan/networkd race is a dice
// roll that a fresh boot re-rolls. But withholding it merely because the agent is
// not connected would be dangerous in the other direction: during a platform
// outage every armed node in the fleet would reboot itself, repeatedly, for an
// outage the node had no part in.
//
// The distinction is exactly the one netstate answers. A node wedged by the race
// has no default route at all; a healthy node during a platform outage routes
// fine. So the report is withheld only when BOTH hold: this process has never
// reached the platform, and the host cannot route. Once connected the file is
// always touched, so an established node's supervision is unchanged.
func (s *AgentService) livenessShouldReport() bool {
	if s.connectedOnce.Load() {
		return true
	}
	if hasDefaultRoute() {
		return true
	}
	s.logger.Warn("withholding the watchdog liveness report: never connected and the host has no default route")
	return false
}

// startHeartbeat starts the heartbeat loop
// platformClient is guaranteed to implement the interface (set in constructor)
func (s *AgentService) startHeartbeat(ctx context.Context) {
	s.platformClient.StartHeartbeat(ctx,
		s.adoptionConfig.NodeID.String(),
		s.adoptionConfig.AccountID.String(),
		s.adoptionConfig.GetEffectiveToken())
}

// refuseCommandOnWatcher is the watcher's command handler: it executes
// nothing and says so.
//
// The watcher binary links no command-execution code at all, so this cannot
// become a way in even by mistake — it exists so the receive loop can run, and
// the receive loop exists so IdentityAssignment is read. A command reaching here
// means the platform's own refusal was bypassed, which is worth a log line
// rather than silence.
func (s *AgentService) refuseCommandOnWatcher(cmd *proto.Command) error {
	commandID := ""
	if cmd != nil {
		commandID = cmd.CommandId
	}
	s.logger.Warn("refusing a command: this node runs the telemetry-only agent", "command_id", commandID)
	return fmt.Errorf("this node runs the telemetry-only agent and executes no commands")
}

// startCommandHandling starts the command handling loop
// platformClient is guaranteed to implement the interface (set in constructor)
func (s *AgentService) startCommandHandling(ctx context.Context) {
	s.platformClient.ListenForCommands(ctx, s.commandHandler.HandleCommand)
}

// metricsInterval is how often live resource utilization is sampled and pushed.
// Kept modest to stay cheap on a Raspberry Pi.
const metricsInterval = 5 * time.Second

// startMetricsLoop samples resource utilization on a timer and pushes each
// sample to the platform. Samples are dropped (not queued) when disconnected.
func (s *AgentService) startMetricsLoop(ctx context.Context) {
	ticker := time.NewTicker(metricsInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			sample := s.metricsReader.Read()
			if err := s.platformClient.SendMetrics(
				s.adoptionConfig.NodeID.String(),
				s.adoptionConfig.AccountID.String(),
				s.adoptionConfig.GetEffectiveToken(),
				sample,
			); err != nil {
				s.logger.Debug("failed to send metrics sample", "error", err)
			}
		}
	}
}

// powerWatchInterval is how often the SoC's throttling mask is polled. One
// vcgencmd fork a minute is cheap enough on a Pi to be invisible, and the thing
// being watched — a supply that sags — does not need second-level resolution.
const powerWatchInterval = 60 * time.Second

// startPowerWatch re-reports system info when the SoC's power/thermal mask
// CHANGES, and only then.
//
// It exists because there is no periodic system_info report at all:
// reportSystemInfo runs on connect, on reconnect, and from the
// hardware-info callback after a command that changes hardware state. So
// `hardware.power` was only ever as fresh as the last of those, which on a
// node up for days can be very stale.
//
// What that cost is precisely what this poll exists for: a node that sags an hour
// into its uptime keeps reporting the throttled_flags: 0 captured at connect,
// while the sticky bits sit set on the device unseen. A brownout severe enough
// to drop the stream is caught by the reconnect; the one that silently corrupts
// an install while the connection holds is not.
//
// Change-driven rather than periodic, and that is what makes it affordable:
// within a boot the sticky bits only ever go up, so a healthy node sends nothing
// extra for its whole uptime and a sagging one sends a handful of reports.
//
// Two shapes deliberately avoided. Not the 5s metrics sample: those are dropped
// when disconnected and never land in system_info, so the sticky evidence would
// not survive — and twelve vcgencmd forks a minute for a value that rarely
// changes is waste. Not a full periodic system_info re-report either: that
// re-runs storage detection and lsblk for a much smaller reason.
func (s *AgentService) startPowerWatch(ctx context.Context) {
	if s.systemInfoReader == nil {
		return
	}
	watchThrottling(ctx, s.systemInfoReader.ReadThrottledFlags, s.reportSystemInfo,
		powerWatchInterval, s.logger)
}

// watchThrottling is the loop itself, taking its reader and reporter as
// functions so the rule can be tested without a Raspberry Pi. The agent's
// hardware code is linux-tagged and cannot run on a development host at all,
// which is how untested logic reaches devices.
func watchThrottling(
	ctx context.Context,
	read func(context.Context) (uint32, bool),
	report func(context.Context) error,
	interval time.Duration,
	logger *slog.Logger,
) {
	// The first reading is the one afterConnect has already sent, so it is a
	// BASELINE, not a change. Without seeding here every agent start would
	// re-report once for nothing.
	last, ok := read(ctx)
	if !ok {
		// No vcgencmd: not a Pi, or it cannot answer. Nothing to watch, and
		// polling a command that always fails is pure noise.
		return
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			flags, ok := read(ctx)
			if !ok || flags == last {
				continue
			}
			logger.Info("SoC throttling mask changed; re-reporting system info",
				"from", fmt.Sprintf("0x%x", last), "to", fmt.Sprintf("0x%x", flags))
			// Advance the baseline BEFORE reporting, and keep it advanced even if
			// the report fails. Retrying on the next tick would make a
			// disconnected node re-report every minute for as long as it is away,
			// and its reconnect re-reports everything anyway.
			last = flags

			reportCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
			err := report(reportCtx)
			cancel()
			if err != nil {
				logger.Warn("failed to re-report system info after a throttling change", "error", err)
			}
		}
	}
}

// reportFiles reports files to the platform (reports both config files separately if they exist)
func (s *AgentService) reportFiles() error {
	if s.fileReader == nil {
		return fmt.Errorf("file reader not initialized")
	}

	// Report both config files separately if they exist
	configPaths := []string{"/boot/firmware/config.txt", "/boot/config.txt"}

	if grpcClient, ok := s.platformClient.(interface {
		SendFileChangedEvent(nodeID, accountID, uniqueToken, path, content, hash string, version int32, status, errorMessage string) error
	}); ok {
		for _, path := range configPaths {
			content, err := os.ReadFile(path)
			if err != nil {
				// Skip if file doesn't exist, but log other errors
				if os.IsNotExist(err) {
					continue
				}
				s.logger.Warn("failed to read config file", "path", path, "error", err)
				continue
			}

			hash := s.fileReader.GetFileHash(string(content))

			// Report with status "applied" and version 0 (unknown version on initial report)
			if err := grpcClient.SendFileChangedEvent(
				s.adoptionConfig.NodeID.String(),
				s.adoptionConfig.AccountID.String(),
				s.adoptionConfig.GetEffectiveToken(),
				path,
				string(content),
				hash,
				0, // version 0 for initial report
				"applied",
				"",
			); err != nil {
				s.logger.Warn("failed to send file changed event", "path", path, "error", err)
				continue
			}
			s.logger.Info("file reported", "path", path)
		}
	}

	return nil
}

// startFileWatcher starts watching files for changes
func (s *AgentService) startFileWatcher(ctx context.Context) {
	if s.fileReader == nil {
		s.logger.Warn("file reader not initialized, cannot start watcher")
		return
	}

	// Create onChange callback
	onChange := func(path, content, hash string) error {
		// Report file change with status "applied" (file was changed externally)
		if grpcClient, ok := s.platformClient.(interface {
			SendFileChangedEvent(nodeID, accountID, uniqueToken, path, content, hash string, version int32, status, errorMessage string) error
		}); ok {
			if err := grpcClient.SendFileChangedEvent(
				s.adoptionConfig.NodeID.String(),
				s.adoptionConfig.AccountID.String(),
				s.adoptionConfig.GetEffectiveToken(),
				path,
				content,
				hash,
				0, // version 0 for external changes
				"applied",
				"",
			); err != nil {
				return fmt.Errorf("failed to send file changed event: %w", err)
			}
			s.logger.Info("file change detected and reported", "path", path)
		}
		return nil
	}

	// Create watcher
	watcher, err := hardware.NewFileWatcher(s.fileReader, onChange, s.logger)
	if err != nil {
		s.logger.Error("failed to create file watcher", "error", err)
		return
	}
	s.fileWatcher = watcher

	// Start watching (this starts a goroutine internally)
	if err := watcher.Start(ctx); err != nil {
		s.logger.Error("failed to start file watcher", "error", err)
		return
	}

	// Wait for context cancellation
	<-ctx.Done()
	s.logger.Info("File watcher context cancelled, closing watcher")

	// Close watcher (this will stop the internal event loop goroutine)
	if err := watcher.Close(); err != nil {
		s.logger.Error("failed to close file watcher", "error", err)
	}
}
