package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"agent/pkg/application/config"
	"agent/pkg/application/handlers"
	"agent/pkg/application/service"
	"agent/pkg/domain/redact"
	"agent/pkg/infrastructure/grpc"
	"agent/pkg/infrastructure/hardware"
	"agent/pkg/signing"

	"github.com/google/uuid"
)

const defaultAdoptionFile = "/mnt/sdcard/node-adoption.txt"

// exitCodeNotProvisioned is the distinct exit code for "no node identity is
// available here" on an interactive run — sysexits EX_CONFIG, so a script can
// tell an unprovisioned invocation from a crash. The systemd
// path keeps exiting 1, unchanged.
const exitCodeNotProvisioned = 78

// isInteractiveRun reports whether stdout is a terminal — true for an operator
// typing `orchestrator-agent` in a shell, false under systemd (journald hands
// the service a stream socket). Decides only which ERROR WORDING an
// already-failed start prints, so a wrong answer costs nothing but tone.
func isInteractiveRun() bool {
	fi, err := os.Stdout.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

// version is set via ldflags during build (e.g., by goreleaser)
// Default value is "0.0.0" if not set during build
var version = "0.0.0"

// runVerifySignature is a hidden CLI mode: the ROM-trusted baked agent inside the
// netboot recovery image (which has no openssl) uses it to verify a downloaded
// agent binary's detached signature before running it. Exit 0 = valid signature.
//
//	orchestrator-agent verify-signature <file> <file.sig>
func runVerifySignature(args []string) int {
	if len(args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: orchestrator-agent verify-signature <file> <file.sig>")
		return 2
	}
	data, err := os.ReadFile(args[0])
	if err != nil {
		fmt.Fprintln(os.Stderr, "verify-signature: read file:", err)
		return 1
	}
	sig, err := os.ReadFile(args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, "verify-signature: read signature:", err)
		return 1
	}
	if err := signing.VerifyDetached(data, sig); err != nil {
		fmt.Fprintln(os.Stderr, "verify-signature: INVALID:", err)
		return 1
	}
	fmt.Fprintln(os.Stderr, "verify-signature: OK")
	return 0
}

func main() {
	// Hidden verify mode (must run before flag parsing) — see runVerifySignature.
	if len(os.Args) >= 2 && os.Args[1] == "verify-signature" {
		os.Exit(runVerifySignature(os.Args[2:]))
	}

	// Hidden watchdog breaker gate: systemd runs this as ExecStartPre= of
	// watchdog.service. It needs no adoption file on purpose — a reboot loop
	// must stop even on a node whose agent cannot start.
	if len(os.Args) >= 2 && os.Args[1] == handlers.WatchdogGateSubcommand {
		os.Exit(handlers.RunWatchdogBreakerGate())
	}

	// Parse command line arguments
	var adoptionFile string
	var showStatus bool
	flag.StringVar(&adoptionFile, "adoption-file", defaultAdoptionFile, "Path to the adoption file")
	flag.BoolVar(&showStatus, "status", false, "Print a local diagnostic (identity, service, process) and exit; talks to no platform")
	flag.Parse()

	// The read-only diagnostic for an operator's hand-run: safe without
	// root, prints no credentials, and exits
	// 0 = running, 1 = provisioned but not running, 78 = no identity here.
	if showStatus {
		os.Exit(runStatus(adoptionFile))
	}

	// Create logger. URLs are redacted at the HANDLER (userinfo, query,
	// fragment) so an operator-authored download URL carrying a credential
	// cannot reach journald through any log call, wrapped or not;
	// the call sites that know they hold one still redact
	// first, this is the backstop.
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level:       slog.LevelInfo,
		ReplaceAttr: redact.SlogAttr,
	}))

	logger.Info("Starting orchestrator agent", "adoption_file", adoptionFile, "version", version)

	// In the netboot bootstrap, name the host after the device serial so
	// recovery nodes are self-describing (no-op on an installed OS).
	hardware.ApplyRecoveryHostname(logger)

	// Purge stale or foreign EEPROM recovery packages from boot media before
	// anything else: a reused provisioning SD card must not stay armed to
	// reflash the next device with another node's identity.
	hardware.CleanupStaleEEPROMArtifacts(logger)

	// Check if Raspberry Pi and create EEPROM storage if needed
	systemInfoReader := hardware.NewSystemInfoReader(logger)
	isRPi, err := systemInfoReader.IsRaspberryPi()
	if err != nil {
		logger.Warn("failed to check if Raspberry Pi", "error", err)
		isRPi = false
	}

	var eepromStorage *hardware.EEPROMAdoptionStorage
	if isRPi {
		eepromStorage = hardware.NewEEPROMAdoptionStorage(logger)
	}

	// Parse adoption file (will fallback to EEPROM if file missing and on Raspberry Pi)
	parser := config.NewParserWithLogger(logger)
	var eepromReader config.EEPROMAdoptionReader
	if eepromStorage != nil {
		eepromReader = eepromStorage
	}
	adoptionConfig, err := parser.ParseAdoptionFile(adoptionFile, eepromReader)
	if err != nil {
		if errors.Is(err, config.ErrIdentityReleased) {
			// Not a fault: the platform deleted this node and the device is
			// unadopted until someone adopts it again. systemd will restart
			// the service and this line repeats at a calm level, instead of
			// an ERROR every ten seconds on a device doing exactly what it
			// was told.
			logger.Info("this device's adoption identity was released; waiting to be adopted again", "file", adoptionFile)
			os.Exit(exitCodeNotProvisioned)
		}
		logger.Error("Failed to parse adoption file", "error", err, "file", adoptionFile)
		if isInteractiveRun() {
			fmt.Fprintf(os.Stderr, `
orchestrator-agent is the managed-node daemon and is not meant to be run by hand.

It starts by loading this node's identity (the adoption file, or the EEPROM on
a Raspberry Pi) and found none — which is expected on a machine that has not
been adopted into an Orchestrator platform, and on any interactive shell.

On a managed node the agent runs as a systemd service:

  systemctl status orchestrator-agent    # is it running, and why not
  journalctl -u orchestrator-agent -e    # its recent log

To adopt a new node, use the install command from the platform UI
(Nodes -> Add node), which writes the identity this start was missing.
`)
			os.Exit(exitCodeNotProvisioned)
		}
		os.Exit(1)
	}

	// One-shot remediation for devices already in the field, on every start
	// because it is cheap and idempotent:
	//
	//  - the install_agent path wrote the adoption file 0644 into the installed
	//    rootfs, so the credential authenticating this node's gRPC stream was
	//    readable by every unprivileged account on the device;
	//  - WriteAdoptionFile kept a verbatim `.pre-identity.bak`, which normally
	//    holds the SHARED master enrolment token, forever.
	//
	// Fixing the write sites only helps devices provisioned from here on; these
	// two calls are what reaches the ones already installed.
	parser.EnsureAdoptionFilePermissions(adoptionFile)
	parser.RedactExistingAdoptionBackup(adoptionFile)

	logger.Info("Adoption config loaded",
		"node_id", adoptionConfig.NodeID,
		"account_id", adoptionConfig.AccountID,
		"platform_url", adoptionConfig.PlatformURL,
		"grpc_endpoint", adoptionConfig.GRPCEndpoint)

	// NOTE: the agent never writes the adoption token (or anything else) to the
	// EEPROM on-device. UPTIME_TOKEN is baked into the per-device EEPROM image
	// by the server-side eeprom-signer; an on-device rpi-eeprom-config --apply
	// would drop our embedded public key and break signed network boot.

	// Create infrastructure adapters
	fingerprintReader := hardware.NewFingerprintReader()
	platformClient := grpc.NewPlatformClient(adoptionConfig.GRPCEndpoint, logger, version)
	commandHandler := handlers.NewCommandHandler(
		logger,
		platformClient,
		adoptionConfig.NodeID.String(),
		adoptionConfig.AccountID.String(),
		adoptionConfig.UniqueToken,
	)
	// The running version is the anti-rollback floor for update_agent.
	commandHandler.SetAgentVersion(version)
	// Physical-button watcher (device profiles): arms from persisted state,
	// re-armed live by apply_device_profile. No-op on boards with no button
	// declared, and on platforms without GPIO.
	handlers.StartButtonWatcher(
		logger,
		platformClient,
		adoptionConfig.NodeID.String(),
		adoptionConfig.AccountID.String(),
		adoptionConfig.UniqueToken,
		commandHandler,
	)
	// LED manager: re-applies the persisted stealth / LED-off / indication
	// state, so a reboot restores it with the platform unreachable.
	commandHandler.StartLEDManager()
	// RTC keeper: once an NTP client has disciplined the system clock, copy it
	// into a plug-in hardware clock so the time survives a power cut. No-op on
	// a board with no I2C RTC. Started before the dial on purpose — the boot
	// this matters on is the one where the clock reads 2000-01-01 and every
	// TLS dial therefore fails, so the keeper must not be downstream of a
	// connection that cannot succeed until the clock is fixed.
	commandHandler.StartRTCKeeper()
	// Env secrets an older agent left in /etc/environment reach every login
	// session through pam_env; move them into the root-only file now rather
	// than at the next provision, which on an installed node may never come.
	commandHandler.MigrateLegacyEnvironmentSecrets()
	// Without this every "is this the adoption file?" guard in the file handlers
	// is skipped: they are all written as `if adoptionFile != ""`, and the
	// setter had no callers at all, so the inode check that catches a symlinked
	// parent, a bind mount or a vfat case-fold never ran on any device. The
	// adoption file holds this node's unique_token, i.e. the ability to
	// impersonate it.
	commandHandler.SetAdoptionFilePath(adoptionFile)

	// Accept the identity the platform hands us after a master-token handshake.
	//
	// Only meaningful in master-token mode: there the agent authenticates with
	// the SHARED enrolment token on every connect, so that token's expiry is the
	// node's. When one expired the device went offline
	// permanently and could not be recovered remotely — the platform cannot
	// command a node it cannot authenticate — and someone had to walk to it.
	//
	// Persisted but NOT applied to the running process: the current stream is
	// already authenticated and working, and swapping credentials underneath it
	// buys nothing. The next start reads the new file and connects as itself.
	// Writing it is therefore the whole job, which is why the write is atomic
	// and keeps a one-time backup.
	platformClient.SetIdentityHandler(func(nodeID, accountID, uniqueToken string) {
		if !adoptionConfig.IsMasterTokenMode() {
			return // already node-specific; nothing to learn
		}
		parsedNode, nerr := uuid.Parse(nodeID)
		parsedAccount, aerr := uuid.Parse(accountID)
		if nerr != nil || aerr != nil || uniqueToken == "" {
			logger.Warn("ignoring malformed identity assignment", "node_id", nodeID)
			return
		}
		updated := *adoptionConfig
		updated.NodeID = parsedNode
		updated.AccountID = parsedAccount
		updated.UniqueToken = uniqueToken
		// Clearing this is the point of the exercise: a file carrying both is
		// rejected by the parser, and leaving it would keep the node tied to a
		// credential that is about to expire.
		updated.MasterToken = ""
		if err := parser.WriteAdoptionFile(adoptionFile, &updated); err != nil {
			logger.Error("failed to persist node identity — this node still depends on the master token", "error", err)
			return
		}
		// Hand it to the command handler too. install_os writes THIS config
		// into /etc/orchestrator/node-adoption.txt on the disk it just imaged,
		// so without this an install run from a master-token recovery session
		// bakes the SHARED enrolment token into the installed OS — the exact
		// dependency this handler exists to end, reintroduced on the one path
		// that then survives a reboot. The connect path will not overwrite this
		// on a later reconnect; see HasAdoptionConfig. The running stream is
		// deliberately left alone: it is already authenticated, and swapping its
		// credentials underneath it buys nothing.
		commandHandler.SetAdoptionConfig(&updated)
		// And tell the client which credentials future RECONNECTS must present.
		// The stored connection request is captured on the first Connect and
		// replayed verbatim, so without this the process keeps offering the shared
		// enrolment token until it exits — and it does not exit: after one
		// successful connect the reconnect loop retries forever without ever
		// returning. A master token that expires mid-life would therefore strand
		// the node permanently, with its own credential sitting unused on disk.
		platformClient.AdoptReconnectIdentity(parsedNode, parsedAccount, uniqueToken)
		logger.Info("node identity received and stored; this node no longer depends on the master token", "node_id", nodeID)
	})

	// Create agent service with dependency injection
	agentService := service.NewAgentService(
		adoptionConfig,
		fingerprintReader,
		platformClient,
		commandHandler,
		logger,
	)

	// Create context with cancellation
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle OS signals for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigChan
		logger.Info("Received signal", "signal", sig)
		cancel()
	}()

	// A blink interrupted by shutdown must not leave the ACT LED trigger on
	// "none" until reboot — the restore otherwise lives only in the blink
	// goroutine, which a process exit never runs.
	defer commandHandler.StopIdentify()

	// Run the agent
	if err := agentService.Run(ctx); err != nil {
		logger.Error("Agent failed", "error", err)
		// Self-heal a network-manager wedge before systemd restarts us. The error
		// is deliberately not passed in: it cannot distinguish "this host has no
		// network" from "the platform is down" (see net_heal.go), so the decision
		// is made from host state.
		//
		// The placement is load-bearing. Run() returns only when the FIRST connect
		// fails, so reaching here proves no command can be in flight. Moving this
		// into the reconnect path would let a networkd restart land in the middle
		// of an install_os streaming several GB to NVMe. If it ever moves, it needs
		// an interlock against in-flight commands first.
		healNetworkIfWedged(realNetHealSystem{}, logger)
		os.Exit(1)
	}

	logger.Info("Agent stopped gracefully")
}
