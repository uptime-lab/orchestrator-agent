// Command watcher is the telemetry-only agent: it connects to
// the platform, declares itself agent_kind=watcher, and reports heartbeat,
// system info and metrics — and nothing else. It links NO command-execution
// code: no install_os, no run_script, no file/access/EEPROM/watchdog handlers,
// no terminal. "It cannot break the node" is a property of the binary, not a
// configuration flag, and it is built to run as an unprivileged user
// (privileged system-info probes degrade to empty fields).
//
// Management of a watcher node happens by netbooting it into recovery, where
// the FULL recovery agent runs — see apply_access_config_offline.
package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"agent/pkg/application/config"
	"agent/pkg/application/service"
	"agent/pkg/domain/redact"
	"agent/pkg/infrastructure/grpc"
	"agent/pkg/infrastructure/hardware"

	"github.com/google/uuid"
)

// The watcher's adoption file lives in its own directory, owned by the
// watcher's unprivileged user — the full agent's /etc/orchestrator copy is
// root-owned 0600 on purpose and this binary must not need root to read it.
const defaultAdoptionFile = "/etc/orchestrator-watcher/node-adoption.txt"

// version is set via ldflags during build (e.g., by goreleaser).
var version = "0.0.0"

func main() {
	var adoptionFile string
	flag.StringVar(&adoptionFile, "adoption-file", defaultAdoptionFile, "Path to the adoption file")
	flag.Parse()

	// Same URL-redacting handler as the full agent.
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level:       slog.LevelInfo,
		ReplaceAttr: redact.SlogAttr,
	}))

	logger.Info("Starting orchestrator watcher (telemetry-only agent)",
		"adoption_file", adoptionFile, "version", version)

	// No recovery hostname, no EEPROM artifact cleanup, no EEPROM adoption
	// fallback: all three are management concerns of the FULL agent, and two of
	// them need root this process does not have.
	parser := config.NewParserWithLogger(logger)
	adoptionConfig, err := parser.ParseAdoptionFile(adoptionFile, nil)
	if err != nil {
		logger.Error("Failed to parse adoption file", "error", err, "file", adoptionFile)
		os.Exit(1)
	}
	// Same remediation as the full agent: the credential in this file
	// authenticates the node's stream, so it must not be world-readable. Here
	// the chmod targets the watcher's own copy, which its user owns.
	parser.EnsureAdoptionFilePermissions(adoptionFile)
	parser.RedactExistingAdoptionBackup(adoptionFile)

	logger.Info("Adoption config loaded",
		"node_id", adoptionConfig.NodeID,
		"account_id", adoptionConfig.AccountID,
		"platform_url", adoptionConfig.PlatformURL,
		"grpc_endpoint", adoptionConfig.GRPCEndpoint)

	fingerprintReader := hardware.NewFingerprintReader()
	platformClient := grpc.NewPlatformClient(adoptionConfig.GRPCEndpoint, logger, version)

	// Master-token handover, same reasoning as the full agent: a watcher
	// provisioned from a master enrolment token must still shed it for the
	// node's own credential, or the shared token's expiry strands the node.
	platformClient.SetIdentityHandler(func(nodeID, accountID, uniqueToken string) {
		if !adoptionConfig.IsMasterTokenMode() {
			return
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
		updated.MasterToken = ""
		if err := parser.WriteAdoptionFile(adoptionFile, &updated); err != nil {
			logger.Error("failed to persist node identity — this node still depends on the master token", "error", err)
			return
		}
		platformClient.AdoptReconnectIdentity(parsedNode, parsedAccount, uniqueToken)
		logger.Info("node identity received and stored", "node_id", nodeID)
	})

	watcherService := service.NewWatcherService(
		adoptionConfig,
		fingerprintReader,
		platformClient,
		logger,
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigChan
		logger.Info("Received signal", "signal", sig)
		cancel()
	}()

	// No net_heal on failure: it restarts systemd-networkd, which needs root
	// and is a management action. A wedged watcher node is exactly the case
	// the watcher model accepts — the machine keeps running, the platform
	// shows it silent, and recovery is a netboot away.
	if err := watcherService.Run(ctx); err != nil {
		logger.Error("Watcher failed", "error", err)
		os.Exit(1)
	}

	logger.Info("Watcher stopped gracefully")
}
