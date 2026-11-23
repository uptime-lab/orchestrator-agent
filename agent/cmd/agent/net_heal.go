package main

import (
	"context"
	"log/slog"
	"os"
	"os/exec"
	"strings"
	"time"

	"agent/pkg/netstate"
)

// Self-healing for the Ubuntu 26.04 boot race that leaves a node with a carrier
// and no network manager.
//
// What the race looks like on real hardware (captured on both CM5 and Pi 4):
// systemd-networkd starts early and begins configuring eth0 from the dracut
// leftover /run/systemd/network/zzzz-dracut-default.network; a second later it is
// STOPPED and — the part that makes it unrecoverable — systemd-networkd.socket is
// deactivated and closed along with it; netplan-configure.service finishes a few
// seconds later and nothing ever starts the daemon again. On Ubuntu 26.04 networkd
// has no persistent enablement (the netplan generator manufactures one into /run
// each boot), so once the socket is gone there is no mechanism left. The node keeps
// a link at 1Gbps, never runs a DHCP client, and stays unreachable indefinitely.
//
// The durable cure is a persistent enablement symlink written into the target
// rootfs at install time — see ensureNetworkdEnabledOnRoot in the handlers package.
// This file is the backstop: for nodes installed before that shipped, and for any
// other way the network manager can end up down.
//
// DELIBERATELY NOT MATCHING THE ERROR TEXT. The previous version triggered on
// strings.Contains(err, "network is unreachable"), which matches only when the
// platform is addressed by IP. With a hostname gRPC dies
// earlier, at DNS, with `name resolver error: produced zero addresses`, so that
// version never fired at all on such an install — a node could crash-loop for
// hours with the heal present and silent. Matching more strings would not
// fix it either: grpc-go folds the cause into the status message, *status.Error
// exposes no Unwrap so errors.As onto *net.OpError / *net.DNSError fails, and
// status.Code is Unavailable for every variant. The error genuinely cannot say
// which fault this is. The host's own state can, so that is what decides.

const (
	// healMarker rate-limits healing. It lives on tmpfs so it survives the agent's
	// process restarts within a boot (systemd restarts us every 10s) but not a
	// reboot, where healing should be free to run again immediately.
	healMarker = "/run/orchestrator-agent-net-heal"
	// healInterval is the minimum gap between two heal attempts.
	healInterval = 3 * time.Minute
	// healBootGrace suppresses healing early in boot. systemd-networkd-wait-online
	// gives up after 120s and lets network-online.target activate degraded, so the
	// agent can legitimately start while a slow DHCP is still in flight. Acting
	// then would tear down a transaction that was about to succeed — and against a
	// slow DHCP server (a whole rack powering on at once is the realistic case)
	// that turns a working boot into a permanent outage.
	healBootGrace = 150 * time.Second
	// healCommandTimeout bounds every systemctl call. The fault being healed IS a
	// systemd job collision, so a job can queue behind a wedged one and block
	// forever. That matters more than it looks: this runs just before os.Exit(1),
	// so a hang leaves the process alive, systemd sees a running unit,
	// Restart=always never fires, and even the crash loop that at least kept
	// retrying stops dead.
	healCommandTimeout = 30 * time.Second

	networkdUnit       = "systemd-networkd"
	networkManagerUnit = "NetworkManager"
)

// netHealSystem is the host state the decision needs. It exists so the policy in
// shouldHealNetwork can be table-tested; realNetHealSystem is the production
// implementation.
type netHealSystem interface {
	// HasSystemd reports whether systemctl exists. The netboot recovery bootstrap
	// is a Buildroot initramfs with no systemd at all.
	HasSystemd() bool
	// Uptime is how long this boot has been running.
	Uptime() (time.Duration, bool)
	// UnitState is `systemctl is-active` output: "active", "inactive", "failed",
	// "activating", "unknown", ...
	UnitState(unit string) string
	// HasDefaultRoute reports whether the host has a default route in either
	// address family.
	//
	// Deliberately about ROUTES, not addresses. "Does any interface hold a global
	// IPv4" is the obvious test and it is wrong in both directions: a host running
	// Docker always has 172.17.0.1 on docker0 — a global unicast address on a // publication-guard: allow private-ip (Docker's documented default bridge address)
	// non-loopback interface — so the test reports "healthy" on exactly the nodes
	// most likely to be running workloads; and an IPv6-only host has no global
	// IPv4 by design, so it would heal forever, turning a platform outage into a
	// fleet-wide network restart every few minutes. A default route means traffic
	// has somewhere to go, which is the property actually at stake.
	HasDefaultRoute() bool
	// ClaimHealWindow reports whether the rate-limit window is free, taking it if
	// so. Part of the interface rather than a free function because it is host
	// state like the rest — and because a free function reading a fixed /run path
	// made the whole policy untestable off-device.
	ClaimHealWindow(logger *slog.Logger) bool
	// Run executes a command under a bounded timeout.
	Run(name string, args ...string) error
}

// healDecision is what shouldHealNetwork concluded. Kept separate from acting on
// it so the policy is testable and so the log states a reason either way.
type healDecision struct {
	Heal   bool
	Reason string
}

// shouldHealNetwork decides whether the host has lost its network manager. It is
// called on ANY platform connection failure — the error is never consulted, only
// the host.
func shouldHealNetwork(sys netHealSystem) healDecision {
	if !sys.HasSystemd() {
		return healDecision{false, "no systemd (netboot bootstrap)"}
	}
	if uptime, ok := sys.Uptime(); ok && uptime < healBootGrace {
		return healDecision{false, "within boot grace, DHCP may still be in flight"}
	}
	if state := sys.UnitState(networkManagerUnit); state == "active" || state == "activating" {
		// Starting networkd next to NetworkManager puts two DHCP clients on one
		// interface — worse than the fault being healed, and it would reproduce on
		// every boot rather than some of them.
		return healDecision{false, "NetworkManager owns the network"}
	}
	if sys.HasDefaultRoute() {
		// The host can route. Whatever failed — the platform being down, a refused
		// credential, a broken resolver — is not something a network manager
		// restart fixes, and doing it anyway would disrupt a working node.
		return healDecision{false, "host has a default route"}
	}

	switch state := sys.UnitState(networkdUnit); state {
	case "active":
		// Running, with nothing to show for it. Could be mid-DHCP past the grace
		// window; restarting would only kill the attempt.
		return healDecision{false, "systemd-networkd is already running"}
	case "not-found", "unknown":
		return healDecision{false, "systemd-networkd is not installed"}
	default:
		return healDecision{true, "no default route and systemd-networkd is " + state}
	}
}

// healNetworkIfWedged starts systemd-networkd when the host has lost its network
// manager. Rate-limited, and a no-op unless shouldHealNetwork agrees.
func healNetworkIfWedged(sys netHealSystem, logger *slog.Logger) {
	decision := shouldHealNetwork(sys)
	if !decision.Heal {
		logger.Debug("network heal not applicable", "reason", decision.Reason)
		return
	}
	if !sys.ClaimHealWindow(logger) {
		return
	}

	logger.Warn("platform unreachable and the host has no working network; starting systemd-networkd",
		"reason", decision.Reason)

	// reset-failed first: a unit parked in `failed` — where systemd's start rate
	// limiter puts it when units collide at boot, which is this very fault —
	// refuses a bare start. Without this the heal would do nothing at all while
	// still looking like it ran.
	if err := sys.Run("systemctl", "reset-failed", networkdUnit); err != nil {
		logger.Debug("reset-failed returned an error (expected when the unit is not failed)", "error", err)
	}
	// `start`, not `restart`. The fault is "not running", so start is sufficient,
	// and restart on a host that turns out to be merely slow tears down an
	// in-flight DHCP transaction.
	if err := sys.Run("systemctl", "start", networkdUnit); err != nil {
		logger.Warn("failed to start systemd-networkd", "error", err)
		return
	}

	// Verify rather than assume: whether a bare start is enough is not known in
	// advance, so log what actually happened and the next reader gets an
	// outcome instead of an intention.
	if sys.HasDefaultRoute() {
		logger.Info("network heal succeeded, host has a default route again")
		return
	}
	logger.Warn("network heal ran but the host still has no default route",
		"next_attempt_in", healInterval.String())
}

// ClaimHealWindow reports whether the rate-limit window is free, taking it if so.
//
// Fail-closed: if the marker cannot be written the window cannot be enforced, and
// healing on every agent start (every 10s, per the unit's RestartSec) would be a
// hostile amount of interface churn. A write failure therefore suppresses the heal
// rather than allowing an unthrottled one.
func (realNetHealSystem) ClaimHealWindow(logger *slog.Logger) bool {
	if info, err := os.Stat(healMarker); err == nil {
		age := time.Since(info.ModTime())
		// A Raspberry Pi has no RTC, so a timesyncd correction can step the clock
		// backwards and make age negative. Treating that as "recent" would suppress
		// healing until wall-clock caught up with the marker — the wrong direction.
		// Negative means "cannot tell": let it through.
		if age >= 0 && age < healInterval {
			logger.Debug("network heal rate-limited", "age", age.String())
			return false
		}
	}
	if err := os.WriteFile(healMarker, []byte(time.Now().UTC().Format(time.RFC3339)), 0o644); err != nil {
		logger.Warn("cannot write the net-heal marker; skipping the heal rather than running it unthrottled",
			"marker", healMarker, "error", err)
		return false
	}
	return true
}

// realNetHealSystem probes the running host.
type realNetHealSystem struct{}

func (realNetHealSystem) HasSystemd() bool {
	_, err := exec.LookPath("systemctl")
	return err == nil
}

func (realNetHealSystem) Uptime() (time.Duration, bool) {
	body, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0, false
	}
	fields := strings.Fields(string(body))
	if len(fields) == 0 {
		return 0, false
	}
	secs, err := time.ParseDuration(fields[0] + "s")
	if err != nil {
		return 0, false
	}
	return secs, true
}

func (realNetHealSystem) UnitState(unit string) string {
	ctx, cancel := context.WithTimeout(context.Background(), healCommandTimeout)
	defer cancel()
	// is-active exits non-zero for anything but "active"; the state we want is on
	// stdout either way, so the exit status is deliberately ignored.
	out, _ := exec.CommandContext(ctx, "systemctl", "is-active", unit).Output()
	state := strings.TrimSpace(string(out))
	if state == "" {
		return "unknown"
	}
	return state
}

func (realNetHealSystem) HasDefaultRoute() bool { return netstate.HasDefaultRoute() }

func (realNetHealSystem) Run(name string, args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), healCommandTimeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if err != nil {
		if trimmed := strings.TrimSpace(string(out)); trimmed != "" {
			return &commandError{err: err, output: trimmed}
		}
	}
	return err
}

// commandError carries a failed command's output alongside its exit error, so a
// log line says what systemd complained about rather than just "exit status 1".
type commandError struct {
	err    error
	output string
}

func (e *commandError) Error() string { return e.err.Error() + ": " + e.output }
func (e *commandError) Unwrap() error { return e.err }
