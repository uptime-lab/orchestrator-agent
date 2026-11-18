package handlers

import (
	"strings"
	"testing"
	"time"

	proto "agent/pkg/infrastructure/grpc/proto"
)

func fullWatchdogCommand() *proto.ApplyWatchdogConfigCommand {
	return &proto.ApplyWatchdogConfigCommand{
		ConfigHash:         "abc123",
		Enabled:            true,
		OsHang:             true,
		WatchdogTimeoutSec: 15,
		Network:            true,
		PingTargets:        []string{"10.0.0.1", "10.0.0.2"},
		PingCount:          3,
		Interface:          "eth0",
		AgentHealth:        true,
		AgentChangeSec:     300,
		MaxLoad_1:          24,
		MaxLoad_5:          18,
		MaxLoad_15:         12,
		MinMemoryPages:     1024,
		MaxTemperatureC:    85,
		IntervalSec:        10,
		RetryTimeoutSec:    60,
		VerifyBeforeArm:    true,
	}
}

func TestRenderWatchdogConfFull(t *testing.T) {
	got := renderWatchdogConf(fullWatchdogCommand(), "/sys/class/thermal/thermal_zone0/temp")
	want := `# Managed by orchestrator — apply_watchdog_config (config abc123)
# Manual edits are overwritten on the next apply.

watchdog-device = /dev/watchdog
watchdog-timeout = 15
ping = 10.0.0.1
ping = 10.0.0.2
ping-count = 3
interface = eth0
file = /run/orchestrator-agent/alive
change = 300
max-load-1 = 24
max-load-5 = 18
max-load-15 = 12
min-memory = 1024
max-temperature = 85
temperature-sensor = /sys/class/thermal/thermal_zone0/temp
interval = 10
retry-timeout = 60
log-dir = /var/log/watchdog
realtime = yes
priority = 1
`
	if got != want {
		t.Errorf("rendered conf mismatch:\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
}

func TestRenderWatchdogConfMinimalAgentHealth(t *testing.T) {
	cmd := &proto.ApplyWatchdogConfigCommand{
		ConfigHash:  "h1",
		Enabled:     true,
		AgentHealth: true,
		// zero change/interval/retry: defaults must fill in
	}
	got := renderWatchdogConf(cmd, "")
	for _, want := range []string{
		"file = /run/orchestrator-agent/alive\n",
		"change = 300\n",
		"interval = 10\n",
		"retry-timeout = 60\n",
		"log-dir = /var/log/watchdog\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("expected %q in rendered conf:\n%s", want, got)
		}
	}
	for _, absent := range []string{"watchdog-device", "ping", "max-load", "min-memory", "temperature"} {
		if strings.Contains(got, absent) {
			t.Errorf("did not expect %q in rendered conf:\n%s", absent, got)
		}
	}
}

func TestRenderWatchdogConfClampsHardwareTimeout(t *testing.T) {
	cmd := &proto.ApplyWatchdogConfigCommand{Enabled: true, OsHang: true, WatchdogTimeoutSec: 120}
	got := renderWatchdogConf(cmd, "")
	if !strings.Contains(got, "watchdog-timeout = 15\n") {
		t.Errorf("120s timeout must clamp to the bcm2835 15s cap:\n%s", got)
	}
}

func TestRenderWatchdogConfNoSensorPath(t *testing.T) {
	cmd := &proto.ApplyWatchdogConfigCommand{Enabled: true, MaxTemperatureC: 80}
	got := renderWatchdogConf(cmd, "")
	if strings.Contains(got, "temperature-sensor") {
		t.Errorf("no sensor path must omit the temperature-sensor directive:\n%s", got)
	}
	if !strings.Contains(got, "max-temperature = 80\n") {
		t.Errorf("max-temperature must still render:\n%s", got)
	}
}

func TestRenderedPingCountParity(t *testing.T) {
	// The pre-arm probe uses renderedPingCount so the check is exactly as
	// strict as the armed daemon.
	cases := []struct {
		in   int32
		want int32
	}{{0, 3}, {1, 1}, {5, 5}, {50, 10}}
	for _, c := range cases {
		if got := renderedPingCount(&proto.ApplyWatchdogConfigCommand{PingCount: c.in}); got != c.want {
			t.Errorf("renderedPingCount(%d) = %d, want %d", c.in, got, c.want)
		}
	}
}

func TestAdvanceBreakerSameBootNeverCounts(t *testing.T) {
	st := &watchdogState{ConfigHash: "h", BootID: "boot-1", BootCount: 2}
	trip, changed := advanceBreaker(st, "boot-1", time.Minute)
	if trip || changed {
		t.Fatalf("agent restart in the same boot must not advance the breaker (trip=%v changed=%v)", trip, changed)
	}
	if st.BootCount != 2 {
		t.Fatalf("boot count changed: %d", st.BootCount)
	}
}

func TestAdvanceBreakerCountsRapidReboots(t *testing.T) {
	st := &watchdogState{ConfigHash: "h", BootID: "boot-0"}
	for i, boot := range []string{"boot-1", "boot-2"} {
		trip, changed := advanceBreaker(st, boot, time.Minute)
		if trip {
			t.Fatalf("reboot %d must not trip yet", i+1)
		}
		if !changed {
			t.Fatalf("reboot %d must persist state", i+1)
		}
	}
	trip, _ := advanceBreaker(st, "boot-3", time.Minute)
	if !trip {
		t.Fatalf("third rapid reboot must trip the breaker (count=%d)", st.BootCount)
	}
	if st.BootCount != watchdogBreakerLimit {
		t.Fatalf("boot count = %d, want %d", st.BootCount, watchdogBreakerLimit)
	}
}

func TestAdvanceBreakerLongUptimeResets(t *testing.T) {
	st := &watchdogState{ConfigHash: "h", BootID: "boot-1", BootCount: 2}
	trip, changed := advanceBreaker(st, "boot-2", 40*time.Minute)
	if trip {
		t.Fatal("a boot past the reset window must not trip")
	}
	if !changed || st.BootCount != 0 || st.BootID != "boot-2" {
		t.Fatalf("healthy boot must reset the counter: %+v", st)
	}
}

func TestAdvanceBreakerDisarmedIsInert(t *testing.T) {
	st := &watchdogState{ConfigHash: "h", Disarmed: true, BootID: "boot-1"}
	trip, changed := advanceBreaker(st, "boot-2", time.Minute)
	if trip || changed {
		t.Fatal("a disarmed breaker must not advance")
	}
}

func TestAdvanceBreakerEmptyBootIDStillCounts(t *testing.T) {
	// Unreadable boot_id is treated as a new boot: conservative toward
	// disarming rather than letting a loop run uncounted.
	st := &watchdogState{ConfigHash: "h", BootID: ""}
	_, changed := advanceBreaker(st, "", time.Minute)
	if !changed || st.BootCount != 1 {
		t.Fatalf("empty boot_id must still count: %+v", st)
	}
}

func TestWatchdogStateRoundTrip(t *testing.T) {
	in := &watchdogState{
		ConfigHash:   "hash",
		BootID:       "boot-7",
		BootCount:    2,
		Disarmed:     true,
		DisarmReason: "the node rebooted 3 times with the watchdog armed",
	}
	data, err := in.marshal()
	if err != nil {
		t.Fatal(err)
	}
	out, err := parseWatchdogState(data)
	if err != nil {
		t.Fatal(err)
	}
	if *out != *in {
		t.Fatalf("round trip mismatch: %+v != %+v", out, in)
	}
}

func TestBuildWatchdogDropIn(t *testing.T) {
	got := buildWatchdogDropIn("/usr/bin/orchestrator-agent")
	want := "[Unit]\n" +
		"After=network-online.target orchestrator-agent.service\n" +
		"Wants=network-online.target\n\n" +
		"[Service]\n" +
		"ExecStartPre=/usr/bin/orchestrator-agent watchdog-gate\n"
	if got != want {
		t.Errorf("drop-in mismatch:\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
	if strings.Contains(got, "ExecStartPre=-") {
		t.Error("the gate must not use the failure-ignoring '-' prefix — its failure is the whole point")
	}
}

func TestClamp32(t *testing.T) {
	cases := []struct {
		v, min, max, fallback, want int32
	}{
		{0, 5, 15, 15, 15},
		{-3, 5, 15, 15, 15},
		{3, 5, 15, 15, 5},
		{10, 5, 15, 15, 10},
		{99, 5, 15, 15, 15},
	}
	for _, c := range cases {
		if got := clamp32(c.v, c.min, c.max, c.fallback); got != c.want {
			t.Errorf("clamp32(%d,%d,%d,%d) = %d, want %d", c.v, c.min, c.max, c.fallback, got, c.want)
		}
	}
}

func TestConfSHA256Stability(t *testing.T) {
	a := confSHA256("interval = 10\n")
	b := confSHA256("interval = 10\n")
	c := confSHA256("interval = 11\n")
	if a != b || a == c || len(a) != 64 {
		t.Fatalf("sha256 helper misbehaves: %s %s %s", a, b, c)
	}
}

func TestBreakerDisarmedSeparatesThePlatformFromTheBreaker(t *testing.T) {
	// One flag used to carry two entirely different events: the local breaker
	// catching a reboot loop, and the platform simply asking for the watchdog to
	// be switched off. The platform then reported its own command back to itself
	// as the device's safety breaker firing — a red fleet pill for a routine
	// action, on every agent start.
	breaker := &watchdogState{Disarmed: true, DisarmReason: "the node rebooted 3 times with the watchdog armed", DisarmSource: DisarmSourceBreaker}
	if !breaker.BreakerDisarmed() {
		t.Error("a breaker trip must read as a breaker trip")
	}

	platform := &watchdogState{Disarmed: true, DisarmReason: "disabled by the platform", DisarmSource: DisarmSourcePlatform}
	if platform.BreakerDisarmed() {
		t.Error("a platform-requested disable is not a breaker trip")
	}

	// A state file written before the field existed. Conservative on purpose: an
	// unexplained disarm deserves attention, and every fielded device keeps
	// behaving exactly as it does today.
	legacy := &watchdogState{Disarmed: true, DisarmReason: "something"}
	if !legacy.BreakerDisarmed() {
		t.Error("an unknown source must read as the breaker, not as the platform")
	}

	armed := &watchdogState{Disarmed: false, DisarmSource: DisarmSourceBreaker}
	if armed.BreakerDisarmed() {
		t.Error("a node that is not disarmed has not tripped anything")
	}
}

func TestWatchdogStateRoundTripsTheDisarmSource(t *testing.T) {
	st := &watchdogState{ConfigHash: "h", Disarmed: true, DisarmReason: "r", DisarmSource: DisarmSourcePlatform}
	data, err := st.marshal()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	back, err := parseWatchdogState(data)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if back.DisarmSource != DisarmSourcePlatform || back.BreakerDisarmed() {
		t.Fatalf("source did not survive the round trip: %#v", back)
	}
}

// Every directive the renderer emits must be one somebody listed on purpose.
//
// The point is not that today's output is wrong — it is field-driven from a
// typed proto and cannot carry a foreign key. The point is that a future field
// added to that proto reaches /etc/watchdog.conf with no review step, and two
// of the daemon's directives (test-binary, repair-binary) name an executable it
// runs as root on a timer. This test fails on ANY new directive, so its author
// has to read watchdogForbiddenDirectives before shipping it.
func TestRenderedWatchdogConfEmitsOnlyKnownDirectives(t *testing.T) {
	allowed := map[string]bool{}
	for _, d := range watchdogAllowedDirectives {
		allowed[d] = true
	}
	for _, d := range watchdogForbiddenDirectives {
		if allowed[d] {
			t.Fatalf("%q is on both the allowed and the forbidden list", d)
		}
	}

	// The maximal config, plus the minimal one, so a key emitted only on the
	// "off" branch is covered too.
	for _, conf := range []string{
		renderWatchdogConf(fullWatchdogCommand(), "/sys/class/thermal/thermal_zone0/temp"),
		renderWatchdogConf(&proto.ApplyWatchdogConfigCommand{ConfigHash: "h", AgentHealth: true}, ""),
	} {
		for _, line := range strings.Split(conf, "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			key, _, found := strings.Cut(line, "=")
			if !found {
				t.Fatalf("unparseable line in rendered watchdog.conf: %q", line)
			}
			key = strings.TrimSpace(key)
			if !allowed[key] {
				t.Fatalf("rendered watchdog.conf emits %q, which nobody listed. "+
					"Add it to watchdogAllowedDirectives if it is safe — and read "+
					"watchdogForbiddenDirectives first: test-binary and repair-binary "+
					"run arbitrary root code on the reboot daemon's timer", key)
			}
		}
	}
}
