package main

import (
	"io"
	"log/slog"
	"testing"
	"time"
)

// fakeSystem is a scripted host. Every field is the answer to one probe, so a
// table row reads as a description of a machine.
type fakeSystem struct {
	systemd      bool
	uptime       time.Duration
	uptimeKnown  bool
	units        map[string]string
	defaultRoute bool
	// routeAfterHeal is what HasDefaultRoute returns once Run has been called, so
	// a test can express "the heal worked" or "the heal did nothing".
	routeAfterHeal bool
	ran            [][]string
	runErr         error
	windowTaken    bool
	windowRefused  bool
}

func (f *fakeSystem) ClaimHealWindow(*slog.Logger) bool {
	if f.windowRefused {
		return false
	}
	f.windowTaken = true
	return true
}

func (f *fakeSystem) HasSystemd() bool { return f.systemd }

func (f *fakeSystem) Uptime() (time.Duration, bool) { return f.uptime, f.uptimeKnown }

func (f *fakeSystem) UnitState(unit string) string {
	if state, ok := f.units[unit]; ok {
		return state
	}
	return "unknown"
}

func (f *fakeSystem) HasDefaultRoute() bool {
	if len(f.ran) > 0 {
		return f.routeAfterHeal
	}
	return f.defaultRoute
}

func (f *fakeSystem) Run(name string, args ...string) error {
	f.ran = append(f.ran, append([]string{name}, args...))
	return f.runErr
}

// wedged is the machine this whole mechanism exists for: booted long ago, systemd
// present, networkd down, no route anywhere.
func wedged() *fakeSystem {
	return &fakeSystem{
		systemd:     true,
		uptime:      10 * time.Minute,
		uptimeKnown: true,
		units: map[string]string{
			networkdUnit:       "inactive",
			networkManagerUnit: "unknown",
		},
		defaultRoute:   false,
		routeAfterHeal: true,
	}
}

func TestShouldHealNetwork(t *testing.T) {
	cases := []struct {
		name string
		sys  func() *fakeSystem
		want bool
	}{
		{
			name: "wedged host is healed",
			sys:  wedged,
			want: true,
		},
		{
			name: "failed unit is healed too (reset-failed exists for this)",
			sys: func() *fakeSystem {
				s := wedged()
				s.units[networkdUnit] = "failed"
				return s
			},
			want: true,
		},
		{
			// The old trigger's blind spot, and the reason this file was rewritten:
			// with a hostname the failure surfaces as a DNS error, not a routing error. The
			// decision no longer looks at the error at all, so the same host is
			// healed regardless of how the transport phrased its complaint.
			name: "healed regardless of how the connection failed",
			sys:  wedged,
			want: true,
		},
		{
			name: "netboot bootstrap has no systemd",
			sys: func() *fakeSystem {
				s := wedged()
				s.systemd = false
				return s
			},
			want: false,
		},
		{
			name: "early boot: DHCP may still be in flight",
			sys: func() *fakeSystem {
				s := wedged()
				s.uptime = 20 * time.Second
				return s
			},
			want: false,
		},
		{
			name: "NetworkManager owns the network",
			sys: func() *fakeSystem {
				s := wedged()
				s.units[networkManagerUnit] = "active"
				return s
			},
			want: false,
		},
		{
			// A healthy node during a platform outage. Healing here would restart
			// the network of every node in the fleet, every few minutes, for the
			// duration of the outage.
			name: "platform down but host can route",
			sys: func() *fakeSystem {
				s := wedged()
				s.defaultRoute = true
				return s
			},
			want: false,
		},
		{
			name: "networkd already running",
			sys: func() *fakeSystem {
				s := wedged()
				s.units[networkdUnit] = "active"
				return s
			},
			want: false,
		},
		{
			name: "image without systemd-networkd",
			sys: func() *fakeSystem {
				s := wedged()
				s.units[networkdUnit] = "not-found"
				return s
			},
			want: false,
		},
		{
			name: "unknown uptime does not block healing",
			sys: func() *fakeSystem {
				s := wedged()
				s.uptimeKnown = false
				s.uptime = 0
				return s
			},
			want: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := shouldHealNetwork(tc.sys())
			if got.Heal != tc.want {
				t.Fatalf("Heal = %v (reason %q), want %v", got.Heal, got.Reason, tc.want)
			}
			if got.Reason == "" {
				t.Error("decision carries no reason; the log line would say nothing useful")
			}
		})
	}
}

func TestHealNetworkIfWedged_UsesResetFailedThenStart(t *testing.T) {
	sys := wedged()
	healNetworkIfWedged(sys, discardLogger())

	if len(sys.ran) != 2 {
		t.Fatalf("ran %d commands, want 2: %v", len(sys.ran), sys.ran)
	}
	// Order matters: a unit parked in `failed` refuses a bare start.
	assertCommand(t, sys.ran[0], "systemctl", "reset-failed", networkdUnit)
	// `start`, never `restart` — restart would kill an in-flight DHCP on a host
	// that turned out to be merely slow.
	assertCommand(t, sys.ran[1], "systemctl", "start", networkdUnit)
}

func TestHealNetworkIfWedged_DoesNothingOnHealthyHost(t *testing.T) {
	sys := wedged()
	sys.defaultRoute = true

	healNetworkIfWedged(sys, discardLogger())

	if len(sys.ran) != 0 {
		t.Fatalf("touched the network of a healthy host: %v", sys.ran)
	}
}

func TestHealNetworkIfWedged_SurvivesStartFailure(t *testing.T) {
	sys := wedged()
	sys.runErr = errFakeStart

	// Must return rather than panic or hang; the caller exits straight after.
	healNetworkIfWedged(sys, discardLogger())
}

// The rate limit is fail-closed: when the marker cannot be written the heal is
// skipped rather than run unthrottled. Unthrottled means once every 10s, the
// unit's RestartSec — a hostile amount of interface churn.
func TestHealNetworkIfWedged_RespectsRateLimit(t *testing.T) {
	sys := wedged()
	sys.windowRefused = true

	healNetworkIfWedged(sys, discardLogger())

	if len(sys.ran) != 0 {
		t.Fatalf("healed despite a closed rate-limit window: %v", sys.ran)
	}
}

// The window must only be consumed when the heal actually runs, or a healthy
// node during a platform outage would burn it every 10s for nothing.
func TestHealNetworkIfWedged_DoesNotClaimWindowWhenNotHealing(t *testing.T) {
	sys := wedged()
	sys.defaultRoute = true

	healNetworkIfWedged(sys, discardLogger())

	if sys.windowTaken {
		t.Fatal("consumed the rate-limit window without healing")
	}
}

func assertCommand(t *testing.T, got []string, want ...string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("command %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("command %v, want %v", got, want)
		}
	}
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

var errFakeStart = &commandError{err: errStub{}, output: "Failed to start systemd-networkd.service"}

type errStub struct{}

func (errStub) Error() string { return "exit status 1" }
