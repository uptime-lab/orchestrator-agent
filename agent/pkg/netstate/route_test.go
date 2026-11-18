package netstate

import (
	"strings"
	"testing"
)

// Real /proc/net/route output. The columns are Iface Destination Gateway Flags
// RefCnt Use Metric Mask MTU Window IRTT — so Destination is field 1 and Mask is
// field 7, and getting either index wrong silently inverts the whole decision.
const (
	routeV4Header = "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n"

	// eth0 with a default route via 192.0.2.1, plus its on-link subnet.
	routeV4Healthy = routeV4Header +
		"eth0\t00000000\t010200C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n" +
		"eth0\t000200C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0\n"

	// The wedge: an on-link route exists (or docker0's does) but nothing default.
	routeV4NoDefault = routeV4Header +
		"eth0\t000200C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0\n"

	// A Docker host with NO default route. docker0 carries a global unicast
	// address, which is exactly why the address-based test this replaced would
	// have called such a host healthy.
	routeV4DockerOnly = routeV4Header +
		"docker0\t000011AC\t00000000\t0001\t0\t0\t0\t0000FFFF\t0\t0\t0\n"
)

func TestParseDefaultRouteV4(t *testing.T) {
	cases := []struct {
		name      string
		table     string
		wantRoute bool
		wantOK    bool
	}{
		{"default route present", routeV4Healthy, true, true},
		{"on-link only, no default", routeV4NoDefault, false, true},
		{"docker bridge only, no default", routeV4DockerOnly, false, true},
		{"header only", routeV4Header, false, true},
		// An empty file is not "no route" — it is a table we could not read, and
		// the two must not be conflated: the caller treats unreadable as healthy.
		{"empty file is unreadable, not routeless", "", false, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			route, ok := parseDefaultRouteV4(strings.NewReader(tc.table))
			if route != tc.wantRoute || ok != tc.wantOK {
				t.Fatalf("got (route=%v, ok=%v), want (route=%v, ok=%v)", route, ok, tc.wantRoute, tc.wantOK)
			}
		})
	}
}

func TestParseDefaultRouteV6(t *testing.T) {
	// /proc/net/ipv6_route columns: dest destPrefixLen src srcPrefixLen nexthop
	// metric refcnt use flags iface. Prefix length is field 1 as two hex digits.
	const (
		defaultViaEth0 = "00000000000000000000000000000000 00 " +
			"00000000000000000000000000000000 00 " +
			"fe800000000000000000000000000001 00000400 00000001 00000000 00000003 eth0\n"
		// The kernel's own ::/0 placeholder, on lo. Counting it would report a
		// route on a host that has none.
		unreachablePlaceholderOnLo = "00000000000000000000000000000000 00 " +
			"00000000000000000000000000000000 00 " +
			"00000000000000000000000000000000 ffffffff 00000001 00000000 00200200 lo\n"
		linkLocalOnly = "fe800000000000000000000000000000 40 " +
			"00000000000000000000000000000000 00 " +
			"00000000000000000000000000000000 00000100 00000000 00000001 00000001 eth0\n"
	)

	cases := []struct {
		name      string
		table     string
		wantRoute bool
	}{
		{"default route via eth0", defaultViaEth0, true},
		{"only the lo placeholder", unreachablePlaceholderOnLo, false},
		{"link-local only (the wedged node's state)", linkLocalOnly, false},
		{"placeholder plus a real route", unreachablePlaceholderOnLo + defaultViaEth0, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			route, ok := parseDefaultRouteV6(tc.table)
			if !ok {
				t.Fatal("a parseable table reported itself unreadable")
			}
			if route != tc.wantRoute {
				t.Fatalf("route = %v, want %v", route, tc.wantRoute)
			}
		})
	}
}

// The fail-safe direction is load-bearing: every caller uses this to decide
// whether to take a corrective action, so an unclassifiable host must look
// healthy. On a dev machine neither /proc table exists, which is that case.
func TestHasDefaultRouteFailsSafe(t *testing.T) {
	if v4, ok := hasDefaultRouteV4(); ok && !v4 {
		t.Skip("running on a host with a readable /proc/net/route and no default route")
	}
	if !HasDefaultRoute() {
		t.Error("HasDefaultRoute must report true when the routing tables cannot be read")
	}
}
