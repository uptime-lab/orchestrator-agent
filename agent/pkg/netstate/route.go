// Package netstate answers one question about the host: can it route at all?
//
// It exists because two unrelated pieces of the agent need exactly that answer
// and must agree on it — the network self-heal (does this host need its network
// manager started?) and the watchdog liveness file (is this host network-dead,
// or is the platform merely down?). Getting different answers in those two places
// is how a platform outage turns into a fleet-wide reboot.
package netstate

import (
	"bufio"
	"io"
	"os"
	"strings"
)

// HasDefaultRoute reports whether the host has a default route in either address
// family.
//
// Deliberately about ROUTES, not addresses. "Does any interface hold a global
// IPv4" is the obvious test and it is wrong in both directions: a host running
// Docker always holds a global unicast address on a non-loopback interface
// (docker0 carries Docker's documented default, 172.17.0.1; publication-guard: allow private-ip),
// so the test reports "healthy" on exactly the nodes most likely to be running
// workloads; and an IPv6-only host has no global IPv4 by design, so it would
// read as broken forever. A default route means traffic
// has somewhere to go, which is the property actually at stake.
//
// Fails SAFE: when neither routing table can be read (not Linux, /proc not
// mounted, the netboot bootstrap) it reports true, because every caller uses this
// to decide whether to take a corrective action, and declining to act on a host
// we cannot classify is the harmless direction.
func HasDefaultRoute() bool {
	v4, okV4 := hasDefaultRouteV4()
	v6, okV6 := hasDefaultRouteV6()
	if !okV4 && !okV6 {
		return true
	}
	return v4 || v6
}

// hasDefaultRouteV4 parses /proc/net/route; a default route is the entry whose
// destination and mask are both zero. The second return reports whether the table
// could be read at all, which is distinct from "read it, found no route".
func hasDefaultRouteV4() (bool, bool) {
	f, err := os.Open("/proc/net/route")
	if err != nil {
		return false, false
	}
	defer f.Close()
	return parseDefaultRouteV4(f)
}

// parseDefaultRouteV4 is the field logic of hasDefaultRouteV4, split out so the
// column indices are covered by a test rather than by hope.
func parseDefaultRouteV4(r io.Reader) (bool, bool) {
	scanner := bufio.NewScanner(r)
	if !scanner.Scan() {
		return false, false // header missing: unreadable, not "no route"
	}
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 8 {
			continue
		}
		if fields[1] == "00000000" && fields[7] == "00000000" {
			return true, true
		}
	}
	return false, scanner.Err() == nil
}

// hasDefaultRouteV6 parses /proc/net/ipv6_route, where a default route has a
// destination prefix length of 0 (field 1). Entries on lo are the kernel's own
// unreachable placeholders for ::/0 and do not count.
func hasDefaultRouteV6() (bool, bool) {
	body, err := os.ReadFile("/proc/net/ipv6_route")
	if err != nil {
		return false, false
	}
	return parseDefaultRouteV6(string(body))
}

// parseDefaultRouteV6 is the field logic of hasDefaultRouteV6, split out for the
// same reason as its v4 counterpart.
func parseDefaultRouteV6(body string) (bool, bool) {
	for _, line := range strings.Split(body, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 10 {
			continue
		}
		if fields[1] != "00" || fields[9] == "lo" {
			continue
		}
		return true, true
	}
	return false, true
}
