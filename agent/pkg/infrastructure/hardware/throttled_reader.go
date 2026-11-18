//go:build linux

package hardware

import (
	"context"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// detectThrottledFlags reads the SoC's power/thermal throttling bitmask via
// `vcgencmd get_throttled`. Returns (flags, true) when the device answered, and
// (0, false) when it could not — on anything that is not a Raspberry Pi, or
// where vcgencmd fails.
//
// The distinction between "0" and "could not answer" is the whole contract: a
// zeroed report would tell an operator the supply is fine on hardware that
// cannot know. The caller leaves PowerInfo absent on false.
//
// It DOES work in the recovery bootstrap — the RAM image ships
// /usr/bin/vcgencmd (measured).
// ReadThrottledFlags is detectThrottledFlags for callers outside this package —
// the freshness watch in the agent service, which polls this ONE value cheaply
// and re-reports the whole system_info only when it changes.
func (r *SystemInfoReader) ReadThrottledFlags(ctx context.Context) (uint32, bool) {
	return r.detectThrottledFlags(ctx)
}

func (r *SystemInfoReader) detectThrottledFlags(ctx context.Context) (uint32, bool) {
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(cctx, "vcgencmd", "get_throttled").Output()
	if err != nil {
		return 0, false
	}
	return parseThrottledFlags(string(out))
}

// parseThrottledFlags extracts the bitmask from `vcgencmd get_throttled` output,
// which is a single line: "throttled=0x50000". Pure, so the parsing is testable
// without the RPi binary.
func parseThrottledFlags(out string) (uint32, bool) {
	for _, line := range strings.Split(out, "\n") {
		v, ok := strings.CutPrefix(strings.TrimSpace(line), "throttled=")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		// ParseUint with base 0 honours the 0x prefix vcgencmd always writes, and
		// still reads a bare decimal if a future firmware drops it.
		n, err := strconv.ParseUint(v, 0, 32)
		if err != nil {
			return 0, false
		}
		return uint32(n), true
	}
	return 0, false
}
