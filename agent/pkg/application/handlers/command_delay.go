package handlers

// maxCommandDelaySeconds bounds the reboot/shutdown delay the agent will
// actually sleep. The delay runs as a time.Sleep on the single command
// goroutine, so an unbounded value parks this node's command handling for as
// long as the caller asked — the node stays connected and answers nothing.
//
// The platform clamps the same value at dispatch
// (backend `node_command.MaxDelaySeconds`, also 3600). This is the agent's own
// bound rather than trust in that one: a command can reach an agent from an
// older backend, from a redelivered queue entry built before the clamp existed,
// or from a platform that is not this repository's. The two numbers are
// deliberately equal, so a value the platform allows is never refused here.
const maxCommandDelaySeconds = 3600

// clampCommandDelaySeconds bounds a delivered delay to [0, maxCommandDelaySeconds]
// and reports whether the clamp actually bound, so the caller can log it. The
// wire field is a uint32, so the only reachable excess is the upper end — but
// the conversion to int is what makes the sleep safe on any platform width.
func clampCommandDelaySeconds(v uint32) (seconds int, bound bool) {
	if v > maxCommandDelaySeconds {
		return maxCommandDelaySeconds, true
	}
	return int(v), false
}

// maxBlockTimeoutSeconds bounds the workflow blocks that wait: wait_for_file's
// poll interval and timeout, and run_script's timeout. Same reasoning as
// maxCommandDelaySeconds and the same ceiling — an hour is far above any
// legitimate step and far below "indefinitely".
//
// The platform bounds them too. The agent's own bound matters more here than
// for a reboot delay, because the wire field is an int32 the BACKEND converts
// from a float64, and that conversion is architecture-dependent: arm64
// saturates to 2147483647 (a 68-year sleep), amd64 wraps to a negative. So an
// unclamped value wedges a node behind an arm64 backend and is harmless behind
// an amd64 one — a test against one architecture does not show the failure.
const maxBlockTimeoutSeconds = 3600
