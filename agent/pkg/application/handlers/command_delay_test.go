package handlers

import "testing"

func TestClampCommandDelaySeconds(t *testing.T) {
	cases := []struct {
		name      string
		in        uint32
		wantSecs  int
		wantBound bool
	}{
		{"zero is immediate and never reported as bound", 0, 0, false},
		{"a normal staged reboot passes through", 300, 300, false},
		{"the ceiling itself is not bound", maxCommandDelaySeconds, maxCommandDelaySeconds, false},
		{"one past the ceiling binds", maxCommandDelaySeconds + 1, maxCommandDelaySeconds, true},
		// A negative delay_seconds cannot travel: the wire field is a uint32, so a
		// negative float64 wraps to a huge positive. That is the value this bound
		// exists for — an agent that slept it would answer nothing for 136 years.
		{"a wrapped negative binds rather than sleeping for years", ^uint32(0), maxCommandDelaySeconds, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			secs, bound := clampCommandDelaySeconds(tc.in)
			if secs != tc.wantSecs {
				t.Errorf("seconds = %d, want %d", secs, tc.wantSecs)
			}
			if bound != tc.wantBound {
				t.Errorf("bound = %v, want %v", bound, tc.wantBound)
			}
		})
	}
}

// The agent's bound must equal the platform's dispatch-time clamp
// (backend node_command.MaxDelaySeconds). A LOWER agent bound would silently
// shorten a delay the platform accepted and reported to the operator; a higher
// one would leave the gap this bound exists to close. The backend constant
// lives in another module, so this asserts the number itself.
func TestAgentDelayCeilingMatchesPlatformClamp(t *testing.T) {
	const platformMaxDelaySeconds = 3600
	if maxCommandDelaySeconds != platformMaxDelaySeconds {
		t.Fatalf("maxCommandDelaySeconds = %d, want %d (backend node_command.MaxDelaySeconds)",
			maxCommandDelaySeconds, platformMaxDelaySeconds)
	}
}
