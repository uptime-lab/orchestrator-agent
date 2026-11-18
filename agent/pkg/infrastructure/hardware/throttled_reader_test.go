//go:build linux

package hardware

import "testing"

func TestParseThrottledFlags(t *testing.T) {
	cases := []struct {
		name      string
		out       string
		wantFlags uint32
		wantOK    bool
	}{
		{
			// The reading taken on the boot where the USB disk wedged:
			// under-voltage HAS occurred + throttling HAS occurred.
			name:      "sticky under-voltage and throttling",
			out:       "throttled=0x50000\n",
			wantFlags: 0x50000,
			wantOK:    true,
		},
		{
			// The same node after a proper power supply — and the reason 0 must be
			// reported rather than treated as "nothing to say".
			name:      "healthy",
			out:       "throttled=0x0\n",
			wantFlags: 0,
			wantOK:    true,
		},
		{
			name:      "live under-voltage",
			out:       "throttled=0x1\n",
			wantFlags: 0x1,
			wantOK:    true,
		},
		{
			name:      "everything set",
			out:       "throttled=0xf000f\n",
			wantFlags: 0xf000f,
			wantOK:    true,
		},
		{
			name:      "surrounding whitespace",
			out:       "  throttled=0x50000  \n\n",
			wantFlags: 0x50000,
			wantOK:    true,
		},
		{
			// A future firmware dropping the 0x prefix still reads.
			name:      "bare decimal",
			out:       "throttled=327680\n",
			wantFlags: 327680,
			wantOK:    true,
		},
		{
			name:   "unexpected output is not a reading",
			out:    "VCHI initialization failed\n",
			wantOK: false,
		},
		{
			name:   "empty is not a reading",
			out:    "",
			wantOK: false,
		},
		{
			name:   "unparseable value is not a reading",
			out:    "throttled=nonsense\n",
			wantOK: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			flags, ok := parseThrottledFlags(tc.out)
			if ok != tc.wantOK {
				t.Fatalf("parseThrottledFlags(%q) ok = %v, want %v", tc.out, ok, tc.wantOK)
			}
			if ok && flags != tc.wantFlags {
				t.Fatalf("parseThrottledFlags(%q) = 0x%x, want 0x%x", tc.out, flags, tc.wantFlags)
			}
		})
	}
}
