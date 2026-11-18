//go:build linux

package handlers

import (
	"testing"
	"time"
)

// The kernel's struct rtc_time counts years from 1900 and months from 0. Both
// off-by-ones are silent: a wrong month still produces a plausible date, which
// is exactly the kind of wrong time this keeper exists to prevent.
func TestRTCTimeRoundTrip(t *testing.T) {
	for _, want := range []time.Time{
		time.Date(2026, time.August, 17, 8, 10, 46, 0, time.UTC),
		time.Date(2000, time.January, 1, 0, 1, 3, 0, time.UTC), // what a blank DS3231 reports
		time.Date(2036, time.December, 31, 23, 59, 59, 0, time.UTC),
	} {
		rt := timeToRTCTime(want)
		if got := rtcTimeToTime(&rt); !got.Equal(want) {
			t.Fatalf("round trip: got %s want %s", got, want)
		}
	}
}

// A seed must land on the nearest second, not the one below it: truncating
// would bias every write half a second slow.
func TestTimeToRTCTimeRounds(t *testing.T) {
	rt := timeToRTCTime(time.Date(2026, time.August, 17, 8, 10, 46, 700_000_000, time.UTC))
	if got := rtcTimeToTime(&rt); got.Second() != 47 {
		t.Fatalf("expected rounding up to :47, got %s", got)
	}
}

func TestRTCNeedsSeeding(t *testing.T) {
	cases := []struct {
		drift time.Duration
		want  bool
	}{
		{0, false},
		{time.Second, false},
		{-time.Second, false},
		{5 * time.Second, true},
		{-5 * time.Second, true},
		// The measured failure: a module that has never been written reads
		// 2000-01-01 and the drift is decades.
		{26 * 365 * 24 * time.Hour, true},
	}
	for _, c := range cases {
		if got := rtcNeedsSeeding(c.drift); got != c.want {
			t.Fatalf("drift %s: got %v want %v", c.drift, got, c.want)
		}
	}
}

// An RTC kept in local time must stand the keeper down rather than have it
// write UTC into a chip the rest of the system reads as local.
func TestAdjtimeSaysLocal(t *testing.T) {
	const utc = "0.000000 1786913887 0.000000\n1786913887\nUTC\n"
	const local = "0.000000 1786913887 0.000000\n1786913887\nLOCAL\n"
	if adjtimeSaysLocal(utc) {
		t.Fatal("UTC must not read as local")
	}
	if !adjtimeSaysLocal(local) {
		t.Fatal("LOCAL must read as local")
	}
	if adjtimeSaysLocal("") {
		t.Fatal("an empty adjtime means UTC")
	}
}
