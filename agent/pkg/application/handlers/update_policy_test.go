package handlers

import (
	"strings"
	"testing"
)

func TestCheckUpdatePolicy(t *testing.T) {
	cases := []struct {
		name           string
		running        string
		requested      string
		declared       string
		allowDowngrade bool
		wantErr        string // substring; "" = allowed
	}{
		{name: "upgrade allowed", running: "0.2.22", requested: "0.2.23", declared: "0.2.23"},
		{name: "same version reinstall allowed", running: "0.2.22", requested: "0.2.22", declared: "0.2.22"},
		{name: "latest resolving to newer allowed", running: "0.2.22", requested: "latest", declared: "0.2.23"},
		{name: "downgrade refused", running: "0.2.22", requested: "0.2.21", declared: "0.2.21", wantErr: "refusing rollback"},
		{name: "downgrade via latest refused", running: "0.2.22", requested: "latest", declared: "0.2.21", wantErr: "refusing rollback"},
		{name: "downgrade with override allowed", running: "0.2.22", requested: "0.2.21", declared: "0.2.21", allowDowngrade: true},
		{name: "declared/requested mismatch refused even with override", running: "0.2.22", requested: "0.2.23", declared: "0.2.21", allowDowngrade: true, wantErr: "different artifact"},
		{name: "declared numeric vs requested v-prefix equal", running: "0.2.22", requested: "v0.2.23", declared: "0.2.23"},
		{name: "dev build has no floor", running: "0.0.0", requested: "0.1.0", declared: "0.1.0"},
		{name: "rpm without declared: concrete floor from requested", running: "0.2.22", requested: "0.2.21", declared: "", wantErr: "refusing rollback"},
		{name: "rpm without declared: latest cannot be checked", running: "0.2.22", requested: "latest", declared: ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := checkUpdatePolicy(tc.running, tc.requested, tc.declared, tc.allowDowngrade)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("expected allowed, got %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("expected error containing %q, got %v", tc.wantErr, err)
			}
		})
	}
}

// Updating to the version that is already running is a no-op: no reinstall,
// no restart that abandons the commands queued behind it.
func TestAlreadyRunning(t *testing.T) {
	cases := []struct {
		name            string
		running, target string
		force           bool
		want            bool
	}{
		{"same version", "0.8.1", "0.8.1", false, true},
		{"same version, v prefix", "0.8.1", "v0.8.1", false, true},
		{"newer", "0.8.1", "0.8.2", false, false},
		{"older", "0.8.1", "0.8.0", false, false},
		{"pre-release of the same number is another build", "0.8.1-rc1", "0.8.1", false, false},
		{"latest is judged after download", "0.8.1", "latest", false, false},
		{"dev build always installs", "0.0.0", "0.0.0", false, false},
		{"unknown running version always installs", "", "0.8.1", false, false},
		{"explicit override reinstalls", "0.8.1", "0.8.1", true, false},
		{"path-like garbage is not the running version", "0.8.1", "../../0.8.1", false, false},
	}
	for _, tc := range cases {
		if got := alreadyRunning(tc.running, tc.target, tc.force); got != tc.want {
			t.Errorf("%s: alreadyRunning(%q, %q, %v) = %v, want %v", tc.name, tc.running, tc.target, tc.force, got, tc.want)
		}
	}
}
