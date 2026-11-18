package main

import (
	"strings"
	"testing"

	"agent/pkg/domain/node"

	"github.com/google/uuid"
)

// The exit code is the monitoring contract: one number for "no identity"
// shared with the interactive-start path, and running/not-running otherwise.
func TestStatusExitCodeContract(t *testing.T) {
	cases := []struct {
		name string
		r    statusReport
		want int
	}{
		{"identity + active service", statusReport{IdentityState: "file", ServiceState: "active"}, 0},
		{"identity + running process, no systemd", statusReport{IdentityState: "file", AgentPID: 42}, 0},
		{"eeprom identity, nothing running", statusReport{IdentityState: "eeprom", ServiceState: "inactive"}, 1},
		{"unreadable file still counts as provisioned", statusReport{IdentityState: "unreadable"}, 1},
		{"no identity at all", statusReport{IdentityState: "absent"}, exitCodeNotProvisioned},
		{"no identity but something running is still not provisioned", statusReport{IdentityState: "absent", ServiceState: "active"}, exitCodeNotProvisioned},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.r.exitCode(); got != c.want {
				t.Fatalf("exit code = %d, want %d", got, c.want)
			}
		})
	}
}

// --status exists to be pasted into a support thread, so the one property the
// render must never lose is that no credential reaches the output.
func TestStatusOutputCarriesNoToken(t *testing.T) {
	token := "very-secret-token-value"
	cfg := &node.AdoptionConfig{
		NodeID:       uuid.New(),
		UniqueToken:  token,
		AccountID:    uuid.New(),
		PlatformURL:  "https://app.example.test",
		GRPCEndpoint: "app.example.test:50051",
	}
	r := &statusReport{Version: "1.2.3", AdoptionFile: "/tmp/x", IdentityState: "file", ServiceState: "active"}
	fillIdentity(r, cfg)

	var b strings.Builder
	r.render(&b)
	out := b.String()

	if strings.Contains(out, token) {
		t.Fatalf("--status output leaked the unique token:\n%s", out)
	}
	for _, want := range []string{cfg.NodeID.String(), cfg.AccountID.String(), cfg.PlatformURL, "1.2.3", "active"} {
		if !strings.Contains(out, want) {
			t.Fatalf("--status output missing %q:\n%s", want, out)
		}
	}
}

// Master-token mode names the mode and still shows no token value.
func TestStatusMasterTokenModeIsNamedNotShown(t *testing.T) {
	token := "master-secret"
	cfg := &node.AdoptionConfig{
		MasterToken:  token,
		AccountID:    uuid.New(),
		PlatformURL:  "https://app.example.test",
		GRPCEndpoint: "app.example.test:50051",
	}
	r := &statusReport{Version: "1.2.3", AdoptionFile: "/tmp/x", IdentityState: "file"}
	fillIdentity(r, cfg)

	var b strings.Builder
	r.render(&b)
	out := b.String()

	if strings.Contains(out, token) {
		t.Fatalf("--status output leaked the master token:\n%s", out)
	}
	if !strings.Contains(out, "master token") {
		t.Fatalf("--status output does not name master-token mode:\n%s", out)
	}
}
