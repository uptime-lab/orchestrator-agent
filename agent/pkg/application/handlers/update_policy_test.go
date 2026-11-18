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
