package handlers

import (
	"strings"
	"testing"
)

// The report travels back to the platform and is stored as plaintext details
// that anyone who can read the node can list. A hostname resolved from
// {{secrets.*}} is exactly the shape that fails this check, so the rejected
// value must not appear in the report.
func TestARejectedHostnameIsNotEchoedBackToThePlatform(t *testing.T) {
	secrets := []string{
		"S3cret-Token-Value",
		"ghp_realLookingPersonalAccessToken",
		"user:hunter2@internal",
	}
	for _, secret := range secrets {
		report := setHostnameRejection(secret)
		if report == "" {
			t.Errorf("%q was accepted as a hostname label", secret)
			continue
		}
		if strings.Contains(report, secret) {
			t.Errorf("the rejected value was echoed into the report: %q", report)
		}
	}
}

func TestSetHostnameRejectionAcceptsAnRFC1123Label(t *testing.T) {
	for _, ok := range []string{"node-01", " node-01 ", "a", strings.Repeat("a", 63)} {
		if report := setHostnameRejection(ok); report != "" {
			t.Errorf("valid label %q was rejected: %s", ok, report)
		}
	}
	for _, bad := range []string{"", "-lead", "trail-", "UPPER", "has space", "a.b", strings.Repeat("a", 64)} {
		if setHostnameRejection(bad) == "" {
			t.Errorf("invalid label %q was accepted", bad)
		}
	}
}
