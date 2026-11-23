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

// /etc/hosts is a line-oriented file: the 127.0.1.1 line ends in a newline
// like every other, whether it is replaced or appended, and a file whose last
// line had no newline gains one before ours rather than having the two run
// together. Applying the same hostname again changes nothing.
func TestEtcHostsHostnameLineEndsInANewlineAndIsIdempotent(t *testing.T) {
	for _, tc := range []struct{ name, in, want string }{
		{"appended", "127.0.0.1\tlocalhost\n", "127.0.0.1\tlocalhost\n127.0.1.1\tnode-a\n"},
		{"no final newline before ours", "127.0.0.1\tlocalhost", "127.0.0.1\tlocalhost\n127.0.1.1\tnode-a\n"},
		{"replaced", "127.0.0.1\tlocalhost\n127.0.1.1\told\n::1\tlocalhost\n", "127.0.0.1\tlocalhost\n127.0.1.1\tnode-a\n::1\tlocalhost\n"},
		{"replaced as the last line without a newline", "127.0.0.1\tlocalhost\n127.0.1.1 old", "127.0.0.1\tlocalhost\n127.0.1.1\tnode-a\n"},
		{"empty file", "", "127.0.1.1\tnode-a\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := etcHostsWithHostname(tc.in, "node-a")
			if got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
			if again := etcHostsWithHostname(got, "node-a"); again != got {
				t.Fatalf("a second apply changed the file: %q -> %q", got, again)
			}
		})
	}
}
