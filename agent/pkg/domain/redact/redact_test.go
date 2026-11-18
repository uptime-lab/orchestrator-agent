package redact

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	neturl "net/url"
	"strings"
	"testing"
)

// The URL helper kept userinfo, and a raw *url.Error returned
// from the download handler carried the whole URL to the dispatcher's log.

func TestURLDropsUserinfoQueryAndFragment(t *testing.T) {
	cases := map[string]string{
		"https://user:hunter2@files.example.test/pkg.tar":      "https://files.example.test/pkg.tar",
		"https://files.example.test/pkg.tar?token=s3cr3t#frag": "https://files.example.test/pkg.tar",
		"https://files.example.test/pkg.tar":                   "https://files.example.test/pkg.tar",
		"::not a url":                                          UnparseableURL,
	}
	for in, want := range cases {
		if got := URL(in); got != want {
			t.Errorf("URL(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestErrorRebuildsAURLErrorWithoutTheCredential(t *testing.T) {
	cause := &net.OpError{Op: "dial", Net: "tcp", Err: context.DeadlineExceeded}
	raw := &neturl.Error{Op: "Get", URL: "https://user:hunter2@files.example.test/pkg.tar?token=s3cr3t", Err: cause}
	wrapped := fmt.Errorf("failed to download: %w", raw)

	clean := Error(wrapped)
	if msg := clean.Error(); strings.Contains(msg, "hunter2") || strings.Contains(msg, "s3cr3t") {
		t.Fatalf("credential survived: %q", msg)
	}
	if !strings.Contains(clean.Error(), "failed to download") || !strings.Contains(clean.Error(), "files.example.test/pkg.tar") {
		t.Fatalf("the message lost its triage value: %q", clean.Error())
	}
	// The chain still answers the questions callers ask of it.
	if !errors.Is(clean, context.DeadlineExceeded) {
		t.Fatal("errors.Is lost the deadline sentinel through the rebuild")
	}
	var ue *neturl.Error
	if !errors.As(clean, &ue) {
		t.Fatal("errors.As no longer finds a *url.Error")
	}
	if strings.Contains(ue.URL, "hunter2") || strings.Contains(ue.URL, "s3cr3t") {
		t.Fatalf("the *url.Error reachable through errors.As still carries the credential: %q", ue.URL)
	}
	if ue.Op != "Get" || ue.URL != "https://files.example.test/pkg.tar" {
		t.Fatalf("rebuilt url.Error = %+v", ue)
	}
}

func TestErrorLeavesACleanErrorIdentical(t *testing.T) {
	sentinel := errors.New("nothing to hide here")
	if Error(sentinel) != sentinel {
		t.Fatal("an error with no URL must come back as itself")
	}
	wrapped := fmt.Errorf("context: %w", sentinel)
	if got := Error(wrapped); got != wrapped {
		t.Fatalf("a clean chain must come back as itself, got %v", got)
	}
	if Error(nil) != nil {
		t.Fatal("nil in, nil out")
	}
}

func TestSlogAttrRedactsStringsAndErrorsAtTheHandler(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{ReplaceAttr: SlogAttr}))
	raw := &neturl.Error{Op: "Get", URL: "https://user:hunter2@files.example.test/pkg.tar?token=s3cr3t", Err: errors.New("dial tcp: i/o timeout")}
	logger.Error("command handler failed", "error", fmt.Errorf("failed to download: %w", raw),
		"url", "https://user:hunter2@files.example.test/pkg.tar?token=s3cr3t",
		"count", 3, "plain", "no url here")
	out := buf.String()
	for _, secret := range []string{"hunter2", "s3cr3t"} {
		if strings.Contains(out, secret) {
			t.Fatalf("%q reached the log line: %s", secret, out)
		}
	}
	for _, keep := range []string{"files.example.test/pkg.tar", "i/o timeout", "count=3", "no url here"} {
		if !strings.Contains(out, keep) {
			t.Fatalf("%q was lost from the log line: %s", keep, out)
		}
	}
}
