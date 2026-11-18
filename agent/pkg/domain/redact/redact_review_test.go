package redact

import (
	"bytes"
	"errors"
	"fmt"
	"log/slog"
	neturl "net/url"
	"os"
	"strings"
	"testing"
)

// Follow-ups on the redaction helpers.

const credURL = "https://deploy:hunter2@files.example.test/pkg.tar?token=s3cr3t"

func assertNoCredential(t *testing.T, what, s string) {
	t.Helper()
	for _, secret := range []string{"hunter2", "deploy:", "s3cr3t"} {
		if strings.Contains(s, secret) {
			t.Fatalf("%s carries %q: %s", what, secret, s)
		}
	}
}

// Error flattened a multi-error (Unwrap() []error): errors.Unwrap is nil on
// it, so the rebuilt error lost every cause and errors.Is stopped answering.
func TestErrorKeepsTheCausesOfAMultiError(t *testing.T) {
	ue := &neturl.Error{Op: "Get", URL: credURL, Err: errors.New("dial tcp: i/o timeout")}
	joined := errors.Join(os.ErrNotExist, ue)
	clean := Error(joined)
	assertNoCredential(t, "the redacted multi-error", clean.Error())
	if !errors.Is(clean, os.ErrNotExist) {
		t.Fatal("errors.Is lost os.ErrNotExist through the rebuild")
	}
	var got *neturl.Error
	if !errors.As(clean, &got) || got.URL != "https://files.example.test/pkg.tar" {
		t.Fatalf("the *url.Error cause was lost or not redacted: %+v", got)
	}
	// A multi-error with nothing to hide comes back as itself.
	plain := errors.Join(os.ErrNotExist, errors.New("other"))
	if Error(plain) != plain {
		t.Fatal("a clean multi-error must come back as itself")
	}
	// And a wrapper around a multi-error keeps the whole tree.
	wrapped := fmt.Errorf("outer: %w", joined)
	if c := Error(wrapped); !errors.Is(c, os.ErrNotExist) || strings.Contains(c.Error(), "hunter2") {
		t.Fatalf("wrapper around a multi-error: %v", c)
	}
}

type stringerWithURL struct{}

func (stringerWithURL) String() string { return "target " + credURL }

// SlogAttr handled strings and errors only; a []string, a *url.URL, a
// fmt.Stringer or a []error attribute passed through with the credential.
func TestSlogAttrRedactsEveryValueShapeThatCanCarryAURL(t *testing.T) {
	u, _ := neturl.Parse(credURL)
	ue := &neturl.Error{Op: "Get", URL: credURL, Err: errors.New("refused")}
	cases := map[string]any{
		"string":   credURL,
		"error":    ue,
		"strings":  []string{"first", credURL},
		"url":      u,
		"stringer": stringerWithURL{},
		"errors":   []error{errors.New("plain"), ue},
	}
	for name, value := range cases {
		t.Run(name, func(t *testing.T) {
			var buf bytes.Buffer
			logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{ReplaceAttr: SlogAttr}))
			logger.Info("probe", name, value)
			assertNoCredential(t, "the log line for a "+name, buf.String())
			if !strings.Contains(buf.String(), "files.example.test/pkg.tar") {
				t.Fatalf("the target itself was lost: %s", buf.String())
			}
		})
	}
	// Values with nothing to hide are untouched, shape included.
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{ReplaceAttr: SlogAttr}))
	logger.Info("probe", "n", 3, "list", []string{"a", "b"}, "err", errors.New("plain"))
	for _, keep := range []string{"n=3", `list="[a b]"`, "err=plain"} {
		if !strings.Contains(buf.String(), keep) {
			t.Fatalf("%q was altered: %s", keep, buf.String())
		}
	}
}
