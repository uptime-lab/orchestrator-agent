package grpc

import (
	"bytes"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"agent/pkg/domain/refusal"
)

// A command the agent refused (bad input, an unknown type, a policy refusal)
// is answered and expected, so the device logs it at WARN; a command that ran
// and failed stays at ERROR. Both keep the redaction of the logging boundary.
func TestACommandRefusalIsLoggedAtWarnAndAFailureAtError(t *testing.T) {
	for _, tc := range []struct {
		name  string
		err   error
		level string
	}{
		{"refusal", fmt.Errorf("manage_service: %w", refusal.Wrap(errors.New("unknown action: bogus"))), "level=WARN"},
		{"failure", errors.New("systemctl restart nginx.service failed: exit status 1"), "level=ERROR"},
		{"refusal quoting a URL", refusal.Wrap(errors.New(`Get "https://user:pw@example.invalid/x": refused`)), "level=WARN"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			c := &PlatformClient{logger: slog.New(slog.NewTextHandler(&buf, nil))}
			c.logCommandHandlerError("cmd-1", tc.err)
			out := buf.String()
			if !strings.Contains(out, tc.level) {
				t.Fatalf("logged %q, want %s", out, tc.level)
			}
			if strings.Contains(out, "pw@") {
				t.Fatalf("the logged error carries a URL credential: %q", out)
			}
		})
	}
}
