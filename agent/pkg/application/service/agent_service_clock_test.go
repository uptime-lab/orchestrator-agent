package service

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	ports "agent/pkg/application/ports/out"
	"agent/pkg/domain/node"
)

// certFailingClient fails every dial with err, as grpc-go reports a TLS
// verification failure: the x509 text folded into an Unavailable status
// message, with no typed error left to unwrap.
type certFailingClient struct {
	fakePlatformClient
	err error
}

func (c *certFailingClient) Connect(context.Context, string, node.ConnectionRequest) error {
	c.calls++
	return c.err
}

var _ ports.PlatformClient = (*certFailingClient)(nil)

func runAndCaptureLog(t *testing.T, dialErr error) string {
	t.Helper()
	shrinkRetries(t, 10*time.Millisecond)
	var buf bytes.Buffer
	s := newTestService(&certFailingClient{err: dialErr})
	s.logger = slog.New(slog.NewTextHandler(&buf, nil))
	if err := s.connectWithRetry(context.Background()); err == nil {
		t.Fatal("expected the dial to keep failing")
	}
	return buf.String()
}

// A board with no battery-backed clock dials before NTP has set the time, and
// the platform's certificate then reads "not yet valid". The retry already
// recovers it; what an operator reading the journal needs is the pointer to the
// clock, because the error alone reads like a PKI problem.
func TestConnectWithRetry_CertificateValidityFailureNamesTheClock(t *testing.T) {
	dialErr := errors.New(`rpc error: code = Unavailable desc = connection error: desc = "transport: authentication handshake failed: tls: failed to verify certificate: x509: certificate has expired or is not yet valid: current time 2026-04-01T00:00:00Z is before 2026-11-19T10:00:00Z"`)
	out := runAndCaptureLog(t, dialErr)

	if !strings.Contains(out, "clock_hint=") {
		t.Errorf("log carries no clock hint for a certificate-validity failure:\n%s", out)
	}
}

// Every other failure keeps the line it had: the hint must not appear where
// the clock has nothing to do with it.
func TestConnectWithRetry_OtherFailuresCarryNoClockHint(t *testing.T) {
	dialErr := errors.New(`rpc error: code = Unavailable desc = name resolver error: produced zero addresses`)
	out := runAndCaptureLog(t, dialErr)

	if strings.Contains(out, "clock_hint=") {
		t.Errorf("clock hint attached to an unrelated failure:\n%s", out)
	}
}
