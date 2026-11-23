package service

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	ports "agent/pkg/application/ports/out"
	"agent/pkg/domain/node"
	proto "agent/pkg/infrastructure/grpc/proto"

	"github.com/google/uuid"
)

// fakePlatformClient counts Connect calls and fails the first failuresBeforeOK
// of them. Every other method is a stub: connect() touches none of them.
type fakePlatformClient struct {
	calls               int
	failuresBeforeOK    int
	alwaysFail          bool
	lastConnectionReq   node.ConnectionRequest
	receivedPlatformURL string
}

func (f *fakePlatformClient) Connect(_ context.Context, platformURL string, req node.ConnectionRequest) error {
	f.calls++
	f.lastConnectionReq = req
	f.receivedPlatformURL = platformURL
	if f.alwaysFail || f.calls <= f.failuresBeforeOK {
		return errors.New(`rpc error: code = Unavailable desc = name resolver error: produced zero addresses`)
	}
	return nil
}

func (f *fakePlatformClient) SendStatusUpdate(_, _, _, _, _ string) error { return nil }
func (f *fakePlatformClient) SendCommandStatus(_, _, _, _, _ string, _ int32, _ string) error {
	return nil
}
func (f *fakePlatformClient) SendCommandStatusWithResult(_, _, _, _, _ string, _ int32, _ string, _ map[string]string) error {
	return nil
}
func (f *fakePlatformClient) SendSystemInfo(_, _, _ string, _ *proto.SystemInfoUpdate) error {
	return nil
}
func (f *fakePlatformClient) SendMetrics(_, _, _ string, _ *proto.MetricsUpdate) error { return nil }
func (f *fakePlatformClient) SendFileChangedEvent(_, _, _, _, _, _ string, _ int32, _, _ string) error {
	return nil
}
func (f *fakePlatformClient) SendNodeEvent(_, _, _, _, _ string) error { return nil }

func (f *fakePlatformClient) StartHeartbeat(context.Context, string, string, string) {}
func (f *fakePlatformClient) ListenForCommands(context.Context, func(*proto.Command) error) {
}
func (f *fakePlatformClient) Close() error { return nil }

var _ ports.PlatformClient = (*fakePlatformClient)(nil)

type fakeFingerprintReader struct{ err error }

func (f fakeFingerprintReader) Harvest() (node.HardwareFingerprint, error) {
	if f.err != nil {
		return node.HardwareFingerprint{}, f.err
	}
	return node.HardwareFingerprint{MacAddress: "2c:cf:67:12:34:56", HardwareSerial: "10000000abcd0002"}, nil
}

func newTestService(pc ports.PlatformClient) *AgentService {
	return &AgentService{
		adoptionConfig: &node.AdoptionConfig{
			NodeID:       uuid.New(),
			AccountID:    uuid.New(),
			UniqueToken:  "tok",
			PlatformURL:  "https://app.example.test",
			GRPCEndpoint: "app.example.test:50051",
		},
		fingerprintReader: fakeFingerprintReader{},
		platformClient:    pc,
		logger:            slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
}

// shrinkRetries makes the retry cadence test-speed and restores it afterwards.
func shrinkRetries(t *testing.T, window time.Duration) {
	t.Helper()
	base, max, win := initialConnectBaseDelay, initialConnectMaxDelay, initialConnectWindow
	initialConnectBaseDelay = time.Millisecond
	initialConnectMaxDelay = 2 * time.Millisecond
	initialConnectWindow = window
	t.Cleanup(func() {
		initialConnectBaseDelay, initialConnectMaxDelay, initialConnectWindow = base, max, win
	})
}

// A transient failure must not take the process down; otherwise systemd
// restarts it in a loop for as long as the failure lasts.
func TestConnectWithRetry_SucceedsAfterTransientFailures(t *testing.T) {
	shrinkRetries(t, time.Minute)
	pc := &fakePlatformClient{failuresBeforeOK: 3}
	s := newTestService(pc)

	if err := s.connectWithRetry(context.Background()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pc.calls != 4 {
		t.Fatalf("Connect called %d times, want 4", pc.calls)
	}
	if !s.connectedOnce.Load() {
		t.Error("connectedOnce not recorded; the liveness gate would stay closed on a connected node")
	}
}

// The escape hatch is deliberate: exiting re-reads the adoption file and lets
// systemd recycle wedged internal state. Retrying forever would remove both.
func TestConnectWithRetry_GivesUpAfterWindow(t *testing.T) {
	shrinkRetries(t, 20*time.Millisecond)
	pc := &fakePlatformClient{alwaysFail: true}
	s := newTestService(pc)

	if err := s.connectWithRetry(context.Background()); err == nil {
		t.Fatal("expected an error so main exits and the supervisor restarts us")
	}
	if s.connectedOnce.Load() {
		t.Error("recorded a connection that never happened")
	}
	if pc.calls < 2 {
		t.Fatalf("gave up after %d attempts; it should retry within the window", pc.calls)
	}
}

func TestConnectWithRetry_StopsOnContextCancel(t *testing.T) {
	shrinkRetries(t, time.Hour)
	pc := &fakePlatformClient{alwaysFail: true}
	s := newTestService(pc)

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(10 * time.Millisecond)
		cancel()
	}()

	done := make(chan error, 1)
	go func() { done <- s.connectWithRetry(ctx) }()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected the last failure to be reported on shutdown")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("connectWithRetry ignored context cancellation")
	}
}

// A failure that is not the platform's fault must still be retried rather than
// crash-looped — but it must not be mistaken for success.
func TestConnectWithRetry_FingerprintFailureIsRetried(t *testing.T) {
	shrinkRetries(t, 20*time.Millisecond)
	pc := &fakePlatformClient{}
	s := newTestService(pc)
	s.fingerprintReader = fakeFingerprintReader{err: errors.New("no such device")}

	if err := s.connectWithRetry(context.Background()); err == nil {
		t.Fatal("expected an error")
	}
	if pc.calls != 0 {
		t.Fatalf("dialled %d times despite no fingerprint", pc.calls)
	}
}

// The liveness gate is the one that can reboot a fleet if it is wrong.
func TestLivenessShouldReport(t *testing.T) {
	cases := []struct {
		name      string
		connected bool
		routes    bool
		want      bool
	}{
		{
			// Established node. Supervision must be exactly as before.
			name: "connected and routing", connected: true, routes: true, want: true,
		},
		{
			// Connected earlier, network since lost: still report. The reconnect
			// loop owns this, and a watchdog reboot here would fight it.
			name: "connected, route since lost", connected: true, routes: false, want: true,
		},
		{
			// THE case that must not regress: a platform outage. The node is
			// healthy; withholding here would reboot every armed node in the fleet
			// for an outage the node had no part in.
			name: "never connected but host routes fine", connected: false, routes: true, want: true,
		},
		{
			// The netplan/networkd wedge. Withhold, so the watchdog reboots and
			// the boot-time dice roll is re-rolled.
			name: "never connected and no route", connected: false, routes: false, want: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			original := hasDefaultRoute
			hasDefaultRoute = func() bool { return tc.routes }
			t.Cleanup(func() { hasDefaultRoute = original })

			s := newTestService(&fakePlatformClient{})
			s.connectedOnce.Store(tc.connected)

			if got := s.livenessShouldReport(); got != tc.want {
				t.Fatalf("livenessShouldReport() = %v, want %v", got, tc.want)
			}
		})
	}
}
