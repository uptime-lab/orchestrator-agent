package grpc

import (
	"bytes"
	"context"
	"log/slog"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	grpclib "google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"agent/pkg/domain/node"
	proto "agent/pkg/infrastructure/grpc/proto"
)

// capRefusingPlatform is a real gRPC server that refuses every handshake
// the way the platform does at its device cap: it reads the ConnectionInit,
// optionally parks, then answers ResourceExhausted with the fixed message.
type capRefusingPlatform struct {
	proto.UnimplementedNodeCommunicationServer
	dials int64
	park  time.Duration
}

func (p *capRefusingPlatform) EstablishStream(stream proto.NodeCommunication_EstablishStreamServer) error {
	if _, err := stream.Recv(); err != nil {
		return err
	}
	atomic.AddInt64(&p.dials, 1)
	if p.park > 0 {
		select {
		case <-time.After(p.park):
		case <-stream.Context().Done():
			return stream.Context().Err()
		}
	}
	return status.Error(codes.ResourceExhausted, deviceCapRefusalMessage)
}

// syncBuffer is a log sink the agent's goroutines may write concurrently.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// runAgainstDeviceCap runs the agent's whole connection machinery — Connect,
// the command listener, the heartbeat and its reconnect watchdog, the
// reconnect controller — against a platform that refuses at the cap, for
// window, and reports how many handshakes reached the platform.
func runAgainstDeviceCap(t *testing.T, window, heartbeat, hold, park time.Duration) (dials int64, logs string) {
	return runAgainstDeviceCapPoked(t, window, heartbeat, hold, park, false)
}

// runAgainstDeviceCapPoked, with poke, signals a disconnection once the
// refusal is held — what a send failing on the refused stream does.
func runAgainstDeviceCapPoked(t *testing.T, window, heartbeat, hold, park time.Duration, poke bool) (dials int64, logs string) {
	t.Helper()
	platform := &capRefusingPlatform{park: park}
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := grpclib.NewServer()
	proto.RegisterNodeCommunicationServer(srv, platform)
	go func() { _ = srv.Serve(lis) }()
	defer srv.Stop()

	sink := &syncBuffer{}
	logger := slog.New(slog.NewTextHandler(sink, &slog.HandlerOptions{Level: slog.LevelInfo}))
	ctx, cancel := context.WithTimeout(context.Background(), window)
	defer cancel()

	c := NewPlatformClient(lis.Addr().String(), logger, "test")
	c.heartbeatInterval = heartbeat
	c.deviceCapHold = func() time.Duration { return hold }
	ctrl := NewConnectionController(ctx, logger)
	c.SetConnectionController(ctrl)
	ctrl.StartReconnectionLoop(ctx)

	req := node.ConnectionRequest{NodeID: uuid.New(), AccountID: uuid.New(), UniqueToken: "tok",
		Fingerprint: node.HardwareFingerprint{MacAddress: "02:00:00:00:00:01", HardwareSerial: "10000000deadbeef"}}
	if err := c.Connect(ctx, "http://127.0.0.1", req); err != nil {
		t.Fatalf("connect: %v", err)
	}
	go c.StartHeartbeat(ctx, req.NodeID.String(), req.AccountID.String(), req.UniqueToken)
	go c.ListenForCommands(ctx, func(*proto.Command) error { return nil })

	if poke {
		for !c.inDeviceCapHold() && ctx.Err() == nil {
			time.Sleep(5 * time.Millisecond)
		}
		ctrl.SignalDisconnection()
	}

	<-ctx.Done()
	_ = c.Close()
	return atomic.LoadInt64(&platform.dials), sink.String()
}

// A device refused at the cap stops knocking: it holds for the long retry
// and does not let the heartbeat watchdog re-dial it every two heartbeats.
// Before this the watchdog nudged a reconnect after two skipped heartbeats
// (about once a minute at the 30 s cadence), each dial parked by the
// platform, forever. The process stays alive and says so ONCE at WARN.
//
// Run twice: refused at once, and refused after a park like the platform's,
// during which heartbeats are written to the stream — so a heartbeat send
// fails on the closed stream right as the refusal arrives, and that send
// failure must not start a dial either.
func TestDeviceCapRefusalHoldsInsteadOfRedialing(t *testing.T) {
	for _, park := range []time.Duration{0, 300 * time.Millisecond} {
		t.Run("park="+park.String(), func(t *testing.T) {
			dials, logs := runAgainstDeviceCap(t, 2500*time.Millisecond, 50*time.Millisecond, time.Hour, park)
			if dials != 1 {
				t.Errorf("%d handshakes reached the platform (heartbeat 50ms); want exactly 1 — the refusal must hold, not re-dial", dials)
			}
			if n := strings.Count(logs, "level=WARN msg=\"the platform refused this device"); n != 1 {
				t.Errorf("%d WARN lines for the refusal, want exactly 1:\n%s", n, logs)
			}
		})
	}
}

// A heartbeat or status send that fails on the refused stream signals a
// disconnection like any other send failure. Measured with real cadences
// (30 s heartbeat, 30 s park) the tick lands on the refusal and started a
// dial 30 s later; the reconnect itself must wait the hold out.
func TestASendFailureDuringTheHoldDoesNotDial(t *testing.T) {
	dials, _ := runAgainstDeviceCapPoked(t, 2500*time.Millisecond, 50*time.Millisecond, time.Hour, 0, true)
	if dials != 1 {
		t.Errorf("%d handshakes after a disconnection signal during the hold; want exactly 1", dials)
	}
}

// The hold ends: the device asks again on its own, so it is admitted once a
// slot frees up without anyone restarting it.
func TestDeviceCapRefusalRetriesAfterTheHold(t *testing.T) {
	dials, logs := runAgainstDeviceCap(t, 3*time.Second, 50*time.Millisecond, 300*time.Millisecond, 0)
	if dials < 2 {
		t.Errorf("%d handshakes in 3s with a 300ms hold; want the device to retry after the hold", dials)
	}
	if n := strings.Count(logs, "level=WARN msg=\"the platform refused this device"); n != 1 {
		t.Errorf("%d WARN lines across %d refusals, want exactly 1", n, dials)
	}
}

// The jitter keeps a fleet refused together from coming back together, and
// stays inside the documented band.
func TestDeviceCapHoldIsJitteredAroundFifteenMinutes(t *testing.T) {
	seen := map[time.Duration]bool{}
	for i := 0; i < 50; i++ {
		d := jitteredDeviceCapHold()
		if d < deviceCapHoldBase-deviceCapHoldJitter || d > deviceCapHoldBase+deviceCapHoldJitter {
			t.Fatalf("hold %s outside %s ± %s", d, deviceCapHoldBase, deviceCapHoldJitter)
		}
		seen[d] = true
	}
	if len(seen) < 2 {
		t.Error("the hold is not jittered")
	}
}
