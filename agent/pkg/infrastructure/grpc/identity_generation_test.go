package grpc

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"agent/pkg/domain/node"

	"github.com/google/uuid"
)

// Why this test exists. AdoptReconnectIdentity swapped the
// stored request under c.mu, but reconnect() copied connectionReq out WITHOUT
// the mutex and Connect republished whatever it was handed. A reconnect that
// took its snapshot before the identity handover and published after it put
// the shared enrolment token back — and every later reconnect replayed that,
// so the token's expiry stranded a device whose own credentials were already
// on disk. The reconnect below is paused between its snapshot and its
// publish, the identity is adopted meanwhile, and the client must present and
// keep the ADOPTED identity. Run under -race: the unlocked read is a data race
// as well as a logical one.

func newIdentityTestClient() *PlatformClient {
	// A port nothing listens on; the stream is asked for under an already
	// cancelled context so Connect fails before any frame is sent. What is
	// under test is the identity the client publishes, not the dial.
	return NewPlatformClient("127.0.0.1:1", slog.New(slog.NewTextHandler(io.Discard, nil)), "test")
}

func storedIdentity(c *PlatformClient) node.ConnectionRequest {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return *c.connectionReq
}

func TestReconnectDoesNotRepublishAnIdentitySupersededMidReconnect(t *testing.T) {
	c := newIdentityTestClient()
	master := node.ConnectionRequest{NodeID: uuid.New(), AccountID: uuid.New(), UniqueToken: "shared-enrolment-token", AgentKind: "full"}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	// The first Connect stores the master-token request the way the agent's
	// start-up does; it fails at the stream, which is fine.
	_ = c.Connect(ctx, "http://platform.test", master)

	snapshotTaken := make(chan struct{})
	resume := make(chan struct{})
	presented := make(chan node.ConnectionRequest, 4)
	c.reconnectHooks.afterSnapshot = func() {
		close(snapshotTaken)
		<-resume
	}
	c.reconnectHooks.beforeConnect = func(req node.ConnectionRequest) { presented <- req }

	done := make(chan error, 1)
	go func() { done <- c.reconnect(ctx) }()

	select {
	case <-snapshotTaken:
	case <-time.After(5 * time.Second):
		t.Fatal("reconnect never reached its snapshot")
	}
	adoptedNode, adoptedAccount := uuid.New(), uuid.New()
	c.AdoptReconnectIdentity(adoptedNode, adoptedAccount, "node-token")
	close(resume)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("reconnect did not return")
	}

	// The LOAD-BEARING assertion: what the paused reconnect PRESENTED to the
	// platform. It is red on the unfixed code (the snapshot was published as
	// taken). The stored-identity check after it is only a sanity check —
	// once reconnect stops republishing, the store trivially holds the
	// adopted identity.
	if got := <-presented; got.UniqueToken != "node-token" || got.NodeID != adoptedNode || got.AccountID != adoptedAccount {
		t.Fatalf("the paused reconnect presented the stale identity: token=%q node=%s", got.UniqueToken, got.NodeID)
	}
	if got := storedIdentity(c); got.UniqueToken != "node-token" {
		t.Fatalf("the reconnect republished the superseded identity: stored token=%q", got.UniqueToken)
	}

	// Every later reconnect presents the adopted identity too.
	c.reconnectHooks.afterSnapshot = nil
	for i := 0; i < 3; i++ {
		_ = c.reconnect(ctx)
		if got := <-presented; got.UniqueToken != "node-token" {
			t.Fatalf("reconnect %d presented %q", i+1, got.UniqueToken)
		}
	}
	// The non-identity fields ride along untouched.
	if got := storedIdentity(c); got.AgentKind != "full" {
		t.Fatalf("the adoption lost the request's other fields: %+v", got)
	}
}
