//go:build linux

package handlers

import (
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Four downloads on the command loop used a bare http.Get, which
// uses Go's default client — and that client has no timeout of any kind.
//
// The consequence was not a slow command. ListenForCommands calls handlers
// INLINE and the same select arm dispatches web-terminal frames, so a blocked
// handler left the node ONLINE and HEARTBEATING while accepting nothing,
// including the terminal you would use to fix it. Two of the four were the
// agent's own install and update paths, i.e. the ones that break the ability to
// ship a fix.

// hangingServer accepts the request and then never answers, which is what a
// black-holed CDN looks like to the client.
func hangingServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	t.Cleanup(srv.Close)
	return srv
}

// The headline: a server that never responds must not block forever.
func TestABoundedClientGivesUpOnAServerThatNeverAnswers(t *testing.T) {
	srv := hangingServer(t)

	done := make(chan error, 1)
	go func() {
		resp, err := boundedHTTPClient(500 * time.Millisecond).Get(srv.URL)
		if resp != nil {
			resp.Body.Close()
		}
		done <- err
	}()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("a server that never answers returned success")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the request did not return — this is the hang that leaves a node " +
			"online, heartbeating and unable to accept even a terminal session")
	}
}

// The signature fetch has its own, much tighter budget: it is ~100 bytes and
// sits between downloading the agent package and trusting it.
func TestTheSignatureFetchIsBounded(t *testing.T) {
	srv := hangingServer(t)

	start := time.Now()
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = downloadSignature(srv.URL)
	}()

	select {
	case <-done:
		if elapsed := time.Since(start); elapsed > signatureTimeout+5*time.Second {
			t.Errorf("downloadSignature took %s, well past its %s budget", elapsed, signatureTimeout)
		}
	case <-time.After(signatureTimeout + 10*time.Second):
		t.Fatalf("downloadSignature did not return within %s", signatureTimeout)
	}
}

// A dial into a black hole must fail on the dial timeout rather than waiting for
// the OS to give up, which can take minutes.
func TestTheDialItselfIsBounded(t *testing.T) {
	// 203.0.113.0/24 is TEST-NET-3: routable-looking and guaranteed to go
	// nowhere, so the connection neither refuses nor completes.
	client := boundedHTTPClient(30 * time.Second)
	start := time.Now()
	resp, err := client.Get("http://203.0.113.1:9/never")
	if resp != nil {
		resp.Body.Close()
	}
	if err == nil {
		t.Fatal("a dial into a black hole reported success")
	}
	if elapsed := time.Since(start); elapsed > 25*time.Second {
		t.Errorf("the dial took %s; the 15s dial timeout is not in effect", elapsed)
	}
	var netErr net.Error
	if !isTimeout(err, &netErr) {
		t.Logf("note: failed with %v (acceptable if the network refuses outright)", err)
	}
}

func isTimeout(err error, target *net.Error) bool {
	if e, ok := err.(net.Error); ok {
		*target = e
		return e.Timeout()
	}
	if u, ok := err.(interface{ Unwrap() error }); ok {
		return isTimeout(u.Unwrap(), target)
	}
	return false
}

// The happy path must still work — a timeout that breaks ordinary downloads
// would be discovered in production.
func TestABoundedClientStillDownloadsNormally(t *testing.T) {
	body := []byte("agent package bytes")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	dst := filepath.Join(t.TempDir(), "pkg.deb")
	if err := downloadFile(srv.URL, dst); err != nil {
		t.Fatalf("downloadFile: %v", err)
	}
	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(body) {
		t.Errorf("downloaded %q, want %q", got, body)
	}
}
