//go:build linux

package handlers

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

	proto "agent/pkg/infrastructure/grpc/proto"
)

// Why these tests exist. download_file copied through
// io.LimitReader(body, 8 GiB); a longer body ended in an ordinary EOF at the
// cap and the truncated file was chmodded, renamed into place and reported
// as success. With a checksum the mismatch caught it; without one nothing
// did. The cap is lowered to something an httptest server can serve, and
// each shape is driven through the handler with and without a checksum.

func withDownloadCap(t *testing.T, cap int64) {
	t.Helper()
	prev := downloadByteCap
	downloadByteCap = cap
	t.Cleanup(func() { downloadByteCap = prev })
}

// serveBody serves body; chunked forces a transfer with no Content-Length so
// the byte count, not the advertised length, is what refuses.
func serveBody(t *testing.T, body []byte, chunked bool) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if chunked {
			w.WriteHeader(http.StatusOK)
			w.(http.Flusher).Flush()
		} else {
			w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		}
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func checksumOf(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func TestDownloadAcceptsABodyExactlyAtTheCap(t *testing.T) {
	const cap = 4096
	withDownloadCap(t, cap)
	body := bytes.Repeat([]byte("a"), cap)
	for _, tc := range []struct {
		name     string
		checksum string
		chunked  bool
	}{
		{"without checksum, advertised length", "", false},
		{"with checksum, chunked", checksumOf(body), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := serveBody(t, body, tc.chunked)
			dest := filepath.Join(t.TempDir(), "exact.bin")
			h := downloadTestHandler()
			if err := h.handleDownloadFile("cmd", &proto.DownloadFileCommand{Url: srv.URL + "/exact.bin", DestPath: dest, Checksum: tc.checksum}); err != nil {
				t.Fatalf("a body exactly at the cap was refused: %v", err)
			}
			got, err := os.ReadFile(dest)
			if err != nil || len(got) != cap {
				t.Fatalf("published %d bytes (%v), want %d", len(got), err, cap)
			}
		})
	}
}

func TestDownloadRefusesABodyPastTheCapBeforePublication(t *testing.T) {
	const cap = 4096
	withDownloadCap(t, cap)
	body := bytes.Repeat([]byte("b"), cap+1)
	for _, tc := range []struct {
		name     string
		checksum string
		chunked  bool
	}{
		{"without checksum, chunked (the silent truncation)", "", true},
		{"with a checksum of the whole body, chunked", checksumOf(body), true},
		{"without checksum, advertised length past the cap", "", false},
		{"with checksum, advertised length past the cap", checksumOf(body), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := serveBody(t, body, tc.chunked)
			dir := t.TempDir()
			dest := filepath.Join(dir, "big.bin")
			if err := os.WriteFile(dest, []byte("previous contents"), 0o644); err != nil {
				t.Fatal(err)
			}
			h := downloadTestHandler()
			err := h.handleDownloadFile("cmd", &proto.DownloadFileCommand{Url: srv.URL + "/big.bin", DestPath: dest, Checksum: tc.checksum})
			if err == nil {
				t.Fatal("a body past the cap was published as a complete download")
			}
			if !errors.Is(err, errDownloadTooLarge) {
				t.Fatalf("the refusal is not the size error: %v", err)
			}
			got, rerr := os.ReadFile(dest)
			if rerr != nil || string(got) != "previous contents" {
				t.Fatalf("the previous destination was touched: %q, %v", got, rerr)
			}
			entries, _ := os.ReadDir(dir)
			for _, e := range entries {
				if strings.HasPrefix(e.Name(), ".orchestrator-") {
					t.Fatalf("staging temp %s was left behind", e.Name())
				}
			}
		})
	}
}

// recordingPlatformClient keeps what the handler reported, for the tests that
// assert on the report rather than on the filesystem.
type recordingPlatformClient struct {
	silentPlatformClient
	mu      sync.Mutex
	details []string
}

func (r *recordingPlatformClient) SendCommandStatusWithResult(_, _, _, _, _ string, _ int32, details string, _ map[string]string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.details = append(r.details, details)
	return nil
}

func (r *recordingPlatformClient) SendCommandStatus(_, _, _, _, _ string, _ int32, details string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.details = append(r.details, details)
	return nil
}

// The transport-failure path: the handler used to return a raw
// *url.Error quoting the whole URL, which the dispatcher logged as is. This
// captures the returned error, the logger output and the status report for a
// URL carrying both userinfo and a query credential.
func TestDownloadTransportFailureDoesNotLeakTheCredential(t *testing.T) {
	var logBuf bytes.Buffer
	rec := &recordingPlatformClient{}
	h := NewCommandHandler(slog.New(slog.NewTextHandler(&logBuf, nil)), rec, "node", "account", "token")
	// Port 1 on loopback: refused at once, a *url.Error around the dial error.
	url := "http://deploy:hunter2@127.0.0.1:1/pkg.tar?token=s3cr3t"
	err := h.handleDownloadFile("cmd", &proto.DownloadFileCommand{Url: url, DestPath: filepath.Join(t.TempDir(), "pkg.tar")})
	if err == nil {
		t.Fatal("expected the download to fail")
	}
	// What the dispatcher logs is the returned error; log it the way it does.
	dispatcherLog := slog.New(slog.NewTextHandler(&logBuf, nil))
	dispatcherLog.Error("command handler failed", "command_id", "cmd", "error", err)
	rec.mu.Lock()
	reported := strings.Join(rec.details, "\n")
	rec.mu.Unlock()
	for _, secret := range []string{"hunter2", "deploy:", "s3cr3t"} {
		if strings.Contains(err.Error(), secret) {
			t.Fatalf("%q in the returned error: %v", secret, err)
		}
		if strings.Contains(logBuf.String(), secret) {
			t.Fatalf("%q reached the log: %s", secret, logBuf.String())
		}
		if strings.Contains(reported, secret) {
			t.Fatalf("%q reached the status report: %s", secret, reported)
		}
	}
	if !strings.Contains(err.Error(), "127.0.0.1:1/pkg.tar") {
		t.Fatalf("the target was lost from the error: %v", err)
	}
}
