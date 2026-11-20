package handlers

import (
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestRedactURLStripsTheCapability(t *testing.T) {
	// The image URL's query IS the credential: an HMAC capability good for an
	// hour. journald keeps it long past that and the node web terminal reads it
	// back, so it must never reach a log line.
	const signed = "https://app.example/cdn/acct/img.zst?exp=1784988000&sig=deadbeefcafe"

	got := redactURL(signed)
	if got != "https://app.example/cdn/acct/img.zst" {
		t.Fatalf("query survived redaction: %q", got)
	}
	for _, secret := range []string{"sig=", "deadbeef", "exp="} {
		if strings.Contains(got, secret) {
			t.Errorf("redacted URL still leaks %q: %q", secret, got)
		}
	}

	// The path must survive — it is what makes a log line useful at all.
	if !strings.Contains(got, "img.zst") {
		t.Errorf("redaction removed the identifying path: %q", got)
	}

	// A URL we cannot parse must not fall through to the original.
	if out := redactURL("://not a url"); strings.Contains(out, "not a url") {
		t.Errorf("unparseable URL was echoed back: %q", out)
	}
}

// A failed install must leave the target deliberately unbootable. The failure
// this replaces left a valid partition table over a truncated filesystem: the
// ROM happily hands control to it, the node hangs in initramfs, and recovery
// costs a site visit.
func TestInvalidateTargetDeviceDestroysEveryPartitionTable(t *testing.T) {
	const (
		deviceSize = 32 << 20 // stand-in for the block device
		imageEnd   = 20 << 20 // the image was smaller than the device
	)
	path := filepath.Join(t.TempDir(), "device.img")

	// Fill the whole "device" with a marker, so anything left untouched is
	// visible. In the real failure the head region holds a PREVIOUS install's
	// partition table, which is exactly what makes the disk look bootable.
	marker := make([]byte, deviceSize)
	for i := range marker {
		marker[i] = 0xAA
	}
	if err := os.WriteFile(path, marker, 0o600); err != nil {
		t.Fatal(err)
	}

	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	h := &CommandHandler{logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	h.invalidateTargetDevice(f, path, imageEnd)

	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	zeroed := func(name string, from, to int64) {
		t.Helper()
		for i := from; i < to; i++ {
			if after[i] != 0 {
				t.Fatalf("%s not destroyed: byte %d = %#x", name, i, after[i])
			}
		}
	}

	// 1. The head: protective MBR, primary GPT header and partition entries.
	zeroed("image head", 0, imageHeadSize)
	// 2. The backup GPT of the image just streamed. On a restore onto a larger
	//    disk this sits MID-device, and sfdisk/parted rebuild a primary from it.
	zeroed("image backup GPT", imageEnd-(1<<20), imageEnd)
	// 3. The backup GPT at the end of the device, left by whatever was there
	//    before.
	zeroed("device backup GPT", deviceSize-(1<<20), deviceSize)

	// Everything else is left alone: the point is to deny the boot chain, not
	// to spend minutes zeroing a terabyte.
	if after[imageHeadSize+1] != 0xAA {
		t.Errorf("invalidation overwrote payload it did not need to touch")
	}
}

// A device smaller than the regions we zero must not panic or corrupt what
// little is there — install_os can target an SD card far smaller than the image.
func TestInvalidateTargetDeviceToleratesATinyDevice(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tiny.img")
	if err := os.WriteFile(path, make([]byte, 512), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	h := &CommandHandler{logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	h.invalidateTargetDevice(f, path, 0) // nothing written yet
}

func TestImageDownloadClientHasNoOverallDeadline(t *testing.T) {
	// An overall deadline would turn "a multi-GB image over a busy LAN" into
	// a routine failure, and the fix for that is always to raise it until it
	// means nothing. Stalls are detected by the watchdog instead.
	if c := imageDownloadClient(); c.Timeout != 0 {
		t.Fatalf("client must not carry an overall timeout, got %s", c.Timeout)
	}
}

// connCount watches a test server's live connections.
type connCount struct {
	mu   sync.Mutex
	open int
}

func (c *connCount) state(_ net.Conn, st http.ConnState) {
	c.mu.Lock()
	defer c.mu.Unlock()
	switch st {
	case http.StateNew:
		c.open++
	case http.StateClosed:
		c.open--
	}
}

func (c *connCount) get() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.open
}

// Why this test exists. Every one-shot client the agent built
// carried its own http.Transport with keep-alive on and nothing to ever drain
// its idle pool: the connection a response came back on stayed parked until
// the peer hung up or the agent restarted, one socket and one goroutine per
// completed download, signature fetch or EEPROM manifest read.
func TestOneShotClientsDoNotAccumulateConnections(t *testing.T) {
	counter := &connCount{}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	srv.Config.ConnState = counter.state
	srv.Start()
	defer srv.Close()

	fetch := func(client *http.Client) {
		t.Helper()
		resp, err := client.Get(srv.URL)
		if err != nil {
			t.Fatalf("request: %v", err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}
	settle := func(want int) bool {
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			if counter.get() == want {
				return true
			}
			time.Sleep(10 * time.Millisecond)
		}
		return false
	}

	// Control: the leaky shape leaves one connection per client.
	leaky := make([]*http.Transport, 0, 3)
	for i := 0; i < 3; i++ {
		tr := &http.Transport{}
		leaky = append(leaky, tr)
		fetch(&http.Client{Transport: tr})
	}
	if got := counter.get(); got != 3 {
		t.Fatalf("control: expected 3 parked connections from per-call keep-alive transports, saw %d", got)
	}
	for _, tr := range leaky {
		tr.CloseIdleConnections()
	}
	if !settle(0) {
		t.Fatalf("control cleanup: %d connections still open", counter.get())
	}

	// The fix: the image download client and the bounded client share a
	// transport shape whose connection dies with the response body.
	for i := 0; i < 3; i++ {
		fetch(imageDownloadClient())
		fetch(&http.Client{Timeout: 5 * time.Second, Transport: newOneShotTransport()})
	}
	if !settle(0) {
		t.Fatalf("%d connections still open after six one-shot requests, want 0", counter.get())
	}
}

// The previous install must stop being bootable BEFORE the stream starts, and
// durably: a hard reset mid-write never reaches the deferred invalidation, and
// a previous partition table over a half-written image hangs the board in
// initramfs instead of letting the ROM fall through to the next boot device.
func TestDisarmTargetBeforeWriteClearsBothPartitionTables(t *testing.T) {
	const deviceSize = 32 << 20
	path := filepath.Join(t.TempDir(), "device.img")
	marker := make([]byte, deviceSize)
	for i := range marker {
		marker[i] = 0xAA
	}
	if err := os.WriteFile(path, marker, 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	if err := disarmTargetBeforeWrite(f); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != deviceSize {
		t.Fatalf("device size changed: %d", len(after))
	}
	for i := 0; i < imageHeadSize; i++ {
		if after[i] != 0 {
			t.Fatalf("head byte %d = %#x, want 0", i, after[i])
		}
	}
	for i := deviceSize - (1 << 20); i < deviceSize; i++ {
		if after[i] != 0 {
			t.Fatalf("backup GPT byte %d = %#x, want 0", i, after[i])
		}
	}
	if after[imageHeadSize] != 0xAA || after[deviceSize/2] != 0xAA {
		t.Fatal("disarm touched more than the partition tables")
	}
}

// A device smaller than the head is cleared without growing (a block device
// cannot grow, and the write would fail with ENOSPC).
func TestDisarmTargetBeforeWriteTinyDevice(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tiny.img")
	if err := os.WriteFile(path, []byte{1, 2, 3, 4}, 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := disarmTargetBeforeWrite(f); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(path)
	if len(after) != 4 || after[0] != 0 || after[3] != 0 {
		t.Fatalf("tiny device = %v, want four zero bytes", after)
	}
}
