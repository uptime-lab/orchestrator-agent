package handlers

import (
	"strings"
	"testing"
)

// This file carries no build tag on purpose. The handlers that produce command
// results are all in _linux.go files, so a developer's `go test ./...` on macOS
// never compiles them; the bound itself is pure Go and is tested everywhere.

func TestBoundedBufferKeepsShortOutputVerbatim(t *testing.T) {
	b := newBoundedBuffer()
	if _, err := b.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	if b.Truncated() {
		t.Fatal("short output must not be marked truncated")
	}
	if b.String() != "hello" {
		t.Fatalf("got %q", b.String())
	}
}

func TestBoundedBufferCapsAndMarks(t *testing.T) {
	b := &boundedBuffer{Max: 10}
	// Written across several calls, because a process pipe arrives in chunks
	// and the boundary can fall inside one of them.
	for i := 0; i < 5; i++ {
		if n, err := b.Write([]byte("abcde")); err != nil || n != 5 {
			t.Fatalf("Write must report a full write: n=%d err=%v", n, err)
		}
	}
	if !b.Truncated() {
		t.Fatal("expected truncation")
	}
	out := b.String()
	if !strings.HasPrefix(out, "abcdeabcde") {
		t.Fatalf("must keep the head, got %q", out)
	}
	if !strings.Contains(out, "kept 10 of 25 bytes") {
		t.Fatalf("truncation must be stated in the value, got %q", out)
	}
}

// The whole point of the bound: a result value must stay far below the
// backend's 4 MiB gRPC receive limit, because exceeding it kills the stream
// rather than the command.
func TestBoundedBufferStaysUnderTheStreamLimit(t *testing.T) {
	const grpcDefaultRecvLimit = 4 * 1024 * 1024
	b := newBoundedBuffer()
	chunk := make([]byte, 64*1024)
	for i := 0; i < 200; i++ { // 12.8 MiB offered
		if _, err := b.Write(chunk); err != nil {
			t.Fatal(err)
		}
	}
	// Two such values (stdout + stderr) plus the marker must still fit with
	// room to spare.
	if 2*len(b.String()) >= grpcDefaultRecvLimit {
		t.Fatalf("two bounded values (%d bytes) must stay under the receive limit", 2*len(b.String()))
	}
	if !b.Truncated() {
		t.Fatal("expected truncation")
	}
}

// Write must never report a short write: the child process is writing to its
// own stdout and must not be failed because we stopped keeping bytes.
func TestBoundedBufferNeverShortWrites(t *testing.T) {
	b := &boundedBuffer{Max: 4}
	payload := []byte("aaaaaaaaaaaaaaaa")
	n, err := b.Write(payload)
	if err != nil {
		t.Fatalf("Write must not error: %v", err)
	}
	if n != len(payload) {
		t.Fatalf("Write must report %d, got %d", len(payload), n)
	}
}
