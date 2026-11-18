package handlers

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

// Why these tests exist. The download copied through
// io.LimitReader(body, cap): a body LONGER than the cap ended in an ordinary
// EOF at the cap, and the first 8 GiB were staged, chmodded and published as
// a complete file. A checksum caught it when one was supplied; without one
// the truncation was reported as success.

func TestCopyDownloadBoundedAcceptsExactlyTheCap(t *testing.T) {
	body := strings.Repeat("x", 1000)
	var dst bytes.Buffer
	n, err := copyDownloadBounded(&dst, strings.NewReader(body), 1000)
	if err != nil {
		t.Fatalf("a body exactly at the cap was refused: %v", err)
	}
	if n != 1000 || dst.Len() != 1000 {
		t.Fatalf("copied %d bytes (buffer %d), want 1000", n, dst.Len())
	}
}

func TestCopyDownloadBoundedRefusesOneBytePastTheCap(t *testing.T) {
	body := strings.Repeat("x", 1001)
	var dst bytes.Buffer
	_, err := copyDownloadBounded(&dst, strings.NewReader(body), 1000)
	if err == nil {
		t.Fatal("a body one byte past the cap was accepted as complete")
	}
	if !errors.Is(err, errDownloadTooLarge) {
		t.Fatalf("the refusal is not the size error: %v", err)
	}
	// Nothing beyond the cap plus the one probing byte is ever read.
	src := endlessReader{}
	var sink limitedSink
	if _, err := copyDownloadBounded(&sink, src, 4096); err == nil {
		t.Fatal("an endless body was accepted")
	} else if sink.n > 4097 {
		t.Fatalf("read %d bytes of an endless body; the copy is not bounded", sink.n)
	}
}

type endlessReader struct{}

func (endlessReader) Read(p []byte) (int, error) { return len(p), nil }

// limitedSink counts bytes and discards them.
type limitedSink struct{ n int64 }

func (s *limitedSink) Write(p []byte) (int, error) { s.n += int64(len(p)); return len(p), nil }
