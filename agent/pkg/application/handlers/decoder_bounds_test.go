package handlers

import (
	"bufio"
	"bytes"
	"io"
	"strings"
	"testing"

	"github.com/ulikunitz/xz"
)

// Why these tests exist. The pure-Go xz reader grows its
// dictionary to whatever the stream declares, and the zstd decoder honoured
// any window a frame named; a header alone could ask a small node for
// gigabytes before the artifact was rejected.

func xzStreamWithDict(t *testing.T, dictCap int) []byte {
	t.Helper()
	var buf bytes.Buffer
	w, err := xz.WriterConfig{DictCap: dictCap}.NewWriter(&buf)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = w.Write([]byte("hello"))
	_ = w.Close()
	return buf.Bytes()
}

func TestXZFirstBlockDictionaryTripwire(t *testing.T) {
	over := xzStreamWithDict(t, 128<<20)
	if err := checkXZFirstBlockDictionary(bufio.NewReader(bytes.NewReader(over)), xzGoDictCap); err == nil {
		t.Fatal("a 128 MiB dictionary declaration passed the 64 MiB tripwire")
	}
	within := xzStreamWithDict(t, 8<<20)
	br := bufio.NewReader(bytes.NewReader(within))
	if err := checkXZFirstBlockDictionary(br, xzGoDictCap); err != nil {
		t.Fatalf("an 8 MiB dictionary was refused: %v", err)
	}
	// The peek must not have consumed anything: the reader still decodes.
	xr, err := xz.ReaderConfig{DictCap: xzGoDictCap}.NewReader(br)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(xr)
	if err != nil || string(got) != "hello" {
		t.Fatalf("decode after the peek: %q, %v", got, err)
	}
	// Not an xz stream at all: left to the reader.
	if err := checkXZFirstBlockDictionary(bufio.NewReader(strings.NewReader("not xz")), xzGoDictCap); err != nil {
		t.Fatalf("a non-xz stream was refused by the tripwire: %v", err)
	}
}

func TestZstdDecoderRefusesAnOversizedWindow(t *testing.T) {
	// A hand-built frame: magic, a frame header descriptor with no content
	// size and no single-segment flag, a Window_Descriptor declaring 256 MiB
	// (exponent 18 → 2^(10+18)), then one raw last block of one byte. The
	// encoder cannot be asked to declare a window this large for a small
	// input, so the header is written by hand.
	// Driven through the PRODUCTION constructor for the image path, not a
	// decoder built in the test, so it fails if the bound is ever dropped
	// there.
	frame := []byte{0x28, 0xB5, 0x2F, 0xFD, 0x00, 18 << 3, 0x09, 0x00, 0x00, 'A'}
	stream, err := newImageStreamReader(compressionZstd, bytes.NewReader(frame), nil)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(stream)
	stream.Close()
	if err == nil {
		t.Fatalf("a 256 MiB window decoded under a 128 MiB bound: %q", got)
	}
	// The same frame with an 8 MiB window (exponent 13) decodes.
	frame[5] = 13 << 3
	stream2, err := newImageStreamReader(compressionZstd, bytes.NewReader(frame), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer stream2.Close()
	if got, err := io.ReadAll(stream2); err != nil || string(got) != "A" {
		t.Fatalf("control frame: %q, %v", got, err)
	}
}

// The header parser must refuse, not panic, on a crafted filter-size varint
// that overflows an int addition.
func TestXZHeaderParserSurvivesACraftedFilterSize(t *testing.T) {
	stream := append([]byte{0xFD, '7', 'z', 'X', 'Z', 0x00, 0x00, 0x01, 0, 0, 0, 0}, // stream header
		0x03,                                                 // block header size byte → 16 bytes
		0x00,                                                 // flags: one filter, no sizes
		0x21,                                                 // LZMA2
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F, // size varint: 63 bits
		0, 0, 0, 0, 0, 0)
	if err := checkXZFirstBlockDictionary(bufio.NewReader(bytes.NewReader(stream)), xzGoDictCap); err != nil {
		t.Fatalf("an unparseable header must be left to the reader, got %v", err)
	}
}
