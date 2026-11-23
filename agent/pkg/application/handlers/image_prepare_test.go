package handlers

import (
	"errors"
	"io"
	"strings"
	"testing"
)

type failingReader struct{ err error }

func (f failingReader) Read([]byte) (int, error) { return 0, f.err }

// The target is cleared (wiped, its table zeroed) only once the image stream
// has delivered its first bytes: a request that fails at once — an image
// missing from storage, an expired link, a corrupt compressed header — leaves
// the previous system on the disk as it was.
func TestTheTargetIsNotPreparedWhenTheStreamFailsFirst(t *testing.T) {
	prepared := 0
	stream := newPrepareOnFirstRead(failingReader{errors.New("xz: bad header")}, func() error {
		prepared++
		return nil
	})
	if _, err := stream.Read(make([]byte, 16)); err == nil {
		t.Fatal("the stream's error was swallowed")
	}
	if prepared != 0 || stream.Prepared() {
		t.Fatal("the target was prepared although no image byte arrived")
	}
}

func TestTheTargetIsPreparedOnceBeforeTheFirstBytes(t *testing.T) {
	prepared := 0
	stream := newPrepareOnFirstRead(strings.NewReader("abcdefgh"), func() error {
		prepared++
		return nil
	})
	buf := make([]byte, 3)
	for {
		_, err := stream.Read(buf)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if prepared != 1 {
			t.Fatalf("bytes were handed on with prepare run %d times", prepared)
		}
	}
	if !stream.Prepared() {
		t.Fatal("Prepared() is false after the target was prepared")
	}
}

// A failure to prepare the target is fatal and no byte is handed on.
func TestAFailedPrepareStopsTheStream(t *testing.T) {
	stream := newPrepareOnFirstRead(strings.NewReader("abc"), func() error {
		return errors.New("cannot clear the partition table")
	})
	n, err := stream.Read(make([]byte, 8))
	if err == nil || n != 0 {
		t.Fatalf("n=%d err=%v, want 0 and the prepare error", n, err)
	}
}
