//go:build linux

package handlers

import (
	"bytes"
	"strings"
	"testing"
)

func TestCopyBoundedPackage(t *testing.T) {
	t.Run("under the cap copies fully", func(t *testing.T) {
		src := strings.NewReader("a small agent package")
		var dst bytes.Buffer
		if err := copyBoundedPackage(&dst, src); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if dst.String() != "a small agent package" {
			t.Errorf("copied %q", dst.String())
		}
	})

	t.Run("over the cap is refused before it is all read", func(t *testing.T) {
		// An endless source: a real OOM would come from an unbounded CDN stream.
		src := endlessReader{}
		var dst limitedSink
		err := copyBoundedPackage(&dst, src)
		if err == nil {
			t.Fatal("expected an error for a stream exceeding the cap")
		}
		if dst.n > maxAgentPackageBytes+1 {
			t.Errorf("wrote %d bytes; the copy was not bounded", dst.n)
		}
	})
}

// endlessReader and limitedSink live in download_bounds_test.go (portable).
