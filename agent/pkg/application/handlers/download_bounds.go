package handlers

// The byte bound on a download_file fetch. Not in the linux-tagged file so the
// bound itself is testable on a dev machine.

import (
	"errors"
	"fmt"
	"io"
)

// maxDownloadBytes caps a single download / archive so a decompression bomb or
// a runaway server cannot fill the disk.
const maxDownloadBytes = 8 << 30 // 8 GiB

// downloadByteCap is the live bound; a variable only so a test can lower it
// to something an httptest server can serve.
var downloadByteCap int64 = maxDownloadBytes

// errDownloadTooLarge is returned when a response carries more than the cap.
var errDownloadTooLarge = errors.New("download exceeds the size cap")

// copyDownloadBounded copies src into dst and refuses a source longer than
// cap. It reads at most cap+1 bytes: exhausting a LimitReader is an ordinary
// EOF, so a plain LimitReader(cap) turned a response LONGER than the cap into
// a silently truncated file that was then published as complete.
// The one probing byte is what tells "exactly the cap" from
// "more than the cap". The caller must treat the error as fatal BEFORE the
// staged file is renamed into place; a checksum, when present, would also
// refuse, but a download without one has only this.
func copyDownloadBounded(dst io.Writer, src io.Reader, cap int64) (int64, error) {
	n, err := io.Copy(dst, io.LimitReader(src, cap+1))
	if err != nil {
		return n, fmt.Errorf("failed to read download: %w", err)
	}
	if n > cap {
		return n, fmt.Errorf("%w (more than %d bytes)", errDownloadTooLarge, cap)
	}
	return n, nil
}
