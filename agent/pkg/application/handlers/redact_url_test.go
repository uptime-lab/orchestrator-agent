package handlers

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

// redactURL dropped the query and the fragment but kept
// userinfo, so download_file's very first log line put user:password@ into
// journald. Captured off a real logger, not off the
// helper's return value alone.
func TestRedactURLDropsUserinfoFromTheStartLog(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	logger.Info("download file command received", "url", redactURL("https://deploy:hunter2@files.example.test/pkg.tar?token=s3cr3t#f"))
	out := buf.String()
	for _, secret := range []string{"hunter2", "deploy:", "s3cr3t", "#f"} {
		if strings.Contains(out, secret) {
			t.Fatalf("%q reached the log line: %s", secret, out)
		}
	}
	if !strings.Contains(out, "https://files.example.test/pkg.tar") {
		t.Fatalf("the target itself was lost: %s", out)
	}
}
