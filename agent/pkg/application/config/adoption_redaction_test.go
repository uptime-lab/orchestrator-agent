package config

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"agent/pkg/domain/node"

	"github.com/google/uuid"
)

func encodedConfig(t *testing.T, cfg node.AdoptionConfig) []byte {
	t.Helper()
	payload, err := json.Marshal(&cfg)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return []byte(base64.StdEncoding.EncodeToString(payload))
}

func decodeConfig(t *testing.T, encoded []byte) node.AdoptionConfig {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(encoded)))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	var cfg node.AdoptionConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return cfg
}

func quietParser() *Parser {
	return NewParserWithLogger(slog.New(slog.NewTextHandler(io.Discard, nil)))
}

// The backup exists so a bad identity handover is recoverable on the device.
// What that needs is the identity and the endpoints — not the credential, which
// in the master-token case is shared by every device the provisioning card ever
// touched.
func TestRedactAdoptionPayloadKeepsIdentityAndDropsCredentials(t *testing.T) {
	accountID, nodeID := uuid.New(), uuid.New()
	in := encodedConfig(t, node.AdoptionConfig{
		NodeID:       nodeID,
		UniqueToken:  "node-secret",
		MasterToken:  "shared-master-secret",
		AccountID:    accountID,
		PlatformURL:  "https://app.example.test",
		GRPCEndpoint: "app.example.test:50051",
	})

	out := redactAdoptionPayload(in)

	if strings.Contains(string(out), "secret") {
		t.Fatal("a credential survived redaction (the payload is base64, so this checks the encoding too)")
	}
	cfg := decodeConfig(t, out)
	if cfg.UniqueToken != "" || cfg.MasterToken != "" {
		t.Errorf("credentials survived: unique=%q master=%q", cfg.UniqueToken, cfg.MasterToken)
	}
	if cfg.NodeID != nodeID || cfg.AccountID != accountID {
		t.Error("the identity that makes the backup useful was lost")
	}
	if cfg.PlatformURL == "" || cfg.GRPCEndpoint == "" {
		t.Error("the endpoints were lost")
	}
}

// A payload we cannot parse is exactly the one whose contents we cannot vouch
// for; copying it verbatim is how the credential would survive.
func TestRedactAdoptionPayloadRefusesToPassThroughGarbage(t *testing.T) {
	out := string(redactAdoptionPayload([]byte("!!! not base64 !!!")))
	if strings.Contains(out, "not base64") {
		t.Errorf("unparseable payload was passed through: %q", out)
	}
}

func TestRedactExistingAdoptionBackup(t *testing.T) {
	dir := t.TempDir()
	adoption := filepath.Join(dir, "node-adoption.txt")
	backup := adoption + ".pre-identity.bak"
	if err := os.WriteFile(backup, encodedConfig(t, node.AdoptionConfig{
		MasterToken: "shared-master-secret", AccountID: uuid.New(),
	}), 0o600); err != nil {
		t.Fatalf("seed backup: %v", err)
	}

	p := quietParser()
	p.RedactExistingAdoptionBackup(adoption)

	after, err := os.ReadFile(backup)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if strings.Contains(string(after), "secret") {
		t.Fatal("the fielded backup still holds the credential")
	}
	// Idempotent: a second pass must not rewrite or destroy it.
	p.RedactExistingAdoptionBackup(adoption)
	again, err := os.ReadFile(backup)
	if err != nil || string(again) != string(after) {
		t.Errorf("second pass changed the file: %v", err)
	}
}

func TestEnsureAdoptionFilePermissions(t *testing.T) {
	dir := t.TempDir()
	adoption := filepath.Join(dir, "node-adoption.txt")
	if err := os.WriteFile(adoption, []byte("payload"), 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}

	quietParser().EnsureAdoptionFilePermissions(adoption)

	info, err := os.Stat(adoption)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Errorf("mode = %v, want -rw-------", got)
	}
	// A missing file is not an error: the agent may be starting before one
	// exists at all.
	quietParser().EnsureAdoptionFilePermissions(filepath.Join(dir, "absent"))
}
