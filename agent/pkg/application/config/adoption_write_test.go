package config

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"agent/pkg/domain/node"

	"github.com/google/uuid"
)

// The adoption file is the node's only way to reach the platform. Getting this
// write wrong does not degrade the node, it strands it — which is the exact
// outcome the identity handoff exists to prevent, so the write itself must not
// be able to cause it.

func writeMasterTokenFile(t *testing.T, dir string) (string, *node.AdoptionConfig) {
	t.Helper()
	path := filepath.Join(dir, "node-adoption.txt")
	cfg := &node.AdoptionConfig{
		MasterToken:  "mt_shared_enrolment_token",
		AccountID:    uuid.MustParse("c0f41804-7d55-4e7e-9ac6-54d4e89a116c"),
		PlatformURL:  "https://example.invalid",
		GRPCEndpoint: "example.invalid:50051",
		CreatedAt:    1,
	}
	p := NewParser()
	if err := p.WriteAdoptionFile(path, cfg); err != nil {
		t.Fatalf("seed write failed: %v", err)
	}
	return path, cfg
}

func TestWrittenFileRoundTripsThroughTheParser(t *testing.T) {
	dir := t.TempDir()
	path, seed := writeMasterTokenFile(t, dir)

	p := NewParser()
	// Hand over an identity the way the platform does.
	updated := *seed
	updated.NodeID = uuid.MustParse("215f81d2-dc8a-41d1-a212-60e0ac8e5535")
	updated.UniqueToken = "11111111-2222-3333-4444-555555555555"
	updated.MasterToken = ""
	if err := p.WriteAdoptionFile(path, &updated); err != nil {
		t.Fatalf("identity write failed: %v", err)
	}

	got, err := p.ParseAdoptionFile(path, nil)
	if err != nil {
		t.Fatalf("the file we just wrote does not parse — that strands the node on next start: %v", err)
	}
	if !got.IsNodeTokenMode() {
		t.Fatal("after the handoff the node must be in node-specific mode")
	}
	if got.IsMasterTokenMode() {
		t.Fatal("the master token must be cleared: the parser rejects a file carrying both, and keeping it leaves the node tied to a credential that expires")
	}
	if got.NodeID != updated.NodeID || got.UniqueToken != updated.UniqueToken {
		t.Fatalf("identity did not survive the round trip: %+v", got)
	}
	if got.PlatformURL != seed.PlatformURL || got.GRPCEndpoint != seed.GRPCEndpoint {
		t.Fatal("endpoints must be preserved — rewriting them would point the node at nothing")
	}
}

// decodeAdoption reads back an encoded adoption payload.
func decodeAdoption(t *testing.T, encoded []byte) node.AdoptionConfig {
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

func TestTheOriginalIsBackedUpOnceAndNeverOverwritten(t *testing.T) {
	dir := t.TempDir()
	path, seed := writeMasterTokenFile(t, dir)
	backup := path + ".pre-identity.bak"

	if _, err := os.Stat(backup); !os.IsNotExist(err) {
		t.Fatal("the seed write should not have produced a backup of a file that did not exist")
	}

	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	p := NewParser()
	first := *seed
	first.NodeID = uuid.New()
	first.UniqueToken = "first"
	first.MasterToken = ""
	if err := p.WriteAdoptionFile(path, &first); err != nil {
		t.Fatal(err)
	}

	saved, err := os.ReadFile(backup)
	if err != nil {
		t.Fatalf("no backup of the pre-handoff file: %v", err)
	}
	// The backup holds the pre-handoff IDENTITY, not the pre-handoff file: the
	// credential is redacted out of it. In master-token mode that credential is
	// shared by every device the provisioning card ever touched and may never
	// expire, and the backup is never cleaned up.
	if string(saved) == string(original) {
		t.Fatal("the backup was stored verbatim; the credential must be redacted out of it")
	}
	if bytes.Contains(saved, []byte(seed.MasterToken)) {
		t.Fatal("the master token survived into the backup")
	}
	savedCfg := decodeAdoption(t, saved)
	if savedCfg.AccountID != seed.AccountID || savedCfg.PlatformURL != seed.PlatformURL {
		t.Fatal("the backup must keep what makes it useful for recovery: the account and the endpoints")
	}

	// A second write must not replace the last known-good copy with something
	// this feature already produced.
	second := first
	second.UniqueToken = "second"
	if err := p.WriteAdoptionFile(path, &second); err != nil {
		t.Fatal(err)
	}
	saved2, err := os.ReadFile(backup)
	if err != nil {
		t.Fatal(err)
	}
	if string(saved2) != string(saved) {
		t.Fatal("the backup was overwritten by a later write — the recoverable state is gone")
	}
}

func TestWriteLeavesNoTempFileBehind(t *testing.T) {
	dir := t.TempDir()
	path, seed := writeMasterTokenFile(t, dir)

	p := NewParser()
	updated := *seed
	updated.NodeID = uuid.New()
	updated.UniqueToken = "tok"
	updated.MasterToken = ""
	if err := p.WriteAdoptionFile(path, &updated); err != nil {
		t.Fatal(err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if filepath.Ext(e.Name()) == ".tmp" {
			t.Fatalf("temp file %s survived — a directory of these on a boot partition is its own problem", e.Name())
		}
	}
}

func TestTheCredentialIsNotWorldReadable(t *testing.T) {
	dir := t.TempDir()
	path, _ := writeMasterTokenFile(t, dir)

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("adoption file mode is %04o, want 0600 — it holds the token that impersonates this node", perm)
	}
}
