package config

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"agent/pkg/domain/node"

	"github.com/google/uuid"
)

// eepromMustNotBeRead fails the test the moment the parser consults the
// EEPROM: that fallback is exactly what a release must switch off.
type eepromMustNotBeRead struct{ t *testing.T }

func (r eepromMustNotBeRead) ReadAdoptionFileFromEEPROM() (string, error) {
	r.t.Fatal("the parser read the EEPROM identity after a release")
	return "", nil
}

// eepromWith serves a fixed EEPROM blob, for the cases where the fallback IS
// expected.
type eepromWith struct{ line string }

func (r eepromWith) ReadAdoptionFileFromEEPROM() (string, error) { return r.line, nil }

// Measured: with the adoption file gone, the agent read the same
// node id and token back out of the EEPROM, so deleting a node from the
// platform released nothing on an EEPROM-adopted Pi. The marker the release
// leaves behind is what stops that.
func TestAReleasedIdentityIsNotTakenBackFromTheEEPROM(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "node-adoption.txt")
	p := quietParser()
	if err := p.WriteAdoptionFile(path, sampleAdoption()); err != nil {
		t.Fatal(err)
	}

	if err := p.ReleaseAdoption(path, "the node was deleted from the platform"); err != nil {
		t.Fatalf("release: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("the adoption file survived the release")
	}
	if _, err := os.Stat(ReleasedMarkerPath(path)); err != nil {
		t.Fatalf("the release left no marker: %v", err)
	}

	_, err := p.ParseAdoptionFile(path, eepromMustNotBeRead{t})
	if !errors.Is(err, ErrIdentityReleased) {
		t.Fatalf("parse after release = %v, want ErrIdentityReleased", err)
	}
}

// The marker decides only what happens when there is NO file: a new adoption
// (install script, SD card, re-adopt) is read as usual, and writing it also
// clears the stale note.
func TestANewAdoptionFileLiftsTheRelease(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "node-adoption.txt")
	p := quietParser()
	if err := p.ReleaseAdoption(path, "deleted"); err != nil {
		t.Fatal(err)
	}
	if err := p.WriteAdoptionFile(path, sampleAdoption()); err != nil {
		t.Fatal(err)
	}
	if _, err := p.ParseAdoptionFile(path, eepromMustNotBeRead{t}); err != nil {
		t.Fatalf("a fresh adoption file was refused after an earlier release: %v", err)
	}
	if _, err := os.Stat(ReleasedMarkerPath(path)); !os.IsNotExist(err) {
		t.Error("writing a new adoption file left the released marker behind")
	}
}

// Without a marker the fallback works as before: a Pi with no disk file and
// an EEPROM identity still starts as that node. This is the behaviour a
// netboot-first device relies on, and nothing here may change it.
func TestWithoutAMarkerTheEEPROMFallbackStillApplies(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "node-adoption.txt")
	p := quietParser()
	// Borrow the writer to produce a valid encoded line, then read it back
	// through the EEPROM path instead of the disk.
	if err := p.WriteAdoptionFile(path, sampleAdoption()); err != nil {
		t.Fatal(err)
	}
	line, err := p.GetRawAdoptionFileString(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	cfg, err := p.ParseAdoptionFile(path, eepromWith{line: line})
	if err != nil {
		t.Fatalf("EEPROM fallback failed with no marker present: %v", err)
	}
	if cfg.NodeID != sampleAdoption().NodeID {
		t.Errorf("EEPROM fallback read node %q, want %q", cfg.NodeID, sampleAdoption().NodeID)
	}
}

func sampleAdoption() *node.AdoptionConfig {
	return &node.AdoptionConfig{
		NodeID:       uuid.MustParse("23401a27-3709-474b-bde4-c579a8ae04da"),
		UniqueToken:  "tok_test",
		AccountID:    uuid.MustParse("c0f41804-7d55-4e7e-9ac6-54d4e89a116c"),
		PlatformURL:  "https://example.invalid",
		GRPCEndpoint: "example.invalid:50051",
		CreatedAt:    1,
	}
}
