package handlers

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// The persisted LED config is what survives a reboot with the platform
// unreachable, so the round-trip semantics are load-bearing: a non-empty
// config persists verbatim, an EMPTY config REMOVES the file (isEmpty is the
// remove trigger, not a stored zero row), and a missing or corrupt file loads
// as the zero config rather than failing the boot re-apply.
func TestLEDConfigPersistenceRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "led-config.json")

	cfg := ledConfig{
		ConfigHash:     "h-1",
		StealthMode:    true,
		DigitalSources: []string{"temperature", "load"},
		DigitalGPIO:    18,
		StealthGPIO:    21,
	}
	if err := persistLEDConfigTo(path, cfg); err != nil {
		t.Fatalf("persist: %v", err)
	}
	if got := loadLEDConfigFrom(path); !reflect.DeepEqual(got, cfg) {
		t.Fatalf("round trip mutated the config: got %+v want %+v", got, cfg)
	}

	// An all-defaults config clears the file instead of storing a zero row —
	// the boot re-apply keys "nothing to do" on the file's absence.
	if err := persistLEDConfigTo(path, ledConfig{ConfigHash: "h-2"}); err != nil {
		t.Fatalf("persist empty: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("empty config must remove the state file, stat err = %v", err)
	}
	// Removing an already-absent file is a no-op, not an error.
	if err := persistLEDConfigTo(path, ledConfig{}); err != nil {
		t.Fatalf("remove of an absent file must be nil, got %v", err)
	}

	// Missing file → zero config; corrupt file → zero config, never a failure.
	if got := loadLEDConfigFrom(path); !got.isEmpty() {
		t.Fatalf("missing file must load empty, got %+v", got)
	}
	if err := os.WriteFile(path, []byte("{corrupt"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := loadLEDConfigFrom(path); !got.isEmpty() {
		t.Fatalf("corrupt file must load empty, got %+v", got)
	}
}

// isEmpty ignores the wiring facts (GPIOs, hash) — only the three knobs and a
// live indication source make a config worth keeping.
func TestLEDConfigIsEmptySemantics(t *testing.T) {
	if !(ledConfig{ConfigHash: "h", DigitalGPIO: 18, StealthGPIO: 21}).isEmpty() {
		t.Fatal("wiring facts alone must read as empty")
	}
	if !(ledConfig{DigitalSources: []string{"off", "off"}}).isEmpty() {
		t.Fatal("explicit off sources must read as empty")
	}
	for _, cfg := range []ledConfig{
		{StealthMode: true},
		{ActLEDOff: true},
		{PwrLEDOff: true},
		{DigitalSources: []string{"temperature"}},
	} {
		if cfg.isEmpty() {
			t.Fatalf("%+v must not read as empty", cfg)
		}
	}
}
