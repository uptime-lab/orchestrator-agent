package hardware

import (
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"
	"testing"
)

func writeHatFile(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestReadHatInfoAbsent(t *testing.T) {
	if got := readHatInfoFrom(filepath.Join(t.TempDir(), "nope")); got != nil {
		t.Fatalf("missing dir must read as nil, got %+v", got)
	}
}

func TestReadHatInfoFields(t *testing.T) {
	dir := t.TempDir()
	// Device-tree strings are NUL-terminated; the reader must strip that.
	writeHatFile(t, dir, "vendor", "Acme Corp\x00")
	writeHatFile(t, dir, "product", "Sense Thing\x00")
	writeHatFile(t, dir, "product_id", "0x0001\x00")
	writeHatFile(t, dir, "uuid", "6c8f6c-dead-beef\x00")

	hat := readHatInfoFrom(dir)
	if hat == nil {
		t.Fatal("expected a HAT")
	}
	if hat.Vendor != "Acme Corp" || hat.Product != "Sense Thing" || hat.ProductId != "0x0001" {
		t.Fatalf("fields: %+v", hat)
	}
	if hat.ProductVer != "" {
		t.Fatalf("missing file must read empty, got %q", hat.ProductVer)
	}
}

func TestReadHatInfoEmptyDirIsNil(t *testing.T) {
	if got := readHatInfoFrom(t.TempDir()); got != nil {
		t.Fatalf("a hat dir with no identity fields is not a HAT, got %+v", got)
	}
}

func TestReadHatInfoTruncatesHostileEEPROM(t *testing.T) {
	dir := t.TempDir()
	writeHatFile(t, dir, "product", strings.Repeat("x", 5000))
	hat := readHatInfoFrom(dir)
	if hat == nil || len(hat.Product) != hatFieldMaxBytes {
		t.Fatalf("truncation failed: %d", len(hat.GetProduct()))
	}
}

func TestReadHatInfoScrubsInvalidUTF8(t *testing.T) {
	// proto3 refuses to marshal invalid UTF-8 and grpc-go tears down the whole
	// stream on the marshal error — a Latin-1 vendor string must cost bytes,
	// never the connection.
	dir := t.TempDir()
	writeHatFile(t, dir, "vendor", "caf\xe9 s.r.l.")
	writeHatFile(t, dir, "product", strings.Repeat("\xc3", 200)) // truncation must not split runes
	hat := readHatInfoFrom(dir)
	if hat == nil {
		t.Fatal("expected a HAT")
	}
	if !utf8.ValidString(hat.GetVendor()) || !utf8.ValidString(hat.GetProduct()) {
		t.Fatalf("invalid UTF-8 survived: %q %q", hat.GetVendor(), hat.GetProduct())
	}
}
