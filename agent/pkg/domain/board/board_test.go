package board

import "testing"

// The three real codes below were read off the ROM's own boot output on the
// devices this support was written for, so they pin the decoder against
// hardware rather than against the documentation it was derived from.
func TestParseRevisionRealDevices(t *testing.T) {
	tests := []struct {
		name     string
		rev      string
		wantType Type
		wantProc Processor
		wantMB   int
	}{
		{"Pi 4 Model B 8GB", "d03115", TypePi4B, ProcBCM2711, 8192},
		{"CM4 8GB rev 1.1", "d03141", TypeCM4, ProcBCM2711, 8192},
		{"Pi 5 4GB", "c04170", TypePi5, ProcBCM2712, 4096},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := ParseRevision(tt.rev)
			if !ok {
				t.Fatalf("ParseRevision(%q) = not ok, want ok", tt.rev)
			}
			if got.Type != tt.wantType {
				t.Errorf("Type = %#x, want %#x", got.Type, tt.wantType)
			}
			if got.Processor != tt.wantProc {
				t.Errorf("Processor = %d, want %d", got.Processor, tt.wantProc)
			}
			if got.MemoryMB != tt.wantMB {
				t.Errorf("MemoryMB = %d, want %d", got.MemoryMB, tt.wantMB)
			}
		})
	}
}

func TestParseRevisionRejects(t *testing.T) {
	// Every one of these must fail rather than decode to a plausible board:
	// the caller flashes an EEPROM, and a confident wrong answer there costs a
	// trip to the rack with a USB cable.
	for _, rev := range []string{
		"",         // nothing reported
		"   ",      // whitespace only
		"000e",     // old-style: bit 23 clear, would decode to garbage
		"0002",     // old-style
		"zzzz",     // not hex
		"c04170ff", // too wide for 32 bits
	} {
		if got, ok := ParseRevision(rev); ok {
			t.Errorf("ParseRevision(%q) = %+v, ok; want not ok", rev, got)
		}
	}
}

func TestParseRevisionAcceptsPrefixAndSpace(t *testing.T) {
	for _, rev := range []string{"0xc04170", "  c04170 ", "C04170"} {
		got, ok := ParseRevision(rev)
		if !ok {
			t.Fatalf("ParseRevision(%q) = not ok, want ok", rev)
		}
		if got.Type != TypePi5 {
			t.Errorf("ParseRevision(%q).Type = %#x, want Pi 5", rev, got.Type)
		}
	}
}

func TestSoCFamilyReadsTheProcessorNotTheType(t *testing.T) {
	tests := []struct {
		rev  string
		want string
	}{
		{"d03115", "cm4"}, // Pi 4 B — same firmware family as a CM4, correctly
		{"d03141", "cm4"}, // CM4
		{"c04170", "cm5"}, // Pi 5
	}
	for _, tt := range tests {
		r, ok := ParseRevision(tt.rev)
		if !ok {
			t.Fatalf("ParseRevision(%q) failed", tt.rev)
		}
		if got := r.SoCFamily(); got != tt.want {
			t.Errorf("SoCFamily(%q) = %q, want %q", tt.rev, got, tt.want)
		}
	}

	// An unknown SoC must yield "", not a guess: the value becomes a path
	// segment the signer validates against ^(cm4|cm5)$, and a wrong one there
	// would flash the wrong-silicon bootloader.
	unknown := Revision{Processor: 9}
	if got := unknown.SoCFamily(); got != "" {
		t.Errorf("SoCFamily(unknown processor) = %q, want empty", got)
	}
}

// This is the regression the whole package exists for. Both boards below are
// BCM2711, so the SoC question says "cm4" for them — but neither is matched by
// config.txt's [cm4] filter, and treating them as CM4s writes directives the
// firmware never reads and then reboots the device for nothing.
func TestMatchesCM4FilterIsNotTheSoCQuestion(t *testing.T) {
	tests := []struct {
		name string
		rev  string
		want bool
	}{
		{"CM4 is the only match", "d03141", true},
		{"Pi 4 B is BCM2711 but not a CM4", "d03115", false},
		{"Pi 5", "c04170", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, ok := ParseRevision(tt.rev)
			if !ok {
				t.Fatalf("ParseRevision(%q) failed", tt.rev)
			}
			if got := r.MatchesCM4Filter(); got != tt.want {
				t.Errorf("MatchesCM4Filter(%q) = %v, want %v", tt.rev, got, tt.want)
			}
		})
	}

	// CM4S has no captured ROM dump, so assert it from the type directly rather
	// than not asserting it at all — it is in the supported set and it is the
	// second board this distinction protects.
	if (Revision{Type: TypeCM4S, Processor: ProcBCM2711}).MatchesCM4Filter() {
		t.Error("CM4S must not match [cm4]; it is matched by [cm4s] and [pi4]")
	}
	if got := (Revision{Type: TypeCM4S, Processor: ProcBCM2711}).SoCFamily(); got != "cm4" {
		t.Errorf("CM4S SoCFamily = %q, want cm4 (same BCM2711 firmware)", got)
	}
}
