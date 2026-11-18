// Package board decodes the Raspberry Pi board revision code.
//
// It exists because two different questions were being answered by one value,
// and they diverge on exactly the boards this platform started supporting last:
//
//   - "which EEPROM firmware family?" — BCM2711 vs BCM2712. A Pi 4 B answers the
//     same as a CM4 here, and that is correct.
//   - "does config.txt's [cm4] section apply?" — a Pi 4 B and a CM4S are both
//     BCM2711 and neither is matched by [cm4]. Writing [cm4]-filtered directives
//     to them and rebooting is work the firmware will never read.
//
// The revision code answers both, separately and exactly. It comes from OTP via
// the firmware, so unlike /proc/device-tree/model it does not change when the
// recovery bootstrap forces a device_tree=.
package board

import (
	"regexp"
	"strconv"
	"strings"
)

// revisionLineRe matches the BOARD revision line in /proc/cpuinfo, e.g.
// "Revision\t: c04170". Anchored to the line start so it cannot match
// "CPU revision", which is a single digit describing the core — a different
// fact with a confusingly similar name, and the one the agent was already
// reading.
var revisionLineRe = regexp.MustCompile(`(?m)^Revision\s*:\s*([0-9a-fA-F]+)\s*$`)

// ExtractRevisionFromCPUInfo pulls the raw board revision code out of
// /proc/cpuinfo contents, or "" when the file reports none (any non-Pi host,
// and some virtualised ones). Kept here, untagged, so it is testable off Linux.
func ExtractRevisionFromCPUInfo(cpuinfo string) string {
	m := revisionLineRe.FindStringSubmatch(cpuinfo)
	if len(m) < 2 {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(m[1]))
}

// Type is the board type, bits 4-11 of a new-style revision code.
type Type uint8

// Board types this platform knows. The list is deliberately short: it covers
// what we support plus the neighbours most likely to be plugged in by mistake.
// An unknown type is not an error — it decodes to a Type we simply do not name.
const (
	TypePi4B    Type = 0x11
	TypePi400   Type = 0x13
	TypeCM4     Type = 0x14
	TypeCM4S    Type = 0x15
	TypePi5     Type = 0x17
	TypeCM5     Type = 0x18
	TypePi500   Type = 0x19
	TypeCM5Lite Type = 0x1a
)

// Processor is the SoC, bits 12-15 of a new-style revision code.
type Processor uint8

const (
	ProcBCM2835 Processor = 0
	ProcBCM2836 Processor = 1
	ProcBCM2837 Processor = 2
	ProcBCM2711 Processor = 3
	ProcBCM2712 Processor = 4
)

// Revision is a decoded new-style Raspberry Pi revision code.
type Revision struct {
	Raw       string
	Type      Type
	Processor Processor
	// MemoryMB is 0 when the encoded size is the "other" marker (7), which has
	// to be read from a firmware parameter instead. Callers must treat 0 as
	// unknown rather than as "no memory".
	MemoryMB int
	// Rev is the board revision within its type (the trailing nibble).
	Rev uint8
}

// ParseRevision decodes a new-style revision code such as "c04170".
//
// Layout: NOQuuuWuFMMMCCCCPPPPTTTTTTTTRRRR. It is valid ONLY when bit 23 (the
// "new flag") is set — an old-style sequential code like "000e" decodes to
// nonsense under it, and one consumer of this data selects the EEPROM firmware
// that gets flashed, so the check is not optional.
//
// Returns ok=false for an empty, unparseable or old-style code. Callers must
// fall back rather than substituting a default board: refusing to act on
// hardware we cannot identify is the cheaper mistake.
func ParseRevision(rev string) (Revision, bool) {
	s := strings.TrimSpace(rev)
	s = strings.TrimPrefix(strings.TrimPrefix(s, "0x"), "0X")
	if s == "" {
		return Revision{}, false
	}

	code, err := strconv.ParseUint(s, 16, 32)
	if err != nil {
		return Revision{}, false
	}

	// Bit 23: new-style flag.
	if code&(1<<23) == 0 {
		return Revision{}, false
	}

	memCode := (code >> 20) & 0x7
	memMB := 0
	if memCode <= 6 {
		memMB = 256 << memCode
	}

	return Revision{
		Raw:       rev,
		Type:      Type((code >> 4) & 0xff),
		Processor: Processor((code >> 12) & 0xf),
		MemoryMB:  memMB,
		Rev:       uint8(code & 0xf),
	}, true
}

// SoCFamily answers "which EEPROM firmware family" as the signer names it:
// "cm4" for BCM2711, "cm5" for BCM2712, "" for anything else.
//
// It reads the PROCESSOR nibble and never the type table. That is the whole
// point: a board we have never heard of still gets the right firmware as long
// as its SoC is one we know, and no table entry can be missing. The names are
// the signer's historical ones (SOC_RE accepts exactly cm4|cm5) and mean the
// silicon, not the form factor.
func (r Revision) SoCFamily() string {
	switch r.Processor {
	case ProcBCM2711:
		return "cm4"
	case ProcBCM2712:
		return "cm5"
	default:
		return ""
	}
}

// MatchesCM4Filter answers "does config.txt's [cm4] section apply to this
// board" — true for a Compute Module 4 and nothing else.
//
// This is NOT the SoC question. A Pi 4 B (0x11) and a CM4S (0x15) are BCM2711
// and are matched by [pi4], not by [cm4]; per the firmware's filter table [cm4]
// is Compute Module 4 alone. Conflating the two is what made the platform write
// inert directives to a Pi 4 B and reboot it for nothing.
func (r Revision) MatchesCM4Filter() bool {
	return r.Type == TypeCM4
}
