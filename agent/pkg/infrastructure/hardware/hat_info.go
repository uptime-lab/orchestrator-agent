// HAT ID EEPROM reader. No build tag on purpose (the usb_devices.go
// convention): the code only reads files under a root that exists on Linux
// alone, callers on other platforms simply get nil, and the pure function
// stays testable everywhere with a fake root.
package hardware

import (
	"os"
	"path/filepath"
	"strings"

	proto "agent/pkg/infrastructure/grpc/proto"
)

// hatFieldMaxBytes bounds each field defensively: the values come from an
// EEPROM any vendor programs, travel in SystemInfo and are stored/rendered by
// the platform. The platform truncates again on its side; this bound only
// keeps a corrupt EEPROM from bloating every report.
const hatFieldMaxBytes = 128

// ReadHatInfo reads the spec-compliant HAT identity the firmware exposed in
// /proc/device-tree/hat. Returns nil when no HAT is present — the proto field
// is documented ABSENT, not zeroed, so "no HAT" and "HAT with empty fields"
// stay distinguishable.
func ReadHatInfo() *proto.HatInfo {
	return readHatInfoFrom("/proc/device-tree/hat")
}

func readHatInfoFrom(dir string) *proto.HatInfo {
	if info, err := os.Stat(dir); err != nil || !info.IsDir() {
		return nil
	}
	read := func(name string) string {
		raw, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return ""
		}
		// Device-tree string properties are NUL-terminated. The UTF-8 scrub is
		// not cosmetic: proto3 refuses to marshal an invalid-UTF-8 string, and
		// grpc-go tears down the WHOLE stream on a marshal error — a vendor
		// EEPROM programmed with Latin-1 would make the node reconnect-flap
		// forever, reading as dead hardware. Byte-truncation could itself split
		// a rune, so the cap counts runes after the scrub.
		val := strings.TrimSpace(strings.Trim(string(raw), "\x00"))
		val = strings.ToValidUTF8(val, "")
		if len(val) > hatFieldMaxBytes {
			var b strings.Builder
			for _, r := range val {
				if b.Len()+len(string(r)) > hatFieldMaxBytes {
					break
				}
				b.WriteRune(r)
			}
			val = b.String()
		}
		return val
	}
	hat := &proto.HatInfo{
		Vendor:     read("vendor"),
		Product:    read("product"),
		ProductId:  read("product_id"),
		ProductVer: read("product_ver"),
		Uuid:       read("uuid"),
	}
	if hat.Vendor == "" && hat.Product == "" && hat.ProductId == "" && hat.Uuid == "" {
		return nil
	}
	return hat
}
