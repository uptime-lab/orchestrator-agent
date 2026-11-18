package hardware

import (
	"regexp"
	"strings"
)

// eepromPackageArtifacts are the files a staged (or spent) EEPROM recovery
// package leaves on a FAT boot partition. The ROM renames recovery.bin to
// RECOVERY.000 after a successful flash; SHA256SUMS accompanies packages
// copied manually from the CDN.
var eepromPackageArtifacts = []string{
	"recovery.bin", "RECOVERY.000", "recovery.000",
	"pieeprom.upd", "pieeprom.sig", "SHA256SUMS",
}

// eepromSerialPattern extracts the device serial baked into a per-device
// EEPROM image (the eeprom-signer sets HTTP_PATH=http-boot/<serial>).
var eepromSerialPattern = regexp.MustCompile(`HTTP_PATH=http-boot/([0-9a-fA-F]{16})`)

// extractEEPROMPackageSerial returns the device serial a pieeprom image was
// baked for, or "" when the image carries no per-device HTTP path (shared
// <soc>/<boot_order> packages).
func extractEEPROMPackageSerial(pieeprom []byte) string {
	m := eepromSerialPattern.FindSubmatch(pieeprom)
	if m == nil {
		return ""
	}
	return strings.ToLower(string(m[1]))
}

// eepromBootOrderPattern extracts the BOOT_ORDER setting from the config
// section of a pieeprom image (the firmware code itself never contains a
// literal "BOOT_ORDER=0x..." string).
var eepromBootOrderPattern = regexp.MustCompile(`BOOT_ORDER=(0x[0-9a-fA-F]+)`)

// ExtractEEPROMBootOrder returns the BOOT_ORDER hex baked into a pieeprom
// image (lowercase, e.g. "0xf167"), or "" if none is found.
func ExtractEEPROMBootOrder(pieeprom []byte) string {
	m := eepromBootOrderPattern.FindSubmatch(pieeprom)
	if m == nil {
		return ""
	}
	return strings.ToLower(string(m[1]))
}

// classifyEEPROMPackage decides whether an EEPROM recovery package found on a
// boot partition must be removed. pkgSerial is the serial baked into the
// image ("" if none), ownSerial this device's serial ("" if unknown), spent
// reports a RECOVERY.000 marker with no active recovery.bin, and inertMedium
// reports a medium the ROM never runs recovery.bin from (NVMe).
//
// A package baked for THIS device with an un-run recovery.bin on SD/USB is
// kept: it is a legitimately staged, not-yet-applied boot-order change.
func classifyEEPROMPackage(pkgSerial, ownSerial string, spent, inertMedium bool) (remove bool, reason string) {
	switch {
	case pkgSerial != "" && ownSerial != "" && !strings.EqualFold(pkgSerial, ownSerial):
		return true, "package baked for another device (reused provisioning card)"
	case spent:
		return true, "package already applied (RECOVERY.000 present)"
	case inertMedium:
		return true, "staged on NVMe, which the ROM never applies"
	default:
		return false, ""
	}
}
