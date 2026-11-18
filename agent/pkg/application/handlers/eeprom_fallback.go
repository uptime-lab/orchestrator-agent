package handlers

import "fmt"

// Deliberately untagged, like manifest_verify.go: the rule it encodes is worth
// testing on a developer's machine and not only in the Linux CI container.

// refusePerDeviceEEPROMFallback decides whether an update_boot_order that cannot
// use this device's per-serial EEPROM package may fall back to the shared
// <soc>/<boot_order> one. It returns the error to fail the command with, or nil
// when the fallback is still legitimate.
//
// The platform mints the short-lived download capability (pkg_exp/pkg_sig,
// carried here as sigQuery) only after the eeprom-signer has baked and SIGNED an
// image for this serial — that image embeds this node's HTTP_PATH and its
// adoption token, and the shared package embeds neither. So with a capability in
// hand the shared package is not a fallback: flashing it overwrites the device's
// netboot identity while the command reports success, and the node cannot
// netboot again without physical access.
//
// Without a capability there is nothing per-serial to lose — the platform either
// predates the capability or never baked an image — so the shared package is
// still the right answer.
//
// cause is wrapped verbatim because it carries the HTTP status, which is what
// separates an expired capability from the boot-host ban gate from a bake that
// never happened.
func refusePerDeviceEEPROMFallback(sigQuery, detail string, cause error) error {
	if sigQuery == "" {
		return nil
	}
	const consequence = "; the shared image carries neither this device's per-serial netboot path nor its adoption token, " +
		"so flashing it would leave the node unable to netboot — re-run provision-eeprom to bake and sign a fresh per-serial image"
	if cause != nil {
		return fmt.Errorf("refusing to flash the shared EEPROM package: %s: %w"+consequence, detail, cause)
	}
	return fmt.Errorf("refusing to flash the shared EEPROM package: %s"+consequence, detail)
}
