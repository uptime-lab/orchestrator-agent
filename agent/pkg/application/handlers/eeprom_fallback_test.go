package handlers

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestSharedEEPROMFallbackAllowedWithoutACapability(t *testing.T) {
	// No capability means the platform baked no per-serial image, so the shared
	// package is all there ever was and must keep working.
	cause := errors.New("unexpected status 404 for http://platform/net_install/eeprom/by-serial/10000000abcd0001/SHA256SUMS")
	if err := refusePerDeviceEEPROMFallback("", "the per-device package could not be fetched", cause); err != nil {
		t.Fatalf("fallback refused without a capability: %v", err)
	}
}

func TestSharedEEPROMFallbackRefusedWhenACapabilityWasSupplied(t *testing.T) {
	cause := fmt.Errorf("unexpected status %d for %s", 429, "http://platform/net_install/eeprom/by-serial/10000000abcd0001/SHA256SUMS?exp=1&sig=deadbeef")

	err := refusePerDeviceEEPROMFallback("?exp=1&sig=deadbeef",
		"the per-device package for serial 10000000abcd0001 could not be fetched", cause)
	if err == nil {
		t.Fatal("shared EEPROM package accepted although the platform supplied a per-serial capability")
	}
	if !errors.Is(err, cause) {
		t.Errorf("refusal does not wrap the fetch failure: %v", err)
	}

	// The HTTP status is the whole point: an operator must be able to tell an
	// expired capability from the boot-host ban gate.
	if !strings.Contains(err.Error(), "429") {
		t.Errorf("refusal drops the HTTP status: %v", err)
	}
	if !strings.Contains(err.Error(), "10000000abcd0001") {
		t.Errorf("refusal does not name the device: %v", err)
	}
}

func TestSharedEEPROMFallbackRefusalSurvivesReportRedaction(t *testing.T) {
	// The refusal travels to the platform through reportCommandStatus, which
	// redacts every URL in it. The status must survive that; the capability
	// signature must not.
	cause := fmt.Errorf("unexpected status %d for %s", 403,
		"http://platform/net_install/eeprom/by-serial/10000000abcd0001/SHA256SUMS?exp=1&sig=deadbeef")
	reported := redactURLsInText(refusePerDeviceEEPROMFallback("?exp=1&sig=deadbeef", "the per-device package could not be fetched", cause).Error())

	if !strings.Contains(reported, "403") {
		t.Errorf("HTTP status lost to redaction: %v", reported)
	}
	if strings.Contains(reported, "deadbeef") {
		t.Errorf("capability signature reported to the platform: %v", reported)
	}
}

func TestSharedEEPROMFallbackRefusalStatesTheConsequenceWithoutACause(t *testing.T) {
	err := refusePerDeviceEEPROMFallback("?exp=1&sig=deadbeef",
		"this device's hardware serial could not be read, so no per-device package could be requested", nil)
	if err == nil {
		t.Fatal("shared EEPROM package accepted although the platform supplied a per-serial capability")
	}
	for _, want := range []string{"adoption token", "netboot", "provision-eeprom"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal does not mention %q: %v", want, err)
		}
	}
}
