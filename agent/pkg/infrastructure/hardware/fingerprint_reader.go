package hardware

import (
	"errors"
	"fmt"
	"net"
	"os"
	"regexp"
	"runtime"

	ports "agent/pkg/application/ports/out"
	"agent/pkg/domain/node"
)

// FingerprintReader implements the hardware fingerprint reading port
type FingerprintReader struct{}

// NewFingerprintReader creates a new hardware fingerprint reader
func NewFingerprintReader() ports.FingerprintReader {
	return &FingerprintReader{}
}

// Harvest collects hardware fingerprint information
func (r *FingerprintReader) Harvest() (node.HardwareFingerprint, error) {
	// Get hardware serial from /proc/cpuinfo
	serial := r.harvestHardwareSerial()

	// Get MAC address and IP addresses
	macAddress, err := r.harvestMacAddress()
	if err != nil {
		return node.HardwareFingerprint{}, fmt.Errorf("failed to harvest MAC address: %w", err)
	}

	return node.HardwareFingerprint{
		MacAddress:     macAddress,
		HardwareSerial: serial,
	}, nil
}

// harvestHardwareSerial extracts hardware serial from /proc/cpuinfo
func (r *FingerprintReader) harvestHardwareSerial() string {
	cpuinfo, err := os.ReadFile("/proc/cpuinfo")
	if err != nil {
		return "unknown"
	}

	re := regexp.MustCompile(`Serial\t*: ([a-z0-9]{16})`)
	match := re.FindStringSubmatch(string(cpuinfo))

	if len(match) > 1 {
		return match[1]
	}

	return "unknown"
}

// harvestMacAddress extracts MAC address from network interface
func (r *FingerprintReader) harvestMacAddress() (string, error) {
	defaultInterface := "eth0"
	if runtime.GOOS == "darwin" {
		defaultInterface = "en0"
	}

	netInterfaces, err := net.Interfaces()
	if err != nil {
		return "", fmt.Errorf("error getting interfaces: %w", err)
	}

	for _, netInterface := range netInterfaces {
		if netInterface.Name == defaultInterface {
			mac := netInterface.HardwareAddr.String()
			if mac != "" {
				return mac, nil
			}
		}
	}

	return "", errors.New("no suitable network interface found")
}
