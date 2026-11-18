//go:build linux

package hardware

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
)

// BootOrderReader reads boot order from Raspberry Pi EEPROM
type BootOrderReader struct{}

// NewBootOrderReader creates a new boot order reader
func NewBootOrderReader() *BootOrderReader {
	return &BootOrderReader{}
}

// GetBootOrderHex reads the boot order hex value from EEPROM
// Returns hex string like "0xf416" or empty string if not found
func (r *BootOrderReader) GetBootOrderHex(ctx context.Context) (string, error) {
	// Run vcgencmd to get bootloader config with context support for cancellation
	cmd := exec.CommandContext(ctx, "vcgencmd", "bootloader_config")
	output, err := cmd.Output()
	if err != nil {
		// Check if error is due to context cancellation
		if ctx.Err() != nil {
			return "", fmt.Errorf("boot order detection cancelled: %w", ctx.Err())
		}
		return "", fmt.Errorf("failed to run vcgencmd: %w", err)
	}

	// Parse output to find BOOT_ORDER line
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "BOOT_ORDER=") {
			// Extract hex value (e.g., "BOOT_ORDER=0xf416" -> "0xf416")
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				return strings.TrimSpace(parts[1]), nil
			}
		}
	}

	// BOOT_ORDER not found in config
	return "", nil
}

// GetBootOrder reads boot order and converts hex to array of boot device enums
// Returns array like ["nvme", "sd", "usb", "restart"]
func (r *BootOrderReader) GetBootOrder(ctx context.Context) ([]string, error) {
	hex, err := r.GetBootOrderHex(ctx)
	if err != nil {
		return nil, err
	}

	if hex == "" {
		return []string{}, nil
	}

	return hexToBootOrderArray(hex)
}

// hexByteToBootDevice converts a hex byte string (e.g., "06", "01", "0e", "0f") to boot device enum
// This is a shared mapping used by both boot mode detection and boot order
// Based on Raspberry Pi boot order documentation: https://www.raspberrypi.com/documentation/computers/raspberry-pi.html#BOOT_ORDER
// Returns empty string if unknown
func hexByteToBootDevice(hexByte string) string {
	// Map hex bytes to boot device enums
	// Boot mode uses hex bytes like "00", "01", "02", "03", "04", "05", "06", "07", "0e", "0f"
	hexByteMap := map[string]string{
		"00": "sd_card_detect", // SD Card Detect (deprecated)
		"01": "sd",             // SD/eMMC
		"02": "network",        // Network boot (PXE)
		"03": "rpiboot",        // RPIBOOT
		"04": "usb_msd",        // USB Mass Storage
		"05": "bcm_usb_msd",    // BCM USB Mass Storage
		"06": "nvme",           // NVMe
		"07": "http",           // HTTP boot
		"0e": "stop",           // Stop and display error pattern
		"0f": "restart",        // Restart (loop)
	}

	// Normalize hex byte (remove leading zeros, convert to lowercase)
	normalized := strings.ToLower(strings.TrimLeft(hexByte, "0"))
	if normalized == "" {
		normalized = "0"
	}

	// Try direct lookup first (with original case)
	normalizedHexByte := strings.ToLower(hexByte)
	if device, ok := hexByteMap[normalizedHexByte]; ok {
		return device
	}

	// Try normalized version (e.g., "1" -> "01", "e" -> "0e", "f" -> "0f")
	if len(normalized) == 1 {
		padded := "0" + normalized
		if device, ok := hexByteMap[padded]; ok {
			return device
		}
	}

	// Try with "0x" prefix removed if present
	if strings.HasPrefix(normalizedHexByte, "0x") {
		withoutPrefix := strings.TrimPrefix(normalizedHexByte, "0x")
		if device, ok := hexByteMap[withoutPrefix]; ok {
			return device
		}
		// Also try normalized version of the value without prefix
		normalizedWithoutPrefix := strings.ToLower(strings.TrimLeft(withoutPrefix, "0"))
		if normalizedWithoutPrefix == "" {
			normalizedWithoutPrefix = "0"
		}
		if len(normalizedWithoutPrefix) == 1 {
			padded := "0" + normalizedWithoutPrefix
			if device, ok := hexByteMap[padded]; ok {
				return device
			}
		}
	}

	return ""
}

// hexToBootOrderArray converts hex string to array of boot device enums
// Reads hex right-to-left and maps digits to device enums
func hexToBootOrderArray(hex string) ([]string, error) {
	// Remove 0x prefix if present
	hex = strings.TrimPrefix(strings.ToLower(hex), "0x")
	if hex == "" {
		return []string{}, nil
	}

	// Map hex digits to boot device enums (for boot order)
	// Boot order uses single hex digits based on Raspberry Pi documentation: https://www.raspberrypi.com/documentation/computers/raspberry-pi.html#BOOT_ORDER
	digitToDevice := map[rune]string{
		'0': "sd_card_detect",
		'1': "sd",
		'2': "network",
		'3': "rpiboot",
		'4': "usb_msd",
		'5': "bcm_usb_msd",
		'6': "nvme",
		'7': "http",
		'e': "stop",
		'f': "restart",
	}

	var bootOrder []string

	// Read hex right-to-left
	for i := len(hex) - 1; i >= 0; i-- {
		digit := rune(hex[i])
		if device, ok := digitToDevice[digit]; ok {
			bootOrder = append(bootOrder, device)
		} else {
			// Unknown digit, skip it
			continue
		}
	}

	return bootOrder, nil
}
