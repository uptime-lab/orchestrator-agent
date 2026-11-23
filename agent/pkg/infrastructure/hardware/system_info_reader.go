//go:build linux

package hardware

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"agent/pkg/domain/board"
	proto "agent/pkg/infrastructure/grpc/proto"
)

// SystemInfoReader collects system information on Linux systems
type SystemInfoReader struct {
	logger *slog.Logger
}

// NewSystemInfoReader creates a new system info reader
func NewSystemInfoReader(logger *slog.Logger) *SystemInfoReader {
	return &SystemInfoReader{
		logger: logger,
	}
}

// SystemInfoComponents holds the collected system information components
type SystemInfoComponents struct {
	Network  *proto.NetworkInfo
	Hardware *proto.HardwareInfo
	OS       *proto.OSInfo
}

// CollectSystemInfo collects all system information including network, hardware, and OS details
func (r *SystemInfoReader) CollectSystemInfo(ctx context.Context) (*SystemInfoComponents, error) {
	components := &SystemInfoComponents{}

	// Collect network information
	networkInfo, err := r.collectNetworkInfo()
	if err != nil {
		return nil, fmt.Errorf("failed to collect network info: %w", err)
	}
	components.Network = networkInfo

	// Collect hardware information
	hardwareInfo, err := r.collectHardwareInfo(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to collect hardware info: %w", err)
	}
	components.Hardware = hardwareInfo

	// Collect OS information
	osInfo, err := r.collectOSInfo()
	if err != nil {
		return nil, fmt.Errorf("failed to collect OS info: %w", err)
	}
	components.OS = osInfo

	return components, nil
}

// collectNetworkInfo collects network information (IP address and hostname)
func (r *SystemInfoReader) collectNetworkInfo() (*proto.NetworkInfo, error) {
	networkInfo := &proto.NetworkInfo{}

	// Get hostname
	hostname, err := os.Hostname()
	if err != nil {
		// Fallback to reading from /etc/hostname
		if hostnameBytes, err := os.ReadFile("/etc/hostname"); err == nil {
			hostname = strings.TrimSpace(string(hostnameBytes))
		} else {
			hostname = "unknown"
		}
	}
	networkInfo.Hostname = hostname

	// Get primary IP address from network interfaces
	// Prefer eth0, then enp*, then any non-loopback interface
	ip := r.getPrimaryIP()
	networkInfo.Ip = ip

	return networkInfo, nil
}

// getPrimaryIP gets the primary IP address from network interfaces
func (r *SystemInfoReader) getPrimaryIP() string {
	interfaces, err := net.Interfaces()
	if err != nil {
		return ""
	}

	// Priority order: eth0, enp*, then any non-loopback interface
	var preferredIP string
	var fallbackIP string

	for _, iface := range interfaces {
		// Skip loopback and down interfaces
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		if iface.Flags&net.FlagUp == 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			default:
				continue
			}

			// Skip IPv6 for now, prefer IPv4
			if ip.To4() == nil {
				continue
			}

			ipStr := ip.String()

			// Prefer eth0
			if iface.Name == "eth0" {
				preferredIP = ipStr
				break
			}

			// Prefer enp* interfaces
			if strings.HasPrefix(iface.Name, "enp") && preferredIP == "" {
				preferredIP = ipStr
			}

			// Fallback to any non-loopback IPv4
			if fallbackIP == "" {
				fallbackIP = ipStr
			}
		}

		if preferredIP != "" && iface.Name == "eth0" {
			break
		}
	}

	if preferredIP != "" {
		return preferredIP
	}
	return fallbackIP
}

// collectHardwareInfo collects hardware information (CPU, RAM, TPM)
func (r *SystemInfoReader) collectHardwareInfo(ctx context.Context) (*proto.HardwareInfo, error) {
	hardwareInfo := &proto.HardwareInfo{}

	// Read CPU info from /proc/cpuinfo
	cpuinfo, err := os.ReadFile("/proc/cpuinfo")
	if err != nil {
		return nil, fmt.Errorf("failed to read /proc/cpuinfo: %w", err)
	}

	cpuinfoStr := string(cpuinfo)

	// Collect CPU information
	cpuInfo := &proto.CPUInfo{}
	cpuInfo.Model = r.extractCPUModel(cpuinfoStr)
	cpuInfo.Vendor = r.extractCPUVendor(cpuinfoStr)
	cpuInfo.Cores = uint32(r.countCPUCores(cpuinfoStr))
	cpuInfo.Info = r.extractCPUInfo(cpuinfoStr)
	// Raw board revision, decoded on the platform. Note this is the BOARD
	// "Revision" line the firmware writes from OTP, not the per-core "CPU
	// revision" that extractCPUInfo already folds into Info — they are
	// different fields with confusingly similar names.
	cpuInfo.BoardRevision = board.ExtractRevisionFromCPUInfo(cpuinfoStr)
	hardwareInfo.Cpu = cpuInfo

	// Collect RAM information
	ramSize, err := r.getRAMSize()
	if err != nil {
		return nil, fmt.Errorf("failed to get RAM size: %w", err)
	}
	ramInfo := &proto.RAMInfo{
		Size: ramSize,
	}
	hardwareInfo.Ram = ramInfo

	// Detect TPM (Trusted Platform Module)
	tpmInfo := r.detectTPM()
	tpmInfoProto := &proto.TPMInfo{
		Present:     tpmInfo.HasTPM,
		Version:     tpmInfo.Version,
		Model:       tpmInfo.Model,
		Description: tpmInfo.Description,
	}
	hardwareInfo.Tpm = tpmInfoProto

	// Collect booted_at + uptime from /proc/uptime (for all systems)
	bootedAt, uptimeSeconds, err := r.getBootedAtTimestamp()
	if err != nil {
		r.logger.Warn("failed to get booted_at/uptime", "error", err)
	}

	// Create BootInfo struct (for all systems, not just Raspberry Pi)
	bootInfo := &proto.BootInfo{}

	// Whether this is the recovery bootstrap, reported independently of the boot
	// medium. The platform holds managed-OS-only commands on it, and the boot
	// device cannot answer the question: the same initramfs reports "http" when
	// netbooted and "sd" when booted from a provisioning card, while having
	// neither groupadd nor systemd in either case.
	bootInfo.RecoveryBootstrap = RootIsEphemeral()

	// The device this system is actually running from, so the platform can mark
	// it rather than guess from the ROM's boot-mode CLASS (which cannot separate
	// two devices of the same kind — eMMC and an inserted SD card are both
	// mmcblk*). Empty in the recovery bootstrap, where the root is RAM and no
	// local device booted this node; that is the answer, not a failure.
	bootInfo.RootDevice = RootDevice()

	// How the root keeps writes — the platform refuses write-shaped commands
	// on an overlay root, where an apply would evaporate at the next boot
	// while its recorded hash suppresses the re-apply.
	bootInfo.RootPersistence = RootPersistence()

	// Set booted_at + uptime if we successfully collected them. uptime_seconds
	// is clock-independent, so it stays accurate even when booted_at collapses
	// to ~0 on RTC-less/netbooted devices with an unsynced wall clock.
	if err == nil {
		bootInfo.BootedAt = bootedAt
		bootInfo.UptimeSeconds = uptimeSeconds
	}

	// Collect boot information if Raspberry Pi
	isRPi, err := r.IsRaspberryPi()
	if err != nil {
		// Log error but continue
		r.logger.Warn("failed to check if Raspberry Pi", "error", err)
	} else if isRPi {
		// Detect current boot device
		currentBootDevice, err := r.detectBootMode()
		if err != nil {
			r.logger.Warn("failed to detect boot mode", "error", err)
		} else if currentBootDevice != "" {
			bootInfo.CurrentBootDevice = currentBootDevice
			r.logger.Info("boot mode detected", "current_boot_device", currentBootDevice)
		}

		// Get boot order
		bootOrderCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()

		bootOrderReader := NewBootOrderReader()
		bootOrder, err := bootOrderReader.GetBootOrder(bootOrderCtx)
		if err != nil {
			// Check if error is due to context cancellation/timeout
			if bootOrderCtx.Err() != nil {
				r.logger.Warn("boot order detection timed out or was cancelled", "error", err)
			} else {
				r.logger.Warn("failed to get boot order", "error", err)
			}
		} else {
			bootInfo.BootDevicesOrder = bootOrder
			if len(bootOrder) > 0 {
				r.logger.Info("boot order detected", "boot_order", bootOrder)
			} else {
				r.logger.Info("boot order is empty (no boot order configured)")
			}
		}

		// The EEPROM-baked netboot identity. HTTP_HOST: the platform compares
		// it to its own boot host to detect a device still pointing at a
		// different install and gate netboot-recovery. HTTP_PATH: the readback
		// the phase-2 httpboot design enforces a per-device path secret
		// against — a flash dispatch's success says the command ran, not what
		// the ROM now holds.
		if host, path := r.detectEEPROMNetbootIdentity(ctx); host != "" || path != "" {
			bootInfo.BootHttpHost = host
			bootInfo.BootHttpPath = path
			r.logger.Info("eeprom netboot identity detected", "http_host", host, "http_path", path)
		}

		// The RUNNING EEPROM firmware version. Reported by the agent (not just
		// captured during an HTTP-boot) so it is present for NAT'd/steady-state
		// nodes that boot their local OS and never netboot.
		if ver, ts := r.detectBootloaderVersion(ctx); ver != "" {
			bootInfo.BootloaderVersion = ver
			bootInfo.BootloaderTimestamp = ts
			r.logger.Info("eeprom bootloader version detected", "version", ver, "timestamp", ts)
		}
	}

	// Set boot info (always set it, even if only booted_at is available)
	hardwareInfo.Boot = bootInfo

	// Detect EEPROM enablement status if Raspberry Pi
	if isRPi {
		eepromEnabled, eepromDescription, err := r.detectEEPROMEnabled()
		if err != nil {
			r.logger.Warn("failed to detect EEPROM enablement status", "error", err)
			// Default to disabled if detection fails
			eepromEnabled = false
			eepromDescription = "EEPROM detection failed"
		}
		hardwareInfo.Eeprom = &proto.EEPROMInfo{
			Enabled:     eepromEnabled,
			Description: eepromDescription,
		}
	} else {
		r.logger.Debug("not a Raspberry Pi, skipping EEPROM detection")
	}

	// What else is plugged in. Cheap (a directory walk, no commands) and works in
	// the recovery bootstrap; storage is excluded because a USB disk is already a
	// StorageDevice and two records for one object invite an operator to reason
	// about them separately.
	for _, d := range ReadUSBDevices() {
		hardwareInfo.Usb = append(hardwareInfo.Usb, &proto.USBDevice{
			VendorId:     d.VendorID,
			ProductId:    d.ProductID,
			Manufacturer: d.Manufacturer,
			Product:      d.Product,
			ClassCode:    d.ClassCode,
			Speed:        d.Speed,
			Port:         d.Port,
		})
	}

	// Spec-compliant HAT ID EEPROM, when the firmware exposed one. ABSENT (nil)
	// when no HAT is present — the platform treats presence itself as the fact.
	hardwareInfo.Hat = ReadHatInfo()

	// Power / thermal throttling. Read here rather than behind a command, because
	// the sticky half of the bitmask is what explains a failure AFTER it happened
	// — exactly when nobody is there to run a probe. Left ABSENT where the device
	// cannot answer: a zeroed report would say "the supply is fine" about hardware
	// that has no idea.
	//
	// FRESHNESS, because this function is NOT periodic. It runs on CONNECT, on
	// RECONNECT, and from the hardware-info reporter callback after a command
	// that changes hardware state; the only timers in AgentService are liveness
	// 10s, heartbeat 30s and the live metrics sample 5s. So system_info on a
	// node with a long-lived stream can be hours or days stale.
	//
	// What closes the gap is AgentService.startPowerWatch, which polls ONLY
	// get_throttled once a minute and calls back here when the mask CHANGES — so
	// a sag that never breaks the stream is reported, while a healthy node sends
	// nothing extra for its whole uptime. Do not move power into the 5s metrics
	// sample instead: those are dropped when disconnected and never land in
	// system_info, so the sticky evidence would not survive.
	if isRPi {
		if flags, ok := r.detectThrottledFlags(ctx); ok {
			hardwareInfo.Power = &proto.PowerInfo{ThrottledFlags: flags}
			if flags != 0 {
				// Worth a line in the agent's own log too: this is the signal that
				// explains failures nothing else on the node can explain.
				r.logger.Warn("power/thermal throttling reported by the SoC",
					"throttled_flags", fmt.Sprintf("0x%x", flags))
			}
		}
	}

	return hardwareInfo, nil
}

// IsRaspberryPi checks if the system is a Raspberry Pi by examining CPU model
// Reads /proc/cpuinfo directly to avoid recursion with collectHardwareInfo()
func (r *SystemInfoReader) IsRaspberryPi() (bool, error) {
	// Read CPU info directly from /proc/cpuinfo to avoid recursion
	cpuinfo, err := os.ReadFile("/proc/cpuinfo")
	if err != nil {
		return false, fmt.Errorf("failed to read /proc/cpuinfo: %w", err)
	}

	cpuinfoStr := string(cpuinfo)

	// Extract CPU model using the same method as collectHardwareInfo
	cpuModel := r.extractCPUModel(cpuinfoStr)

	// Check if CPU model contains "Raspberry Pi"
	if cpuModel != "" {
		return strings.Contains(strings.ToLower(cpuModel), "raspberry pi"), nil
	}

	return false, nil
}

// ParseBoardRevision reads and decodes this device's board revision code.
// Returns ok=false when there is no usable code; callers must fall back rather
// than assume a board.
func ParseBoardRevision() (board.Revision, bool) {
	data, err := os.ReadFile("/proc/cpuinfo")
	if err != nil {
		return board.Revision{}, false
	}
	return board.ParseRevision(board.ExtractRevisionFromCPUInfo(string(data)))
}

// extractCPUModel extracts CPU model from /proc/cpuinfo
func (r *SystemInfoReader) extractCPUModel(cpuinfo string) string {
	// Try "model name" first (x86_64)
	re := regexp.MustCompile(`model name\s*:\s*(.+)`)
	match := re.FindStringSubmatch(cpuinfo)
	if len(match) > 1 {
		return strings.TrimSpace(match[1])
	}

	// Try "Model" (ARM/Raspberry Pi) - this appears at the end of cpuinfo
	re = regexp.MustCompile(`Model\s*:\s*(.+)`)
	match = re.FindStringSubmatch(cpuinfo)
	if len(match) > 1 {
		return strings.TrimSpace(match[1])
	}

	// Try "Processor" (ARM)
	re = regexp.MustCompile(`Processor\s*:\s*(.+)`)
	match = re.FindStringSubmatch(cpuinfo)
	if len(match) > 1 {
		return strings.TrimSpace(match[1])
	}

	// Try "Hardware" (ARM)
	re = regexp.MustCompile(`Hardware\s*:\s*(.+)`)
	match = re.FindStringSubmatch(cpuinfo)
	if len(match) > 1 {
		return strings.TrimSpace(match[1])
	}

	return "unknown"
}

// extractCPUVendor extracts CPU vendor from /proc/cpuinfo
func (r *SystemInfoReader) extractCPUVendor(cpuinfo string) string {
	// Try "vendor_id" (x86_64)
	re := regexp.MustCompile(`vendor_id\s*:\s*(.+)`)
	match := re.FindStringSubmatch(cpuinfo)
	if len(match) > 1 {
		vendor := strings.TrimSpace(match[1])
		// Normalize common vendor names
		if strings.Contains(strings.ToLower(vendor), "genuineintel") {
			return "Intel"
		}
		if strings.Contains(strings.ToLower(vendor), "authenticamd") {
			return "AMD"
		}
		return vendor
	}

	// Try "CPU implementer" (ARM)
	re = regexp.MustCompile(`CPU implementer\s*:\s*0x([0-9a-fA-F]+)`)
	match = re.FindStringSubmatch(cpuinfo)
	if len(match) > 1 {
		implementer := strings.TrimSpace(match[1])
		// Common ARM implementers
		switch implementer {
		case "41":
			return "ARM"
		case "69":
			return "Intel"
		case "48":
			return "HiSilicon"
		default:
			return "ARM (0x" + implementer + ")"
		}
	}

	return "unknown"
}

// extractCPUInfo extracts additional CPU information
func (r *SystemInfoReader) extractCPUInfo(cpuinfo string) string {
	var infoParts []string

	// Extract CPU part (ARM) - identifies the specific CPU core (e.g., 0xd08 = Cortex-A72)
	re := regexp.MustCompile(`CPU part\s*:\s*0x([0-9a-fA-F]+)`)
	match := re.FindStringSubmatch(cpuinfo)
	if len(match) > 1 {
		cpuPart := strings.TrimSpace(match[1])
		// Map common ARM CPU parts to readable names
		switch cpuPart {
		case "d08":
			infoParts = append(infoParts, "Cortex-A72")
		case "d03":
			infoParts = append(infoParts, "Cortex-A53")
		case "d07":
			infoParts = append(infoParts, "Cortex-A57")
		case "d09":
			infoParts = append(infoParts, "Cortex-A73")
		case "d0a":
			infoParts = append(infoParts, "Cortex-A75")
		case "d0b":
			infoParts = append(infoParts, "Cortex-A76")
		case "d0c":
			infoParts = append(infoParts, "Cortex-A55")
		case "d0d":
			infoParts = append(infoParts, "Cortex-A77")
		case "d40":
			infoParts = append(infoParts, "Cortex-A78")
		case "d41":
			infoParts = append(infoParts, "Cortex-X1")
		default:
			infoParts = append(infoParts, "CPU Part: 0x"+cpuPart)
		}
	}

	// Extract CPU revision (ARM)
	re = regexp.MustCompile(`CPU revision\s*:\s*(\d+)`)
	match = re.FindStringSubmatch(cpuinfo)
	if len(match) > 1 {
		infoParts = append(infoParts, "Revision: "+strings.TrimSpace(match[1]))
	}

	// Extract CPU architecture (ARM)
	re = regexp.MustCompile(`CPU architecture\s*:\s*(\d+)`)
	match = re.FindStringSubmatch(cpuinfo)
	if len(match) > 1 {
		arch := strings.TrimSpace(match[1])
		switch arch {
		case "8":
			infoParts = append(infoParts, "ARMv8")
		case "7":
			infoParts = append(infoParts, "ARMv7")
		case "6":
			infoParts = append(infoParts, "ARMv6")
		default:
			infoParts = append(infoParts, "ARMv"+arch)
		}
	}

	// For x86_64, try to get model name or processor info
	if len(infoParts) == 0 {
		lines := strings.Split(cpuinfo, "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "model name") || strings.HasPrefix(line, "Processor") {
				parts := strings.SplitN(line, ":", 2)
				if len(parts) == 2 {
					infoParts = append(infoParts, strings.TrimSpace(parts[1]))
				}
			}
		}
	}

	if len(infoParts) > 0 {
		return strings.Join(infoParts, "; ")
	}

	return ""
}

// countCPUCores counts the number of CPU cores
func (r *SystemInfoReader) countCPUCores(cpuinfo string) int {
	// Count unique processor entries using multiline mode
	// (?m) enables multiline mode where ^ matches start of line
	re := regexp.MustCompile(`(?m)^processor\s*:\s*\d+`)
	matches := re.FindAllString(cpuinfo, -1)
	if len(matches) > 0 {
		return len(matches)
	}

	// Fallback: try to read from /proc/cpuinfo or use lscpu
	// Try lscpu command as fallback
	cmd := exec.Command("lscpu")
	output, err := cmd.Output()
	if err == nil {
		re = regexp.MustCompile(`^CPU\(s\):\s*(\d+)`)
		match := re.FindStringSubmatch(string(output))
		if len(match) > 1 {
			if cores, err := strconv.Atoi(strings.TrimSpace(match[1])); err == nil {
				return cores
			}
		}
	}

	// Last resort: count physical cores from cpuinfo
	re = regexp.MustCompile(`(?m)^physical id\s*:\s*\d+`)
	physicalIDs := make(map[string]bool)
	matches = re.FindAllString(cpuinfo, -1)
	for _, match := range matches {
		physicalIDs[match] = true
	}

	if len(physicalIDs) > 0 {
		// Count cores per physical ID
		re = regexp.MustCompile(`(?m)^cpu cores\s*:\s*(\d+)`)
		coreMatches := re.FindAllStringSubmatch(cpuinfo, -1)
		if len(coreMatches) > 0 {
			totalCores := 0
			for _, match := range coreMatches {
				if cores, err := strconv.Atoi(strings.TrimSpace(match[1])); err == nil {
					totalCores += cores
				}
			}
			if totalCores > 0 {
				return totalCores
			}
		}
	}

	return 1 // Default to 1 if we can't determine
}

// getRAMSize gets the total RAM size in bytes from /proc/meminfo
func (r *SystemInfoReader) getRAMSize() (uint64, error) {
	meminfo, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0, fmt.Errorf("failed to read /proc/meminfo: %w", err)
	}

	// Look for "MemTotal" line
	re := regexp.MustCompile(`MemTotal:\s*(\d+)\s*kB`)
	match := re.FindStringSubmatch(string(meminfo))
	if len(match) > 1 {
		kb, err := strconv.ParseUint(strings.TrimSpace(match[1]), 10, 64)
		if err != nil {
			return 0, fmt.Errorf("failed to parse memory size: %w", err)
		}
		// Convert from KB to bytes
		return kb * 1024, nil
	}

	return 0, fmt.Errorf("MemTotal not found in /proc/meminfo")
}

// tpmInfo holds TPM detection results
type tpmInfo struct {
	HasTPM      bool
	Version     string
	Model       string
	Description string
}

// detectTPM detects if a TPM (Trusted Platform Module) is present and collects its information
// Based on Linux TPM detection methods:
// - Checks /sys/class/tpm/tpm0 directory existence
// - Checks /dev/tpm0 or /dev/tpmrm0 device files
// - Reads TPM version from sysfs
// - Reads TPM description if available
func (r *SystemInfoReader) detectTPM() tpmInfo {
	info := tpmInfo{
		HasTPM:      false,
		Version:     "",
		Model:       "",
		Description: "",
	}

	// Check if TPM sysfs directory exists (most reliable method)
	tpmSysfsPath := "/sys/class/tpm/tpm0"
	if _, err := os.Stat(tpmSysfsPath); os.IsNotExist(err) {
		// TPM not found via sysfs, try checking device files as fallback
		if _, err := os.Stat("/dev/tpm0"); os.IsNotExist(err) {
			if _, err := os.Stat("/dev/tpmrm0"); os.IsNotExist(err) {
				return info // No TPM found
			}
		}
		// Device file exists but no sysfs, TPM might be present but not fully initialized
		// Still report as found but without version info
		info.HasTPM = true
		return info
	}

	// TPM sysfs directory exists, TPM is present
	info.HasTPM = true

	// Read TPM version from sysfs
	versionMajorPath := fmt.Sprintf("%s/tpm_version_major", tpmSysfsPath)
	versionMinorPath := fmt.Sprintf("%s/tpm_version_minor", tpmSysfsPath)

	majorBytes, err := os.ReadFile(versionMajorPath)
	if err == nil {
		major := strings.TrimSpace(string(majorBytes))
		minorBytes, err := os.ReadFile(versionMinorPath)
		if err == nil {
			minor := strings.TrimSpace(string(minorBytes))
			info.Version = fmt.Sprintf("%s.%s", major, minor)
		} else {
			// Only major version available
			info.Version = major
		}
	}

	// Extract TPM model from various sources
	// Try 1: Extract model from device tree node path (e.g., "slb9670" from "slb9670@1")
	// We need to find the TPM chip model, not the SPI bus identifier (e.g., "spi@7e204000")
	ofNodePath := fmt.Sprintf("%s/device/of_node", tpmSysfsPath)
	if link, err := os.Readlink(ofNodePath); err == nil {
		// Extract model from path like "../../firmware/devicetree/base/soc/spi@7e204000/slb9670@1"
		// We want the last part with @ that's not "spi@" or common bus identifiers
		parts := strings.Split(link, "/")
		// Common bus identifiers to skip
		skipPatterns := []string{"spi@", "i2c@", "usb@", "pci@", "platform@"}

		// Iterate in reverse to get the last (most specific) device identifier
		for i := len(parts) - 1; i >= 0; i-- {
			part := parts[i]
			if strings.Contains(part, "@") {
				// Check if this is a bus identifier we should skip
				shouldSkip := false
				for _, pattern := range skipPatterns {
					if strings.HasPrefix(strings.ToLower(part), pattern) {
						shouldSkip = true
						break
					}
				}
				if !shouldSkip {
					// Extract the part before @ (the model)
					modelParts := strings.Split(part, "@")
					if len(modelParts) > 0 && modelParts[0] != "" {
						model := strings.ToUpper(modelParts[0])
						// Additional safeguard: don't use generic bus names as model
						genericNames := []string{"SPI", "I2C", "USB", "PCI", "PLATFORM", "SERIAL", "UART"}
						isGeneric := false
						for _, generic := range genericNames {
							if model == generic {
								isGeneric = true
								break
							}
						}
						if !isGeneric {
							info.Model = model
							break
						}
					}
				}
			}
		}
	}

	// Try 2: Read from uevent file (contains device information)
	if info.Model == "" {
		ueventPath := fmt.Sprintf("%s/device/uevent", tpmSysfsPath)
		ueventBytes, err := os.ReadFile(ueventPath)
		if err == nil {
			// Parse uevent file for MODEL field
			lines := strings.Split(string(ueventBytes), "\n")
			for _, line := range lines {
				if strings.HasPrefix(line, "MODEL=") {
					model := strings.TrimPrefix(line, "MODEL=")
					if model != "" {
						info.Model = strings.TrimSpace(model)
						break
					}
				}
			}
		}
	}

	// Try 3: Read from modalias file (contains device identifier)
	if info.Model == "" {
		modaliasPath := fmt.Sprintf("%s/device/modalias", tpmSysfsPath)
		modaliasBytes, err := os.ReadFile(modaliasPath)
		if err == nil {
			modalias := strings.TrimSpace(string(modaliasBytes))
			// Modalias format: "spi:slb9670" or similar
			// Extract the model part after the colon
			if strings.Contains(modalias, ":") {
				parts := strings.Split(modalias, ":")
				if len(parts) > 1 && parts[1] != "" {
					info.Model = strings.ToUpper(parts[1])
				}
			}
		}
	}

	// Read TPM description from description file (if available) - this is separate from model
	descriptionPath := fmt.Sprintf("%s/device/description", tpmSysfsPath)
	descBytes, err := os.ReadFile(descriptionPath)
	if err == nil {
		info.Description = strings.TrimSpace(string(descBytes))
	}

	return info
}

// detectBootMode detects the current boot mode from device tree
// Returns boot device string: "sd", "usb", "nvme", "http", or empty string if unknown/failed
// detectEEPROMNetbootIdentity returns the HTTP_HOST and HTTP_PATH baked into
// the RPi EEPROM (the netboot server and per-serial path this device fetches
// boot.img from), each "" when unavailable (not a Pi, tooling missing, or not
// configured). One rpi-eeprom-config call for both. Best-effort: never fails
// system-info reporting.
func (r *SystemInfoReader) detectEEPROMNetbootIdentity(ctx context.Context) (string, string) {
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(cctx, "sudo", "rpi-eeprom-config").Output()
	if err != nil {
		return "", ""
	}
	var host, path string
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if v, ok := strings.CutPrefix(line, "HTTP_HOST="); ok {
			host = strings.TrimSpace(v)
		}
		if v, ok := strings.CutPrefix(line, "HTTP_PATH="); ok {
			path = strings.TrimSpace(v)
		}
	}
	return host, path
}

// detectBootloaderVersion reads the running EEPROM firmware version via
// `vcgencmd bootloader_version`. The first line is the build date
// (e.g. "2024/06/05 15:30:37"), followed by a version hash and a
// "timestamp <unix>" line. Returns the raw first-line version string and the
// build date as a Unix timestamp (0 if it cannot be parsed). Best-effort:
// returns "" wherever vcgencmd is absent or fails, which in practice means
// non-Pi hardware.
//
// It is NOT absent in the recovery bootstrap — this comment claimed it was
// until `which vcgencmd` on a netbooted node (Buildroot
// 2026.02.3, RAM-backed root) answered /usr/bin/vcgencmd and
// `vcgencmd bootloader_version` returned the full hash and timestamp lines. So
// a netbooted node DOES contribute the 40-hex bootloader version that wins over
// the httpboot handler's short UA hash; do not add a recovery-mode skip here.
func (r *SystemInfoReader) detectBootloaderVersion(ctx context.Context) (string, int64) {
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(cctx, "vcgencmd", "bootloader_version").Output()
	if err != nil {
		return "", 0
	}
	return parseBootloaderVersion(string(out))
}

// parseBootloaderVersion extracts the firmware version HASH and build timestamp
// from `vcgencmd bootloader_version` output. Pure, so the parsing is testable
// without the RPi binary.
//
// The output is, e.g.:
//
//	2024/06/05 15:30:37          <- build date
//	version 0123456789abcdef...  <- the firmware git hash
//	timestamp 1717601437         <- build date as unix seconds
//	update-time 0
//
// The HASH (not the date) is returned as the version, because the whole
// freshness feature compares this field against the signer's base-firmware
// hash and the httpboot handler records a hash too — returning the date string
// would make the "Up to date" badge never match and clobber a correct
// httpboot-captured hash. The build date is returned separately as the
// timestamp.
func parseBootloaderVersion(out string) (string, int64) {
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) == 0 || strings.TrimSpace(lines[0]) == "" {
		return "", 0
	}
	var version string
	var ts int64
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if v, ok := strings.CutPrefix(line, "version "); ok {
			// Just the hash token: vcgencmd appends a channel suffix
			// (e.g. "f68405bc... (release)") that the freshness badge must not
			// see, or a current node reads as outdated.
			if f := strings.Fields(v); len(f) > 0 {
				version = f[0]
			}
		}
		// Explicit "timestamp <unix>" line is the authoritative build date.
		if v, ok := strings.CutPrefix(line, "timestamp "); ok {
			if n, perr := strconv.ParseInt(strings.TrimSpace(v), 10, 64); perr == nil {
				ts = n
			}
		}
	}
	// Fall back to the first line as the build date when no timestamp line.
	if ts == 0 {
		if t, perr := time.Parse("2006/01/02 15:04:05", strings.TrimSpace(lines[0])); perr == nil {
			ts = t.Unix()
		}
	}
	return version, ts
}

func (r *SystemInfoReader) detectBootMode() (string, error) {
	// Run od command to read boot mode from device tree
	cmd := exec.Command("od", "-An", "-t", "x1", "/proc/device-tree/chosen/bootloader/boot-mode")
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to run od command: %w", err)
	}

	// Parse hex output (e.g., "00 00 00 06" = NVMe)
	outputStr := strings.TrimSpace(string(output))
	parts := strings.Fields(outputStr)
	if len(parts) < 4 {
		return "", fmt.Errorf("unexpected boot mode output format: %s", outputStr)
	}

	// Get the last hex byte (the boot mode value)
	// Format is typically "00 00 00 06" where 06 is the boot mode
	lastByte := parts[len(parts)-1]

	// Use the shared mapping from boot_order_reader.go
	device := hexByteToBootDevice(lastByte)
	if device == "" {
		return "", fmt.Errorf("unknown boot mode: %s", lastByte)
	}

	return device, nil
}

// detectEEPROMEnabled detects if EEPROM updates are enabled on Raspberry Pi
// Returns (enabled bool, description string, error)
func (r *SystemInfoReader) detectEEPROMEnabled() (bool, string, error) {
	// The board decides which of the settings below are meaningful at all.
	// Unreadable model = treat as non-CM4: demanding CM4 evidence from hardware
	// we cannot identify is what produced the permanent false "disabled".
	boardModel := ""
	if data, err := os.ReadFile("/proc/device-tree/model"); err == nil {
		boardModel = string(bytes.Trim(data, "\x00"))
	}

	// Check /etc/default/rpi-eeprom-update for required settings
	eepromUpdateConfigPath := "/etc/default/rpi-eeprom-update"
	hasFlashrom := false
	hasCM4Enable := false

	if _, err := os.Stat(eepromUpdateConfigPath); err == nil {
		content, err := os.ReadFile(eepromUpdateConfigPath)
		if err == nil {
			lines := strings.Split(string(content), "\n")
			for _, line := range lines {
				trimmed := strings.TrimSpace(line)
				// Skip comments
				if strings.HasPrefix(trimmed, "#") {
					continue
				}
				if strings.HasPrefix(trimmed, "RPI_EEPROM_USE_FLASHROM=") {
					parts := strings.SplitN(trimmed, "=", 2)
					if len(parts) == 2 && strings.TrimSpace(parts[1]) == "1" {
						hasFlashrom = true
					}
				}
				if strings.HasPrefix(trimmed, "CM4_ENABLE_RPI_EEPROM_UPDATE=") {
					parts := strings.SplitN(trimmed, "=", 2)
					if len(parts) == 2 && strings.TrimSpace(parts[1]) == "1" {
						hasCM4Enable = true
					}
				}
			}
		}
	}

	// Check config.txt for CM4 settings
	configTxtPaths := []string{"/boot/firmware/config.txt", "/boot/config.txt"}
	var configContent string

	for _, path := range configTxtPaths {
		if _, err := os.Stat(path); err == nil {
			content, err := os.ReadFile(path)
			if err == nil {
				configContent = string(content)
				break
			}
		}
	}

	hasSPIInCM4 := false
	hasAudremapInCM4 := false
	hasSPIGPIOInCM4 := false
	hasCM4Section := false

	if configContent != "" {
		lines := strings.Split(configContent, "\n")
		inCM4Section := false

		for _, line := range lines {
			trimmed := strings.TrimSpace(line)

			if trimmed == "[cm4]" {
				hasCM4Section = true
				inCM4Section = true
				continue
			}

			// If we're in the [cm4] section and hit another section, exit it
			if inCM4Section && strings.HasPrefix(trimmed, "[") && trimmed != "[cm4]" {
				inCM4Section = false
			}

			// Check for settings within [cm4] section
			if inCM4Section {
				if trimmed == "dtparam=spi=on" {
					hasSPIInCM4 = true
				} else if trimmed == "dtoverlay=audremap" {
					hasAudremapInCM4 = true
				} else if trimmed == "dtoverlay=spi-gpio40-45" {
					hasSPIGPIOInCM4 = true
				}
			}
		}
	}

	// What "enabled" means depends on the BOARD, which this check used to
	// ignore: it demanded all six CM4 markers everywhere. Only
	// RPI_EEPROM_USE_FLASHROM is universal — CM4_ENABLE_RPI_EEPROM_UPDATE is
	// read by rpi-eeprom-update on CM4 alone, and a [cm4] filter in config.txt
	// never matches a CM5/Pi5, so those overlays cannot apply there. The result
	// was that a CM5 with the one setting that matters to it reported "disabled"
	// forever, and the UI offered a CM4 remedy plus a pointless reboot.
	//
	// The CM5 half was fixed by the substring test below; the BCM2711 half was
	// not, because `Contains(model, "Pi 4")` also catches a Pi 4 B and a Pi 400,
	// which the [cm4] filter does not match either — so those reported
	// "disabled" forever for exactly the same reason. Decided from the board
	// revision code now, which names the board exactly; the substring test stays
	// as the fallback for hardware that reports no revision at all.
	isCM4 := false
	if rev, ok := ParseBoardRevision(); ok {
		isCM4 = rev.MatchesCM4Filter()
	} else {
		isCM4 = strings.Contains(boardModel, "Compute Module 4")
	}

	enabled := hasFlashrom
	var missing []string
	if !hasFlashrom {
		missing = append(missing, "RPI_EEPROM_USE_FLASHROM=1")
	}
	if isCM4 {
		enabled = enabled && hasCM4Enable && hasCM4Section && hasSPIInCM4 && hasAudremapInCM4 && hasSPIGPIOInCM4
		if !hasCM4Enable {
			missing = append(missing, "CM4_ENABLE_RPI_EEPROM_UPDATE=1")
		}
		if !hasCM4Section {
			missing = append(missing, "[cm4] section")
		} else {
			if !hasSPIInCM4 {
				missing = append(missing, "dtparam=spi=on")
			}
			if !hasAudremapInCM4 {
				missing = append(missing, "dtoverlay=audremap")
			}
			if !hasSPIGPIOInCM4 {
				missing = append(missing, "dtoverlay=spi-gpio40-45")
			}
		}
	}

	var description string
	if enabled {
		description = "EEPROM updates enabled"
	} else if len(missing) > 0 {
		description = "EEPROM updates disabled - missing: " + strings.Join(missing, ", ")
	} else {
		description = "EEPROM updates disabled"
	}

	return enabled, description, nil
}

// getBootedAtTimestamp reads /proc/uptime and returns both the absolute
// booted_at timestamp and the raw uptime in seconds. booted_at depends on the
// wall clock (unreliable on RTC-less/netbooted devices where the clock may be
// unsynced); uptimeSeconds is clock-independent and always trustworthy.
func (r *SystemInfoReader) getBootedAtTimestamp() (bootedAt int64, uptimeSeconds int64, err error) {
	// Read /proc/uptime
	uptimeData, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0, 0, fmt.Errorf("failed to read /proc/uptime: %w", err)
	}

	// Parse uptime (format: "uptime_seconds idle_seconds")
	uptimeStr := strings.TrimSpace(string(uptimeData))
	parts := strings.Fields(uptimeStr)
	if len(parts) == 0 {
		return 0, 0, fmt.Errorf("invalid /proc/uptime format: empty")
	}

	// Parse first value (uptime in seconds)
	uptimeFloat, err := strconv.ParseFloat(parts[0], 64)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to parse uptime: %w", err)
	}

	// Calculate booted_at = current_time - uptime_seconds
	now := time.Now()
	uptimeSeconds = int64(uptimeFloat)
	bootedAt = now.Unix() - uptimeSeconds

	return bootedAt, uptimeSeconds, nil
}

// collectOSInfo collects OS information from /etc/os-release
func (r *SystemInfoReader) collectOSInfo() (*proto.OSInfo, error) {
	osInfo := &proto.OSInfo{}

	// Read /etc/os-release
	osRelease, err := os.ReadFile("/etc/os-release")
	if err != nil {
		// Fallback: try to get basic info from uname
		cmd := exec.Command("uname", "-r")
		if output, err := cmd.Output(); err == nil {
			osInfo.Version = strings.TrimSpace(string(output))
			osInfo.Details = "Linux " + osInfo.Version
			return osInfo, nil
		}
		return nil, fmt.Errorf("failed to read /etc/os-release: %w", err)
	}

	// Parse os-release file
	lines := strings.Split(string(osRelease), "\n")
	var name, version, prettyName string

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "NAME=") {
			name = strings.Trim(strings.TrimPrefix(line, "NAME="), "\"")
		} else if strings.HasPrefix(line, "VERSION=") {
			version = strings.Trim(strings.TrimPrefix(line, "VERSION="), "\"")
		} else if strings.HasPrefix(line, "PRETTY_NAME=") {
			prettyName = strings.Trim(strings.TrimPrefix(line, "PRETTY_NAME="), "\"")
		}
	}

	// Set version
	if version != "" {
		osInfo.Version = version
	} else {
		// Fallback to uname -r
		cmd := exec.Command("uname", "-r")
		if output, err := cmd.Output(); err == nil {
			osInfo.Version = strings.TrimSpace(string(output))
		} else {
			osInfo.Version = "unknown"
		}
	}

	// Set details
	if prettyName != "" {
		osInfo.Details = prettyName
	} else if name != "" && version != "" {
		osInfo.Details = name + " " + version
	} else if name != "" {
		osInfo.Details = name
	} else {
		osInfo.Details = "Linux " + osInfo.Version
	}

	return osInfo, nil
}
