//go:build linux

package hardware

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	proto "agent/pkg/infrastructure/grpc/proto"
)

// StorageReader detects available storage devices on Linux systems
type StorageReader struct{}

// skipBlockDevice reports whether a /sys/block entry must never be offered as a
// storage device. One list, called from all three detection paths — they used to
// carry three slightly different inline conditions.
//
// Beyond the usual pseudo-devices, this excludes the eMMC **boot partitions and
// RPMB area**. They are separate block devices with their own /sys/block entries,
// they inherit the parent's device/type, and they are not storage: a non-Lite CM5
// therefore reported its single eMMC as THREE devices — `mmcblk0` at 58 GB plus
// `mmcblk0boot0` and `mmcblk0boot1` at 0 GB — and all three appeared in the
// install-target picker. Naming them eMMC made that worse rather
// than better: one medium, three identical-looking rows to choose from, two of
// which cannot be installed to at all.
//
// Filtered by NAME rather than by a zero size on purpose: the name is a kernel
// fact about what the device IS, while a zero size is also what a transient read
// failure or an empty card reader looks like, and a device silently vanishing
// from the picker for that reason would be its own bug.
func skipBlockDevice(name string) bool {
	switch {
	case strings.HasPrefix(name, "loop"),
		strings.HasPrefix(name, "sr"),
		strings.HasPrefix(name, "ram"),
		strings.HasPrefix(name, "zram"):
		return true
	}
	// mmcblkNbootM / mmcblkNrpmb — eMMC-only areas, never install targets. Match
	// on what follows the controller number, so `mmcblk0` and a `mmcblk0p1`
	// partition (filtered elsewhere, as a partition) are both left alone.
	if rest, ok := strings.CutPrefix(name, "mmcblk"); ok {
		i := 0
		for i < len(rest) && rest[i] >= '0' && rest[i] <= '9' {
			i++
		}
		switch suffix := rest[i:]; {
		case strings.HasPrefix(suffix, "boot"), suffix == "rpmb":
			return true
		}
	}
	return false
}

// NewStorageReader creates a new storage reader
func NewStorageReader() *StorageReader {
	return &StorageReader{}
}

// DetectDevices detects available storage devices and returns a map of device paths to StorageDevice metadata
func (r *StorageReader) DetectDevices() (map[string]*proto.StorageDevice, error) {
	devices := make(map[string]*proto.StorageDevice)

	// Get mount information for filesystem and usage data
	mountInfo := r.getMountInfo()

	// Method 1: Try lsblk with JSON output first (handles spaces in MODEL/VENDOR)
	cmd := exec.Command("lsblk", "-d", "-b", "-J", "-o", "NAME,SIZE,MODEL,VENDOR,SERIAL,TYPE,RO,RM")
	output2, err2 := cmd.Output()
	jsonParsed := false
	if err2 == nil {
		var lsblkOutput struct {
			Blockdevices []struct {
				Name   string      `json:"name"`
				Size   interface{} `json:"size"`   // Can be string or number in JSON
				Model  *string     `json:"model"`  // Can be null
				Vendor *string     `json:"vendor"` // Can be null
				Serial *string     `json:"serial"` // Can be null
				Type   string      `json:"type"`
				Ro     bool        `json:"ro"` // Boolean, not string
				Rm     bool        `json:"rm"` // Boolean, not string
			} `json:"blockdevices"`
		}

		if err := json.Unmarshal(output2, &lsblkOutput); err == nil && len(lsblkOutput.Blockdevices) > 0 {
			jsonParsed = true
			for _, blockdev := range lsblkOutput.Blockdevices {
				deviceName := blockdev.Name
				devicePath := fmt.Sprintf("/dev/%s", deviceName)

				// Pseudo-devices and eMMC boot/RPMB areas are never storage.
				if skipBlockDevice(deviceName) {
					continue
				}

				// Verify device exists
				if _, err := os.Stat(devicePath); err != nil {
					continue
				}

				device := &proto.StorageDevice{
					Path: devicePath,
				}

				// Parse size (in bytes) - can be string or number
				if blockdev.Size != nil {
					var size uint64
					switch v := blockdev.Size.(type) {
					case string:
						if parsed, err := strconv.ParseUint(v, 10, 64); err == nil {
							size = parsed
						}
					case float64:
						size = uint64(v)
					case int64:
						size = uint64(v)
					case int:
						size = uint64(v)
					default:
						// Try to convert via string
						if parsed, err := strconv.ParseUint(fmt.Sprintf("%v", v), 10, 64); err == nil {
							size = parsed
						}
					}
					if size > 0 {
						device.TotalCapacity = size
					}
				}

				// Parse model, vendor, serial (can be null)
				if blockdev.Model != nil {
					device.Model = strings.TrimSpace(*blockdev.Model)
				}
				if blockdev.Vendor != nil {
					device.Vendor = strings.TrimSpace(*blockdev.Vendor)
				}
				if blockdev.Serial != nil {
					device.Serial = strings.TrimSpace(*blockdev.Serial)
				}

				// Parse device type
				deviceType := strings.ToLower(strings.TrimSpace(blockdev.Type))
				device.DeviceType = deviceType

				// Parse read-only flag (boolean)
				device.IsReadOnly = blockdev.Ro

				// Parse removable flag (boolean)
				device.IsRemovable = blockdev.Rm

				// Get additional info from /sys/block
				r.enrichDeviceFromSys(device, deviceName)

				// Get filesystem and usage info from mount info
				// Collect partitions for this device
				r.collectPartitions(device, deviceName, mountInfo)

				// Build label
				device.Label = r.buildLabel(device)

				devices[devicePath] = device
			}
		}
	}

	// Method 1b: Fallback to non-JSON lsblk if JSON parsing failed or returned no devices
	if !jsonParsed || len(devices) == 0 {
		cmd2 := exec.Command("lsblk", "-d", "-n", "-b", "-o", "NAME,SIZE,MODEL,VENDOR,SERIAL,TYPE,RO,RM")
		output3, err3 := cmd2.Output()
		if err3 == nil {
			lines := strings.Split(string(output3), "\n")
			for _, line := range lines {
				line = strings.TrimSpace(line)
				if line == "" {
					continue
				}

				// Parse lsblk output: NAME SIZE MODEL VENDOR SERIAL TYPE RO RM
				// Note: MODEL and VENDOR may contain spaces, so we need to be careful
				// We'll parse from the end backwards for RO, RM, TYPE, then work forward
				parts := strings.Fields(line)
				if len(parts) < 2 {
					continue
				}

				deviceName := parts[0]
				devicePath := fmt.Sprintf("/dev/%s", deviceName)

				// Pseudo-devices and eMMC boot/RPMB areas are never storage.
				if skipBlockDevice(deviceName) {
					continue
				}
				if _, exists := devices[devicePath]; exists {
					continue
				}

				// Verify device exists
				if _, err := os.Stat(devicePath); err != nil {
					continue
				}

				device := &proto.StorageDevice{
					Path: devicePath,
				}

				// Parse size (in bytes) - second field
				if len(parts) >= 2 {
					if size, err := strconv.ParseUint(parts[1], 10, 64); err == nil {
						device.TotalCapacity = size
					}
				}

				// Parse from the end: RO, RM, TYPE, SERIAL
				// Then MODEL and VENDOR are what's left in the middle
				if len(parts) >= 8 {
					// Format: NAME SIZE MODEL VENDOR SERIAL TYPE RO RM
					device.IsReadOnly = parts[len(parts)-2] == "1"
					device.IsRemovable = parts[len(parts)-1] == "1"
					deviceType := strings.ToLower(parts[len(parts)-3])
					device.DeviceType = deviceType
					device.Serial = parts[len(parts)-4]

					// MODEL and VENDOR are in the middle (parts[2] to parts[len(parts)-5])
					// Try to split them - usually MODEL comes first, then VENDOR
					// But they might be combined or swapped, so we'll take what we can get
					if len(parts) >= 5 {
						// Take everything between SIZE and SERIAL as MODEL/VENDOR
						modelVendor := strings.Join(parts[2:len(parts)-4], " ")
						// Try to split on common patterns, or just use as model
						device.Model = modelVendor
					}
				} else if len(parts) >= 6 {
					// Simpler case: NAME SIZE MODEL TYPE RO RM (no VENDOR/SERIAL)
					deviceType := strings.ToLower(parts[len(parts)-3])
					device.DeviceType = deviceType
					device.IsReadOnly = parts[len(parts)-2] == "1"
					device.IsRemovable = parts[len(parts)-1] == "1"
					if len(parts) >= 3 {
						device.Model = strings.Join(parts[2:len(parts)-3], " ")
					}
				}

				// Get additional info from /sys/block (this will override/complete the data)
				r.enrichDeviceFromSys(device, deviceName)

				// Get filesystem and usage info from mount info
				r.collectPartitions(device, deviceName, mountInfo)

				// Build label
				device.Label = r.buildLabel(device)

				devices[devicePath] = device
			}
		}
	}

	// Method 2: Fallback to /sys/block if lsblk is not available
	if len(devices) == 0 {
		sysBlockDir := "/sys/block"
		entries, err := os.ReadDir(sysBlockDir)
		if err == nil {
			for _, entry := range entries {
				name := entry.Name()
				// Pseudo-devices and eMMC boot/RPMB areas are never storage.
				if skipBlockDevice(name) {
					continue
				}

				devicePath := fmt.Sprintf("/dev/%s", name)

				// Check if it's a block device (not a partition)
				// Partitions have a number suffix (e.g., sda1, sda2)
				if strings.ContainsAny(name, "0123456789") {
					continue
				}

				// Verify device exists
				if _, err := os.Stat(devicePath); err != nil {
					continue
				}

				device := &proto.StorageDevice{
					Path: devicePath,
				}

				// Get all info from /sys/block
				r.enrichDeviceFromSys(device, name)

				// Get filesystem and usage info - collect partitions
				r.collectPartitions(device, name, mountInfo)

				// Build label
				device.Label = r.buildLabel(device)

				devices[devicePath] = device
			}
		}
	}

	return devices, nil
}

// mountInfo holds filesystem and usage information
type mountInfo struct {
	filesystem string
	mountPoint string
	used       uint64
	available  uint64
}

// getMountInfo retrieves mount and filesystem usage information
func (r *StorageReader) getMountInfo() map[string]mountInfo {
	info := make(map[string]mountInfo)

	// Use df to get filesystem usage
	cmd := exec.Command("df", "-B1", "-T")
	output, err := cmd.Output()
	if err == nil {
		lines := strings.Split(string(output), "\n")
		for i, line := range lines {
			if i == 0 {
				continue // Skip header
			}
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}

			parts := strings.Fields(line)
			if len(parts) >= 7 {
				devicePath := parts[0]
				filesystem := parts[1]
				mountPoint := parts[6]

				var total, used, available uint64
				if len(parts) >= 4 {
					fmt.Sscanf(parts[2], "%d", &total)
					fmt.Sscanf(parts[3], "%d", &used)
					if len(parts) >= 5 {
						fmt.Sscanf(parts[4], "%d", &available)
					}
				}

				info[devicePath] = mountInfo{
					filesystem: filesystem,
					mountPoint: mountPoint,
					used:       used,
					available:  available,
				}
			}
		}
	}

	return info
}

// collectPartitions collects partition information for a device
func (r *StorageReader) collectPartitions(device *proto.StorageDevice, deviceName string, mountInfo map[string]mountInfo) {
	var partitions []*proto.StoragePartition

	// Find all partitions of this device (e.g., nvme0n1p1, nvme0n1p2 for nvme0n1)
	for partitionPath, mountData := range mountInfo {
		// Check if this partition belongs to our device
		// e.g., /dev/nvme0n1p1 starts with /dev/nvme0n1
		if strings.HasPrefix(partitionPath, device.Path) && partitionPath != device.Path {
			partition := &proto.StoragePartition{
				PartitionId:    partitionPath,
				MountPoint:     mountData.mountPoint,
				Filesystem:     mountData.filesystem,
				UsedSpace:      mountData.used,
				AvailableSpace: mountData.available,
			}
			partitions = append(partitions, partition)
		}
	}

	// If no partitions found in mount info, try to detect partitions from /sys/block
	if len(partitions) == 0 {
		partitions = r.detectPartitionsFromSys(device, deviceName)
	}

	device.Partitions = partitions
}

// detectPartitionsFromSys detects partitions from /sys/block even if not mounted
func (r *StorageReader) detectPartitionsFromSys(device *proto.StorageDevice, deviceName string) []*proto.StoragePartition {
	var partitions []*proto.StoragePartition
	sysBlockDir := "/sys/block"
	deviceDir := filepath.Join(sysBlockDir, deviceName)

	// Read directory entries to find partitions
	entries, err := os.ReadDir(deviceDir)
	if err != nil {
		return partitions
	}

	for _, entry := range entries {
		// Partitions are typically named like deviceName + number (e.g., sda1, nvme0n1p1)
		entryName := entry.Name()
		if strings.HasPrefix(entryName, deviceName) && entryName != deviceName {
			// This might be a partition
			partitionPath := fmt.Sprintf("/dev/%s", entryName)

			// Try to get filesystem info even if not mounted
			fsType := ""
			cmd := exec.Command("blkid", "-s", "TYPE", "-o", "value", partitionPath)
			if output, err := cmd.Output(); err == nil {
				fsType = strings.TrimSpace(string(output))
			}

			partition := &proto.StoragePartition{
				PartitionId:    partitionPath,
				MountPoint:     "", // Not mounted
				Filesystem:     fsType,
				UsedSpace:      0,
				AvailableSpace: 0,
			}
			partitions = append(partitions, partition)
		}
	}

	return partitions
}

// enrichDeviceFromSys enriches device information from /sys/block
func (r *StorageReader) enrichDeviceFromSys(device *proto.StorageDevice, deviceName string) {
	sysBlockDir := "/sys/block"
	basePath := filepath.Join(sysBlockDir, deviceName)

	// Get size (in 512-byte sectors)
	sizeFile := filepath.Join(basePath, "size")
	if sizeBytes, err := os.ReadFile(sizeFile); err == nil {
		var sectors uint64
		if _, err := fmt.Sscanf(strings.TrimSpace(string(sizeBytes)), "%d", &sectors); err == nil {
			device.TotalCapacity = sectors * 512
		}
	}

	// Get model. Only overwrite with a non-empty value: an empty-but-present
	// sysfs file must not blank a name lsblk already supplied.
	modelFile := filepath.Join(basePath, "device", "model")
	if modelBytes, err := os.ReadFile(modelFile); err == nil {
		if m := strings.TrimSpace(string(modelBytes)); m != "" {
			device.Model = m
		}
	}

	// MMC devices have no device/model — their product name lives in
	// device/name (e.g. "SH32G"). Without this the UI showed a nameless "30GB"
	// for an SD card while the USB disk beside it got a full model string.
	if device.Model == "" {
		if nameBytes, err := os.ReadFile(filepath.Join(basePath, "device", "name")); err == nil {
			if n := strings.TrimSpace(string(nameBytes)); n != "" {
				device.Model = n
			}
		}
	}

	// Get vendor
	vendorFile := filepath.Join(basePath, "device", "vendor")
	if vendorBytes, err := os.ReadFile(vendorFile); err == nil {
		device.Vendor = strings.TrimSpace(string(vendorBytes))
	}

	// Get serial
	serialFile := filepath.Join(basePath, "device", "serial")
	if serialBytes, err := os.ReadFile(serialFile); err == nil {
		device.Serial = strings.TrimSpace(string(serialBytes))
	}

	// Get removable flag
	removableFile := filepath.Join(basePath, "removable")
	if removableBytes, err := os.ReadFile(removableFile); err == nil {
		device.IsRemovable = strings.TrimSpace(string(removableBytes)) == "1"
	}

	// Get read-only flag
	roFile := filepath.Join(basePath, "ro")
	if roBytes, err := os.ReadFile(roFile); err == nil {
		device.IsReadOnly = strings.TrimSpace(string(roBytes)) == "1"
	}

	// Determine device type from name and sys info
	device.DeviceType = classifyDeviceType(sysBlockDir, basePath, deviceName, device.DeviceType)
}

// classifyDeviceType decides what a block device IS, from its name and sysfs.
// current is whatever lsblk already reported, kept as the fallback.
//
// Takes its sysfs roots as parameters so the whole table is testable against a
// tree a test builds — this used to be an inline chain in enrichDeviceFromSys
// with no test at all, and it had never classified an MMC device.
func classifyDeviceType(sysBlockDir, basePath, deviceName, current string) string {
	switch {
	case strings.HasPrefix(deviceName, "nvme"):
		return "nvme"

	// SD card vs eMMC. For a product whose whole subject is Raspberry Pi this is
	// the storage distinction that matters most, and there was no branch for it
	// at all: an MMC device fell through to the generic arm and became "disk", so
	// a CM4/CM5 carrying eMMC AND an inserted SD card showed two identical rows
	// differing only in size — and choosing an install target was a guess whose
	// wrong answer wipes the wrong medium.
	//
	// device/type is the discriminator ("SD" here, "MMC" for eMMC). `removable`
	// CANNOT be used, which is why the frontend's old guess was wrong too: the
	// kernel reports 0 for an SD card exactly as it does for eMMC.
	case strings.HasPrefix(deviceName, "mmcblk"):
		return mmcDeviceType(basePath)

	case strings.HasPrefix(deviceName, "vd"):
		return "virtio"
	}

	// Transport before rotational, for sd*/hd* and anything unrecognised. A UAS
	// bridge is free to lie about rotational and one does: a SanDisk USB stick
	// reported rotational=1 and was labelled "57GB SanDisk 3.2Gen1 HDD".
	if hardwareTransport := DeviceTransport(sysBlockDir, deviceName); hardwareTransport == "usb" {
		return usbDeviceType(basePath)
	}

	if strings.HasPrefix(deviceName, "sd") || strings.HasPrefix(deviceName, "hd") ||
		current == "" {
		rotationalFile := filepath.Join(basePath, "queue", "rotational")
		if rotationalBytes, err := os.ReadFile(rotationalFile); err == nil {
			if strings.TrimSpace(string(rotationalBytes)) == "0" {
				return "ssd"
			}
			return "hdd"
		}
		if current == "" {
			return "disk"
		}
	}

	return current
}

// usbDeviceType separates a USB stick from an external SSD or spinning disk, as
// far as the kernel can actually answer it — and the honest answer has three
// values, not two.
//
// Why `queue/rotational` alone cannot do it: for USB/SCSI the kernel sets it from
// VPD page B1 (Medium Rotation Rate). A device that answers "non-rotating" gets
// rotational=0; a device that answers NOTHING keeps the default 1, which is
// indistinguishable from a real spinning disk. That is exactly what happened to
// the SanDisk stick — it reports no MRR, so the old code called it an HDD.
//
// So:
//   - rotational=0 → "usb_ssd". Positive evidence: the device said non-rotating.
//   - removable=1 → "usb_flash". The SCSI RMB bit — a stick or a card reader,
//     which is what the measured SanDisk (rm=1, rot=1) is.
//   - otherwise → "usb". A fixed-medium device that reported no rotation rate:
//     could be a spinning disk in an enclosure, could be a bridge that stays
//     quiet. Deliberately NOT called a disk or a stick, because we do not know.
//
// The order matters: rotational=0 outranks removable, since a removable-medium
// device that also says non-rotating is flash either way, and the SSD label is
// the more useful one for the operator picking an install target.
//
// CAVEAT: only the flash case is measured. No external USB SSD or spinning disk
// in an enclosure was available, so the first and third branches
// rest on how the kernel documents VPD B1 and RMB, not on a reading from one of
// ours. Confirm before treating "usb" as "probably spinning".
func usbDeviceType(basePath string) string {
	if b, err := os.ReadFile(filepath.Join(basePath, "queue", "rotational")); err == nil {
		if strings.TrimSpace(string(b)) == "0" {
			return "usb_ssd"
		}
	}
	if b, err := os.ReadFile(filepath.Join(basePath, "removable")); err == nil {
		if strings.TrimSpace(string(b)) == "1" {
			return "usb_flash"
		}
	}
	return "usb"
}

// mmcDeviceType reads /sys/block/mmcblkN/device/type, which reports the MMC card
// class: "SD" for a card in a slot, "MMC" for soldered-down eMMC. That it
// genuinely distinguishes classes is visible on the same node, where the second
// controller reports "SDIO" (a Wi-Fi radio, not storage).
//
// BOTH strings are measured, on two different boards:
//
//	SD card:                 device/type=SD   device/name=SH32G
//	eMMC, CM5 rev e04180:    device/type=MMC  device/name=CJTD4R
//
// The eMMC board also carries /sys/block/mmcblk0boot0 and boot1, which exist for
// eMMC only — an independent confirmation of the same fact, and a second
// discriminator if device/type is ever missing.
//
// An unreadable or unrecognised value still degrades to the honest "mmc" rather
// than guessing eMMC: a wrong confident answer here is what makes somebody wipe
// the wrong medium.
func mmcDeviceType(basePath string) string {
	typeBytes, err := os.ReadFile(filepath.Join(basePath, "device", "type"))
	if err != nil {
		return "mmc"
	}
	switch strings.ToUpper(strings.TrimSpace(string(typeBytes))) {
	case "SD":
		return "sd"
	case "MMC":
		return "emmc"
	default:
		return "mmc"
	}
}

// deviceTypeLabel renders a device_type for a human, or "" for a type that says
// nothing worth showing ("disk" is the "we could not tell" value).
func deviceTypeLabel(deviceType string) string {
	switch deviceType {
	case "sd":
		return "SD"
	case "emmc":
		return "eMMC"
	case "mmc":
		return "MMC"
	case "nvme":
		return "NVMe"
	case "usb_flash":
		return "USB flash"
	case "usb_ssd":
		return "USB SSD"
	case "usb":
		return "USB"
	case "ssd":
		return "SSD"
	case "hdd":
		return "HDD"
	case "virtio":
		return "virtio"
	case "", "disk":
		return ""
	default:
		return strings.ToUpper(deviceType)
	}
}

// buildLabel creates a human-readable label for the device
func (r *StorageReader) buildLabel(device *proto.StorageDevice) string {
	var parts []string

	// Add size
	if device.TotalCapacity > 0 {
		sizeGB := float64(device.TotalCapacity) / (1024 * 1024 * 1024)
		if sizeGB >= 1024 {
			sizeTB := sizeGB / 1024
			parts = append(parts, fmt.Sprintf("%.1fTB", sizeTB))
		} else {
			parts = append(parts, fmt.Sprintf("%.0fGB", sizeGB))
		}
	}

	// Add model or vendor
	if device.Model != "" {
		parts = append(parts, device.Model)
	} else if device.Vendor != "" {
		parts = append(parts, device.Vendor)
	}

	// Add device type if available. Rendered through a table rather than
	// ToUpper: this label is what the install-target picker shows, so "EMMC" and
	// "NVME" are the strings an operator reads while choosing a disk to wipe.
	if label := deviceTypeLabel(device.DeviceType); label != "" {
		parts = append(parts, label)
	}

	if len(parts) > 0 {
		return strings.Join(parts, " ")
	}

	// Fallback to device path
	return filepath.Base(device.Path)
}
