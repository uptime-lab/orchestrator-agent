package hardware

import (
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// USBDevice is one attached USB device, as sysfs reports it.
type USBDevice struct {
	VendorID     string
	ProductID    string
	Manufacturer string
	Product      string
	ClassCode    uint32
	Speed        string
	Port         string
}

// ReadUSBDevices lists what is plugged into the node's USB ports.
//
// It answers the question storage cannot: a Wi-Fi dongle, a serial or CAN
// adapter, a HAT that presents over USB, a hub. Storage is deliberately absent —
// a USB disk is already a StorageDevice, and two records for one object invites
// an operator to reason about them separately.
//
// A directory walk over /sys/bus/usb/devices, so it costs no commands and works
// in the recovery bootstrap. Empty is a normal answer: on hardware with no USB
// bus, in a container, and on anything that is not Linux.
//
// No build tag, deliberately: this is path and string work over a root the
// caller supplies, so it is testable on any machine. The agent's other hardware
// code is linux-tagged and cannot run on a development host at all.
func ReadUSBDevices() []USBDevice {
	return readUSBDevicesFrom("/sys/bus/usb/devices")
}

// readUSBDevicesFrom is ReadUSBDevices against an arbitrary root.
func readUSBDevicesFrom(root string) []USBDevice {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil
	}

	var devices []USBDevice
	for _, entry := range entries {
		name := entry.Name()
		// Skip INTERFACES ("1-1:1.0"): they are facets of a device already
		// listed, and including them turns one dongle into three rows. Skip root
		// hubs ("usb1") too — they are the controller, not something anyone
		// plugged in.
		if strings.Contains(name, ":") || strings.HasPrefix(name, "usb") {
			continue
		}
		dir := filepath.Join(root, name)
		vendor := readSysAttr(dir, "idVendor")
		product := readSysAttr(dir, "idProduct")
		if vendor == "" || product == "" {
			// Not a USB device node — every real one carries both.
			continue
		}

		dev := USBDevice{
			VendorID:     vendor,
			ProductID:    product,
			Manufacturer: readSysAttr(dir, "manufacturer"),
			Product:      readSysAttr(dir, "product"),
			Speed:        readSysAttr(dir, "speed"),
			Port:         name,
		}

		// bDeviceClass is 00 for most modern devices, which defer the class to
		// their interfaces; fall back to the first interface's class so a
		// keyboard does not report "defined at interface level".
		class := readSysAttr(dir, "bDeviceClass")
		if class == "" || class == "00" {
			class = firstInterfaceClass(dir, name)
		}
		if n, err := strconv.ParseUint(class, 16, 32); err == nil {
			dev.ClassCode = uint32(n)
		}

		// Hubs are structure, not attachments: a 4-port hub would otherwise
		// appear beside the things plugged into it as if it were one of them.
		if dev.ClassCode == usbClassHub {
			continue
		}
		// Mass storage is reported as a StorageDevice; see the doc comment.
		if dev.ClassCode == usbClassMassStorage {
			continue
		}

		devices = append(devices, dev)
	}

	// Stable order, so an unchanged fleet does not produce a changed report.
	// ReadDir is already sorted, but the filtering above makes that easy to lose.
	sort.Slice(devices, func(i, j int) bool { return devices[i].Port < devices[j].Port })
	return devices
}

const (
	usbClassMassStorage = 0x08
	usbClassHub         = 0x09
)

// firstInterfaceClass returns bInterfaceClass of the device's first interface,
// which is where a device that reports class 00 keeps its real class.
func firstInterfaceClass(dir, name string) string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return ""
	}
	prefix := name + ":"
	best := ""
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), prefix) {
			continue
		}
		if class := readSysAttr(filepath.Join(dir, e.Name()), "bInterfaceClass"); class != "" {
			if best == "" || e.Name() < best {
				best = e.Name()
				// Keep scanning: ReadDir is sorted, but a composite device's
				// interfaces are not guaranteed to be, and the FIRST one is the
				// one whose class describes the device.
				continue
			}
		}
	}
	if best == "" {
		return ""
	}
	return readSysAttr(filepath.Join(dir, best), "bInterfaceClass")
}

// readSysAttr reads one sysfs attribute, trimmed. Missing is "" — most of these
// are optional and a device that omits `manufacturer` is completely normal.
func readSysAttr(dir, name string) string {
	b, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}
