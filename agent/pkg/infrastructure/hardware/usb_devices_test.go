package hardware

import (
	"os"
	"path/filepath"
	"testing"
)

// writeUSBDevice builds one /sys/bus/usb/devices entry from attribute files.
func writeUSBDevice(t *testing.T, root, name string, attrs map[string]string) {
	t.Helper()
	dir := filepath.Join(root, name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for k, v := range attrs {
		full := filepath.Join(dir, k)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(v+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func TestReadUSBDevices(t *testing.T) {
	root := t.TempDir()

	// A root hub: the controller, not something anyone plugged in.
	writeUSBDevice(t, root, "usb1", map[string]string{
		"idVendor": "1d6b", "idProduct": "0002", "bDeviceClass": "09",
	})
	// A real hub: structure, not an attachment. Listing it beside the devices
	// plugged into it reads as if it were one of them.
	writeUSBDevice(t, root, "1-1", map[string]string{
		"idVendor": "2109", "idProduct": "3431", "bDeviceClass": "09",
		"product": "USB2.0 Hub", "speed": "480",
	})
	// A Wi-Fi dongle, which is exactly what this inventory is for.
	writeUSBDevice(t, root, "1-1.2", map[string]string{
		"idVendor": "0bda", "idProduct": "8179", "bDeviceClass": "00",
		"manufacturer": "Realtek", "product": "802.11n NIC", "speed": "480",
		// Class 00 defers to the interface; without the fallback this device
		// would report no class at all.
		"1-1.2:1.0/bInterfaceClass": "ff",
	})
	// A SanDisk stick: storage, already a StorageDevice.
	writeUSBDevice(t, root, "1-1.3", map[string]string{
		"idVendor": "0781", "idProduct": "55a9", "bDeviceClass": "00",
		"manufacturer": "SanDisk", "product": "SanDisk 3.2Gen1", "speed": "5000",
		"1-1.3:1.0/bInterfaceClass": "08",
	})
	// An interface directory at the top level — a facet of a device already
	// listed, and including it turns one dongle into several rows.
	writeUSBDevice(t, root, "1-1.2:1.0", map[string]string{
		"bInterfaceClass": "ff",
	})
	// A directory that is not a USB device at all.
	writeUSBDevice(t, root, "notadevice", map[string]string{"something": "else"})

	got := readUSBDevicesFrom(root)

	if len(got) != 1 {
		t.Fatalf("got %d devices, want 1 (the Wi-Fi dongle): %+v", len(got), got)
	}
	d := got[0]
	if d.VendorID != "0bda" || d.ProductID != "8179" {
		t.Errorf("ids = %s:%s, want 0bda:8179", d.VendorID, d.ProductID)
	}
	if d.Manufacturer != "Realtek" || d.Product != "802.11n NIC" {
		t.Errorf("names = %q / %q", d.Manufacturer, d.Product)
	}
	if d.ClassCode != 0xff {
		t.Errorf("class = 0x%x, want 0xff from the interface fallback", d.ClassCode)
	}
	if d.Speed != "480" {
		t.Errorf("speed = %q", d.Speed)
	}
	if d.Port != "1-1.2" {
		t.Errorf("port = %q — the bus path is what tells two identical dongles apart", d.Port)
	}
}

// Empty is a normal answer, not a failure: hardware with no USB bus, a
// container, anything that is not Linux.
func TestReadUSBDevicesOnAnAbsentBus(t *testing.T) {
	if got := readUSBDevicesFrom(filepath.Join(t.TempDir(), "nope")); got != nil {
		t.Errorf("got %+v, want nil", got)
	}
}

// A device that reports its class directly must not be overridden by an
// interface — the fallback exists only for the class-00 case.
func TestDeviceClassWinsOverInterfaceClass(t *testing.T) {
	root := t.TempDir()
	writeUSBDevice(t, root, "1-2", map[string]string{
		"idVendor": "1a86", "idProduct": "7523", "bDeviceClass": "02",
		"product": "USB Serial", "1-2:1.0/bInterfaceClass": "ff",
	})
	got := readUSBDevicesFrom(root)
	if len(got) != 1 || got[0].ClassCode != 0x02 {
		t.Fatalf("got %+v, want one device with class 0x02", got)
	}
}

// Missing optional attributes are normal; a device that omits `manufacturer`
// must still be listed rather than dropped.
func TestDeviceWithNoNamesIsStillListed(t *testing.T) {
	root := t.TempDir()
	writeUSBDevice(t, root, "1-3", map[string]string{
		"idVendor": "0424", "idProduct": "7800",
	})
	got := readUSBDevicesFrom(root)
	if len(got) != 1 {
		t.Fatalf("got %d devices, want 1", len(got))
	}
	if got[0].Manufacturer != "" || got[0].Product != "" {
		t.Errorf("expected empty names, got %+v", got[0])
	}
}
