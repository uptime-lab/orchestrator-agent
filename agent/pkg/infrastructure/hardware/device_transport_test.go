//go:build linux

package hardware

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDeviceTransportFromSysPath(t *testing.T) {
	// Real resolved /sys/block targets, matching the shapes measured on
	// real boards.
	cases := map[string]string{
		"/sys/devices/platform/scb/fd500000.pcie/pci0000:00/0000:00:00.0/0000:01:00.0/usb2/2-1/2-1:1.0/host0/target0:0:0/0:0:0:0/block/sda": "usb",
		"/sys/devices/platform/scb/fd500000.pcie/pci0000:00/0000:00:00.0/0000:01:00.0/nvme/nvme0/nvme0n1":                                   "nvme",
		"/sys/devices/platform/soc/fe340000.mmc/mmc_host/mmc0/mmc0:aaaa/block/mmcblk0":                                                      "mmc",
		"/sys/devices/pci0000:00/0000:00:07.0/virtio3/block/vda":                                                                            "virtio",
		"/sys/devices/platform/soc/fe801000.csi/block/xda":                                                                                  "",
	}

	for resolved, want := range cases {
		if got := DeviceTransportFromSysPath(resolved); got != want {
			t.Errorf("DeviceTransportFromSysPath(%q) = %q, want %q", resolved, got, want)
		}
	}
}

func TestDeviceTransportResolvesSymlink(t *testing.T) {
	root := t.TempDir()
	sysBlock := filepath.Join(root, "sys", "block")
	target := filepath.Join(root, "sys", "devices", "platform", "scb", "usb2", "block", "sda")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatalf("building the fake sysfs tree: %v", err)
	}
	if err := os.MkdirAll(sysBlock, 0o755); err != nil {
		t.Fatalf("building the fake /sys/block: %v", err)
	}
	if err := os.Symlink(target, filepath.Join(sysBlock, "sda")); err != nil {
		t.Fatalf("linking the fake device: %v", err)
	}

	if got := DeviceTransport(sysBlock, "sda"); got != "usb" {
		t.Fatalf("DeviceTransport = %q, want usb", got)
	}
	// An absent device must be "" rather than a guess.
	if got := DeviceTransport(sysBlock, "nvme0n1"); got != "" {
		t.Fatalf("DeviceTransport on an absent device = %q, want empty", got)
	}
	// A path, not a device name — refused rather than resolved.
	if got := DeviceTransport(sysBlock, "../devices/sda"); got != "" {
		t.Fatalf("DeviceTransport on a path = %q, want empty", got)
	}
}

func TestDeviceTransportLabel(t *testing.T) {
	cases := map[string]string{
		"usb":    "USB",
		"nvme":   "NVMe",
		"mmc":    "SD/eMMC",
		"virtio": "virtio",
		"":       "",
		"weird":  "",
	}
	for in, want := range cases {
		if got := DeviceTransportLabel(in); got != want {
			t.Errorf("DeviceTransportLabel(%q) = %q, want %q", in, got, want)
		}
	}
}
