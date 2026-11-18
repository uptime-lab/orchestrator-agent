//go:build linux

package hardware

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	proto "agent/pkg/infrastructure/grpc/proto"
)

// fakeSysBlock builds a /sys/block-shaped tree and returns its path. Each device
// is described by the sysfs files it carries; transportSegment, when non-empty,
// becomes a path segment in the device's resolved location so DeviceTransport
// can classify it the way it does on a real host.
func fakeSysBlock(t *testing.T, name string, files map[string]string, transportSegment string) (sysBlockDir, basePath string) {
	t.Helper()
	root := t.TempDir()
	sysBlockDir = filepath.Join(root, "sys", "block")
	if err := os.MkdirAll(sysBlockDir, 0o755); err != nil {
		t.Fatalf("mkdir /sys/block: %v", err)
	}

	deviceDir := filepath.Join(root, "sys", "devices", "platform")
	if transportSegment != "" {
		deviceDir = filepath.Join(deviceDir, transportSegment)
	}
	deviceDir = filepath.Join(deviceDir, "block", name)
	if err := os.MkdirAll(deviceDir, 0o755); err != nil {
		t.Fatalf("mkdir device dir: %v", err)
	}
	for rel, content := range files {
		full := filepath.Join(deviceDir, rel)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", filepath.Dir(full), err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatalf("write %s: %v", full, err)
		}
	}
	if err := os.Symlink(deviceDir, filepath.Join(sysBlockDir, name)); err != nil {
		t.Fatalf("symlink device: %v", err)
	}
	return sysBlockDir, filepath.Join(sysBlockDir, name)
}

func TestClassifyDeviceTypeSDCard(t *testing.T) {
	// Measured: an SD card reports device/type=SD
	// and removable=0 — the same 0 an eMMC reports, which is why removable can
	// never be the discriminator.
	sysBlock, base := fakeSysBlock(t, "mmcblk0", map[string]string{
		"device/type":      "SD\n",
		"device/name":      "SH32G\n",
		"removable":        "0\n",
		"queue/rotational": "0\n",
	}, "fe340000.mmc/mmc_host/mmc0")

	if got := classifyDeviceType(sysBlock, base, "mmcblk0", ""); got != "sd" {
		t.Fatalf("classifyDeviceType(mmcblk0, type=SD) = %q, want sd", got)
	}
}

func TestClassifyDeviceTypeEMMC(t *testing.T) {
	sysBlock, base := fakeSysBlock(t, "mmcblk0", map[string]string{
		"device/type": "MMC\n",
		"removable":   "0\n",
	}, "fe340000.mmc/mmc_host/mmc0")

	if got := classifyDeviceType(sysBlock, base, "mmcblk0", ""); got != "emmc" {
		t.Fatalf("classifyDeviceType(mmcblk0, type=MMC) = %q, want emmc", got)
	}
}

func TestClassifyDeviceTypeMMCUnknownDegradesHonestly(t *testing.T) {
	// No device/type at all, and an unrecognised value. Both must land on the
	// honest "mmc" rather than guessing a class: a confident wrong answer here is
	// what makes an operator wipe the wrong medium.
	sysBlock, base := fakeSysBlock(t, "mmcblk1", map[string]string{
		"removable": "0\n",
	}, "fe340000.mmc/mmc_host/mmc1")
	if got := classifyDeviceType(sysBlock, base, "mmcblk1", ""); got != "mmc" {
		t.Fatalf("classifyDeviceType with no device/type = %q, want mmc", got)
	}

	sysBlock2, base2 := fakeSysBlock(t, "mmcblk2", map[string]string{
		"device/type": "SDIO\n",
	}, "fe340000.mmc/mmc_host/mmc2")
	if got := classifyDeviceType(sysBlock2, base2, "mmcblk2", ""); got != "mmc" {
		t.Fatalf("classifyDeviceType with device/type=SDIO = %q, want mmc", got)
	}
}

func TestClassifyDeviceTypeUSBBeatsRotational(t *testing.T) {
	// A SanDisk stick: a UAS bridge reporting rotational=1 for
	// flash, which produced the label "57GB SanDisk 3.2Gen1 HDD". It must land on
	// a USB verdict of some kind, never on hdd — which of the three it gets is
	// TestUSBFlashVersusExternalDisk's subject.
	sysBlock, base := fakeSysBlock(t, "sda", map[string]string{
		"queue/rotational": "1\n",
		"removable":        "1\n",
	}, "scb/usb2/2-1/2-1:1.0/host0/target0:0:0/0:0:0:0")

	got := classifyDeviceType(sysBlock, base, "sda", "")
	if !strings.HasPrefix(got, "usb") {
		t.Fatalf("classifyDeviceType(usb-attached sda) = %q, want a usb* type", got)
	}
}

func TestClassifyDeviceTypeSATARotationalStillDecides(t *testing.T) {
	// A non-USB sd* keeps the old behaviour: rotational decides SSD vs HDD.
	sysBlock, base := fakeSysBlock(t, "sda", map[string]string{
		"queue/rotational": "0\n",
	}, "soc/ahci")
	if got := classifyDeviceType(sysBlock, base, "sda", ""); got != "ssd" {
		t.Fatalf("classifyDeviceType(sata ssd) = %q, want ssd", got)
	}

	sysBlock2, base2 := fakeSysBlock(t, "sdb", map[string]string{
		"queue/rotational": "1\n",
	}, "soc/ahci")
	if got := classifyDeviceType(sysBlock2, base2, "sdb", ""); got != "hdd" {
		t.Fatalf("classifyDeviceType(sata hdd) = %q, want hdd", got)
	}
}

func TestClassifyDeviceTypeNVMeAndVirtio(t *testing.T) {
	sysBlock, base := fakeSysBlock(t, "nvme0n1", nil, "scb/pcie/nvme/nvme0")
	if got := classifyDeviceType(sysBlock, base, "nvme0n1", ""); got != "nvme" {
		t.Fatalf("classifyDeviceType(nvme0n1) = %q, want nvme", got)
	}

	sysBlock2, base2 := fakeSysBlock(t, "vda", nil, "virtio3")
	if got := classifyDeviceType(sysBlock2, base2, "vda", ""); got != "virtio" {
		t.Fatalf("classifyDeviceType(vda) = %q, want virtio", got)
	}
}

func TestClassifyDeviceTypeKeepsLsblkValueWhenNothingBetterIsKnown(t *testing.T) {
	// An unrecognised name with no rotational file and a type lsblk already
	// supplied: keep it rather than inventing "disk".
	sysBlock, base := fakeSysBlock(t, "xda", nil, "soc/whatever")
	if got := classifyDeviceType(sysBlock, base, "xda", "rom"); got != "rom" {
		t.Fatalf("classifyDeviceType kept %q, want rom", got)
	}
}

func TestEnrichDeviceFromSysNamesAnMMCCard(t *testing.T) {
	// device/model does not exist for MMC — the product name lives in
	// device/name. Without the fallback the UI showed a nameless "30GB" card.
	// enrichDeviceFromSys reads the real /sys/block, so this asserts the pieces
	// it composes instead: the label an MMC device now produces.
	r := NewStorageReader()
	label := r.buildLabel(&proto.StorageDevice{
		Path:          "/dev/mmcblk0",
		Model:         "SH32G",
		DeviceType:    "sd",
		TotalCapacity: 31 * 1024 * 1024 * 1024,
	})
	if label != "31GB SH32G SD" {
		t.Fatalf("buildLabel = %q, want %q", label, "31GB SH32G SD")
	}

	// eMMC must read as eMMC, not EMMC — this string is what the install-target
	// picker shows while somebody chooses a disk to wipe.
	label = r.buildLabel(&proto.StorageDevice{
		Path:          "/dev/mmcblk0",
		Model:         "BJTD4R",
		DeviceType:    "emmc",
		TotalCapacity: 32 * 1024 * 1024 * 1024,
	})
	if label != "32GB BJTD4R eMMC" {
		t.Fatalf("buildLabel = %q, want %q", label, "32GB BJTD4R eMMC")
	}
}

func TestDeviceTypeLabel(t *testing.T) {
	cases := map[string]string{
		"sd":     "SD",
		"emmc":   "eMMC",
		"mmc":    "MMC",
		"nvme":   "NVMe",
		"usb":    "USB",
		"ssd":    "SSD",
		"hdd":    "HDD",
		"virtio": "virtio",
		// "disk" is the "we could not tell" value and must add nothing.
		"disk": "",
		"":     "",
	}
	for in, want := range cases {
		if got := deviceTypeLabel(in); got != want {
			t.Errorf("deviceTypeLabel(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSkipBlockDevice(t *testing.T) {
	// The measurement that produced this: a non-Lite CM5 (rev e04180, serial
	// 10000000abcd0005) reported its ONE eMMC as three devices —
	// mmcblk0 at 58 GB plus mmcblk0boot0 and mmcblk0boot1 at 0 GB — and the
	// operator saw "eMMC" three times in the UI.
	skip := map[string]bool{
		"mmcblk0boot0": true,
		"mmcblk0boot1": true,
		"mmcblk1boot0": true,
		"mmcblk0rpmb":  true,
		"loop0":        true,
		"sr0":          true,
		"ram3":         true,
		"zram0":        true,

		// Real storage, and the near-misses that must survive.
		"mmcblk0":   false,
		"mmcblk1":   false,
		"mmcblk0p1": false, // a partition; excluded elsewhere, not here
		"nvme0n1":   false,
		"sda":       false,
		"sdb":       false,
		"vda":       false,
		// Named to look like a pseudo-device without being one.
		"sdramdisk": false,
	}

	for name, want := range skip {
		if got := skipBlockDevice(name); got != want {
			t.Errorf("skipBlockDevice(%q) = %v, want %v", name, got, want)
		}
	}
}

func TestUSBFlashVersusExternalDisk(t *testing.T) {
	// Measured: a SanDisk stick reports rot=1 (its bridge
	// answers no Medium Rotation Rate, so the kernel keeps its default) and rm=1.
	// rot=1 alone is therefore worthless as evidence of spinning rust — it is what
	// produced the label "57GB SanDisk 3.2Gen1 HDD".
	sysBlock, base := fakeSysBlock(t, "sda", map[string]string{
		"queue/rotational": "1\n",
		"removable":        "1\n",
	}, "scb/usb2/2-1/2-1:1.0/host0/target0:0:0/0:0:0:0")
	if got := classifyDeviceType(sysBlock, base, "sda", ""); got != "usb_flash" {
		t.Errorf("a removable USB medium = %q, want usb_flash", got)
	}

	// An external SSD in an enclosure: the bridge reports non-rotating, which is
	// positive evidence. NOT measured on our hardware — no such device was
	// available — so this pins the intended rule, not an observation.
	sysBlock2, base2 := fakeSysBlock(t, "sda", map[string]string{
		"queue/rotational": "0\n",
		"removable":        "0\n",
	}, "scb/usb2/2-1/2-1:1.0/host0/target0:0:0/0:0:0:0")
	if got := classifyDeviceType(sysBlock2, base2, "sda", ""); got != "usb_ssd" {
		t.Errorf("a non-rotating USB device = %q, want usb_ssd", got)
	}

	// Fixed medium, no rotation rate reported: UNKNOWN. It must not be called a
	// disk — that is the same mistake as before, in the other direction.
	sysBlock3, base3 := fakeSysBlock(t, "sda", map[string]string{
		"queue/rotational": "1\n",
		"removable":        "0\n",
	}, "scb/usb2/2-1/2-1:1.0/host0/target0:0:0/0:0:0:0")
	if got := classifyDeviceType(sysBlock3, base3, "sda", ""); got != "usb" {
		t.Errorf("an unclassifiable USB device = %q, want usb", got)
	}

	// Non-rotating outranks removable: flash either way, and the SSD label is the
	// more useful one when picking an install target.
	sysBlock4, base4 := fakeSysBlock(t, "sda", map[string]string{
		"queue/rotational": "0\n",
		"removable":        "1\n",
	}, "scb/usb2/2-1/2-1:1.0/host0/target0:0:0/0:0:0:0")
	if got := classifyDeviceType(sysBlock4, base4, "sda", ""); got != "usb_ssd" {
		t.Errorf("non-rotating + removable = %q, want usb_ssd", got)
	}

	if got := deviceTypeLabel("usb_flash"); got != "USB flash" {
		t.Errorf("deviceTypeLabel(usb_flash) = %q", got)
	}
	if got := deviceTypeLabel("usb_ssd"); got != "USB SSD" {
		t.Errorf("deviceTypeLabel(usb_ssd) = %q", got)
	}
}
