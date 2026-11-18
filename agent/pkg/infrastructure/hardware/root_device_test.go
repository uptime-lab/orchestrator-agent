package hardware

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Real /proc/mounts shapes. The USB case is the one that motivated
// all of this: a node booting from /dev/sda2 while an SD card sits beside it,
// which the class-based guess could not resolve.
func TestResolveRootDeviceFromRealMountShapes(t *testing.T) {
	cases := map[string]struct {
		mounts string
		want   string
	}{
		"usb disk (Node-abcd0003)": {
			mounts: "/dev/sda2 / ext4 rw,relatime 0 0\n/dev/sda1 /boot/firmware vfat rw 0 0\n",
			want:   "/dev/sda",
		},
		"nvme": {
			mounts: "/dev/nvme0n1p2 / ext4 rw,relatime 0 0\n",
			want:   "/dev/nvme0n1",
		},
		"sd card (Node-abcd0004)": {
			mounts: "/dev/mmcblk0p2 / ext4 rw 0 0\n",
			want:   "/dev/mmcblk0",
		},
		// The recovery bootstrap. "" is the correct answer, not a failure: no
		// local device booted this node, and marking the disk that merely holds
		// an installed OS would mislead the operator most likely to act on it.
		"recovery bootstrap runs from RAM": {
			mounts: "rootfs / rootfs rw 0 0\n/dev/nvme0n1p2 /mnt/target ext4 rw 0 0\n",
			want:   "",
		},
		"tmpfs root": {
			mounts: "tmpfs / tmpfs rw 0 0\n",
			want:   "",
		},
		"overlay root (container)": {
			mounts: "overlay / overlay rw 0 0\n",
			want:   "",
		},
		// Some initramfs report this; it names no disk we can offer as a target.
		"/dev/root is not resolvable": {
			mounts: "/dev/root / ext4 rw 0 0\n",
			want:   "/dev/root",
		},
		"no root line at all": {
			mounts: "proc /proc proc rw 0 0\n",
			want:   "",
		},
		// A pivot leaves the earlier mount visible; the LAST one is in effect.
		"later root mount wins": {
			mounts: "rootfs / rootfs rw 0 0\n/dev/mmcblk0p2 / ext4 rw 0 0\n",
			want:   "/dev/mmcblk0",
		},
		"pivot to RAM wins too": {
			mounts: "/dev/mmcblk0p2 / ext4 rw 0 0\nrootfs / rootfs rw 0 0\n",
			want:   "",
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			got := resolveRootDevice(strings.NewReader(tc.mounts), t.TempDir())
			if got != tc.want {
				t.Errorf("resolveRootDevice = %q, want %q", got, tc.want)
			}
		})
	}
}

// The name-based reduction is the fallback for when sysfs is unavailable. The
// nvme case is why the two conventions cannot be collapsed: stripping trailing
// digits from "nvme0n1" would produce "nvme0n", a device that does not exist.
func TestWholeDiskFromName(t *testing.T) {
	cases := map[string]string{
		"sda2":       "sda",
		"sda":        "sda",
		"sdb15":      "sdb",
		"nvme0n1p2":  "nvme0n1",
		"nvme0n1":    "nvme0n1",
		"mmcblk0p1":  "mmcblk0",
		"mmcblk0":    "mmcblk0",
		"mmcblk0p12": "mmcblk0",
		"vda1":       "vda",
		// loop0 is a whole device, not partition 0 of "loop"; same trap as
		// mmcblk0 and nvme0n1, and the reason the two families are separate.
		"loop0": "loop0",
		// Unrecognised names are left alone: naming a disk that does not exist
		// is worse than naming nothing.
		"weird9": "weird9",
	}
	for in, want := range cases {
		if got := wholeDiskFromName(in); got != want {
			t.Errorf("wholeDiskFromName(%q) = %q, want %q", in, got, want)
		}
	}
}

// sysfs answers without any naming convention, which is why it is preferred: a
// partition sits inside its disk's directory, and carries a `partition` file
// that a whole disk does not.
func TestWholeDiskFromSysfs(t *testing.T) {
	root := t.TempDir()
	sysClassBlock := filepath.Join(root, "sys", "class", "block")
	diskDir := filepath.Join(root, "sys", "devices", "pci", "nvme", "nvme0n1")
	partDir := filepath.Join(diskDir, "nvme0n1p2")
	if err := os.MkdirAll(partDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(partDir, "partition"), []byte("2\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(sysClassBlock, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(partDir, filepath.Join(sysClassBlock, "nvme0n1p2")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(diskDir, filepath.Join(sysClassBlock, "nvme0n1")); err != nil {
		t.Fatal(err)
	}

	if got := wholeDiskFromSysfs(sysClassBlock, "nvme0n1p2"); got != "nvme0n1" {
		t.Errorf("partition reduced to %q, want nvme0n1", got)
	}
	// A whole disk has no `partition` file, so it must be returned unchanged
	// rather than "reduced" to its controller.
	if got := wholeDiskFromSysfs(sysClassBlock, "nvme0n1"); got != "nvme0n1" {
		t.Errorf("whole disk became %q, want nvme0n1", got)
	}
	if got := wholeDiskFromSysfs(sysClassBlock, "absent"); got != "" {
		t.Errorf("absent device = %q, want empty", got)
	}
}

// sysfs wins when both can answer, and the fallback covers it when sysfs cannot.
func TestResolveRootDevicePrefersSysfs(t *testing.T) {
	root := t.TempDir()
	sysClassBlock := filepath.Join(root, "sys", "class", "block")
	// A deliberately convention-defying layout: the partition is named "weird9"
	// but lives inside disk "sda". Only sysfs can get this right.
	diskDir := filepath.Join(root, "sys", "devices", "usb", "sda")
	partDir := filepath.Join(diskDir, "weird9")
	if err := os.MkdirAll(partDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(partDir, "partition"), []byte("9\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(sysClassBlock, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(partDir, filepath.Join(sysClassBlock, "weird9")); err != nil {
		t.Fatal(err)
	}

	got := resolveRootDevice(strings.NewReader("/dev/weird9 / ext4 rw 0 0\n"), sysClassBlock)
	if got != "/dev/sda" {
		t.Errorf("resolveRootDevice = %q, want /dev/sda (sysfs should beat the naming convention)", got)
	}
}
