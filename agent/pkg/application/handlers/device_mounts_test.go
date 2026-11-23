package handlers

import (
	"strings"
	"testing"
)

const procMountsSample = `rootfs / rootfs rw 0 0
devtmpfs /dev devtmpfs rw,relatime 0 0
proc /proc proc rw,relatime 0 0
/dev/mmcblk0p1 /mnt/sdcard vfat rw,sync,relatime 0 0
/dev/nvme0n1p2 /data ext4 rw,relatime 0 0
/dev/sdaa1 /srv/other ext4 rw,relatime 0 0
tmpfs /run tmpfs rw,nosuid 0 0
`

func mountPoints(mounts []deviceMount) []string {
	out := make([]string, 0, len(mounts))
	for _, m := range mounts {
		out = append(out, m.MountPoint)
	}
	return out
}

func TestMountsForDeviceFindsPartitionOfTheBootCard(t *testing.T) {
	got := mountPoints(mountsForDevice(strings.NewReader(procMountsSample), "/dev/mmcblk0"))
	if len(got) != 1 || got[0] != "/mnt/sdcard" {
		t.Fatalf("want [/mnt/sdcard], got %v", got)
	}
}

// The bug this guards: /dev/sda is a prefix of /dev/sdaa, a real name on a host
// with more than 26 disks. A prefix test would unmount an unrelated disk right
// before erasing it.
func TestMountsForDeviceDoesNotMatchALongerDeviceName(t *testing.T) {
	if got := mountsForDevice(strings.NewReader(procMountsSample), "/dev/sda"); len(got) != 0 {
		t.Fatalf("/dev/sda must not match /dev/sdaa1, got %v", mountPoints(got))
	}
	if got := mountPoints(mountsForDevice(strings.NewReader(procMountsSample), "/dev/sdaa")); len(got) != 1 {
		t.Fatalf("/dev/sdaa should match its own partition, got %v", got)
	}
}

// mmcblk0 must not match mmcblk0p1's SIBLING device mmcblk1, and nvme0n1 must
// match nvme0n1p2 through the "p" separator.
func TestMountsForDeviceHandlesBothPartitionNamings(t *testing.T) {
	if got := mountPoints(mountsForDevice(strings.NewReader(procMountsSample), "/dev/nvme0n1")); len(got) != 1 || got[0] != "/data" {
		t.Fatalf("want [/data], got %v", got)
	}
	if got := mountsForDevice(strings.NewReader(procMountsSample), "/dev/mmcblk1"); len(got) != 0 {
		t.Fatalf("mmcblk1 must not match mmcblk0's partitions, got %v", mountPoints(got))
	}
}

// Never return "/": a caller that unmounted the running root would take the
// agent down with it.
func TestMountsForDeviceNeverReturnsRoot(t *testing.T) {
	const rooted = "/dev/mmcblk0p2 / ext4 rw,relatime 0 0\n/dev/mmcblk0p1 /boot/firmware vfat rw 0 0\n"
	got := mountPoints(mountsForDevice(strings.NewReader(rooted), "/dev/mmcblk0"))
	if len(got) != 1 || got[0] != "/boot/firmware" {
		t.Fatalf("want [/boot/firmware] only, got %v", got)
	}
}

func TestMountsForDeviceMatchesTheWholeDiskItself(t *testing.T) {
	const whole = "/dev/sdb /media/stick vfat rw 0 0\n"
	got := mountPoints(mountsForDevice(strings.NewReader(whole), "/dev/sdb"))
	if len(got) != 1 || got[0] != "/media/stick" {
		t.Fatalf("want [/media/stick], got %v", got)
	}
}

// The kernel octal-escapes whitespace in /proc/mounts. Passing the raw field to
// umount would hand it a path that does not exist.
func TestMountsForDeviceUnescapesMountPoints(t *testing.T) {
	const spaced = `/dev/sdc1 /media/My\040Card vfat rw 0 0` + "\n"
	got := mountPoints(mountsForDevice(strings.NewReader(spaced), "/dev/sdc"))
	if len(got) != 1 || got[0] != "/media/My Card" {
		t.Fatalf("want [/media/My Card], got %q", got)
	}
}

func TestMountsForDeviceIgnoresEmptyDevicePath(t *testing.T) {
	if got := mountsForDevice(strings.NewReader(procMountsSample), ""); len(got) != 0 {
		t.Fatalf("an empty device path must match nothing, got %v", mountPoints(got))
	}
}

// A command that released the provisioning card's mount and was then refused
// mounts it back exactly as it was: the identity release writes the adoption
// file through that mount, and with the mount gone the write lands in the RAM
// directory beneath it while the card keeps the old identity.
func TestReleasedMountIsRestoredAsItWas(t *testing.T) {
	mounts := mountsForDevice(strings.NewReader(procMountsSample), "/dev/mmcblk0")
	if len(mounts) != 1 {
		t.Fatalf("want one mount, got %v", mounts)
	}
	got := strings.Join(remountArgs(mounts[0]), " ")
	want := "-t vfat -o rw,sync,relatime /dev/mmcblk0p1 /mnt/sdcard"
	if got != want {
		t.Fatalf("remount args = %q, want %q", got, want)
	}
}
