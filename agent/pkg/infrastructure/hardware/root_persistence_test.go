package hardware

import (
	"strings"
	"testing"
)

func TestClassifyRootPersistence(t *testing.T) {
	cases := []struct {
		name, mounts, want string
	}{
		{"installed OS on nvme", "/dev/nvme0n1p2 / ext4 rw 0 0\n", "persistent"},
		{"overlayroot", "/dev/mmcblk0p2 /media/root-ro ext4 ro 0 0\noverlayroot / overlay rw,lowerdir=/media/root-ro,upperdir=/media/root-rw/overlay 0 0\n", "overlay"},
		{"recovery ram root", "rootfs / rootfs rw 0 0\n", ""},
		{"tmpfs root", "tmpfs / tmpfs rw 0 0\n", ""},
		{"no root line", "proc /proc proc rw 0 0\n", ""},
		// An initramfs pivot leaves the earlier "/" visible; the LAST wins.
		{"pivot then overlay", "/dev/sda2 / ext4 rw 0 0\noverlay / overlay rw 0 0\n", "overlay"},
		{"overlay then real root wins", "overlay / overlay rw 0 0\n/dev/sda2 / ext4 rw 0 0\n", "persistent"},
	}
	for _, tc := range cases {
		if got := classifyRootPersistence(strings.NewReader(tc.mounts)); got != tc.want {
			t.Errorf("%s: got %q, want %q", tc.name, got, tc.want)
		}
	}
}
