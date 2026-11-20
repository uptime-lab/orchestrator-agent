package handlers

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// targetDeviceHolders lists what keeps a disk, or one of its partitions, in
// use WITHOUT a mount of its own: a device-mapper target (LUKS, LVM), an md
// array member, or an active swap partition. None of those appears under the
// partition's name in df or /proc/mounts, so the mount checks pass a disk
// whose live root filesystem sits on it through one of them.
//
// sysClassBlock is /sys/class/block and procSwaps /proc/swaps on a real host;
// both are parameters so the rule is testable. An unreadable source yields no
// entries — the caller also asks the kernel directly (an exclusive open).
func targetDeviceHolders(sysClassBlock, procSwaps, devicePath string) []string {
	disk := filepath.Base(devicePath)
	names := []string{disk}
	if entries, err := os.ReadDir(filepath.Join(sysClassBlock, disk)); err == nil {
		for _, e := range entries {
			if !strings.HasPrefix(e.Name(), disk) {
				continue
			}
			if _, err := os.Stat(filepath.Join(sysClassBlock, disk, e.Name(), "partition")); err == nil {
				names = append(names, e.Name())
			}
		}
	}

	var held []string
	for _, name := range names {
		holders, err := os.ReadDir(filepath.Join(sysClassBlock, name, "holders"))
		if err != nil {
			continue
		}
		for _, h := range holders {
			label := h.Name()
			if dm, err := os.ReadFile(filepath.Join(sysClassBlock, h.Name(), "dm", "name")); err == nil {
				if n := strings.TrimSpace(string(dm)); n != "" {
					label = fmt.Sprintf("%s (%s)", h.Name(), n)
				}
			}
			held = append(held, fmt.Sprintf("/dev/%s is held by %s", name, label))
		}
	}

	if f, err := os.Open(procSwaps); err == nil {
		defer f.Close()
		sc := bufio.NewScanner(f)
		first := true
		for sc.Scan() {
			if first { // the column header
				first = false
				continue
			}
			fields := strings.Fields(sc.Text())
			if len(fields) == 0 || !strings.HasPrefix(fields[0], "/dev/") {
				continue
			}
			for _, name := range names {
				if fields[0] == "/dev/"+name {
					held = append(held, fmt.Sprintf("/dev/%s is active swap", name))
				}
			}
		}
	}
	return held
}
