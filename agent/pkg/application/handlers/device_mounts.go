package handlers

import (
	"bufio"
	"io"
	"strings"
)

// deviceMount is one entry of /proc/mounts that belongs to a target device.
type deviceMount struct {
	Source     string
	MountPoint string
	FSType     string
	Options    string
}

// mountsForDevice returns the mounts of devicePath and of its partitions,
// EXCLUDING the root filesystem.
//
// Matching is exact rather than a prefix test, and that is not pedantry:
// /dev/sda is a prefix of /dev/sdaa, which is a real device name on a host with
// more than 26 disks, and unmounting someone else's disk before an erase is the
// worst possible way to be approximately right. A partition is devicePath
// followed by digits (sda1) or by "p" and digits (mmcblk0p1, nvme0n1p1).
//
// "/" is never returned. A caller that unmounted the running root would take
// the agent down with it, and the callers exist precisely to make a destructive
// operation possible — not to make it fatal.
func mountsForDevice(procMounts io.Reader, devicePath string) []deviceMount {
	if devicePath == "" {
		return nil
	}

	var found []deviceMount
	scanner := bufio.NewScanner(procMounts)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 {
			continue
		}
		source, mountPoint := fields[0], unescapeMountField(fields[1])
		if mountPoint == "/" {
			continue
		}
		if !isDeviceOrPartition(source, devicePath) {
			continue
		}
		m := deviceMount{Source: source, MountPoint: mountPoint}
		if len(fields) >= 4 {
			m.FSType, m.Options = fields[2], fields[3]
		}
		found = append(found, m)
	}
	return found
}

// isDeviceOrPartition reports whether source is devicePath itself or one of its
// partitions.
func isDeviceOrPartition(source, devicePath string) bool {
	if source == devicePath {
		return true
	}
	if !strings.HasPrefix(source, devicePath) {
		return false
	}
	suffix := source[len(devicePath):]
	if suffix == "" {
		return false
	}
	// nvme0n1p1 / mmcblk0p1 use a "p" separator; sda1 does not.
	if suffix[0] == 'p' {
		suffix = suffix[1:]
	}
	if suffix == "" {
		return false
	}
	for i := 0; i < len(suffix); i++ {
		if suffix[i] < '0' || suffix[i] > '9' {
			return false
		}
	}
	return true
}

// unescapeMountField decodes the octal escapes the kernel writes into
// /proc/mounts for space, tab, newline and backslash. A mount point under
// /mnt/sd card would otherwise be truncated at the space and umount would be
// handed a path that does not exist.
func unescapeMountField(field string) string {
	if !strings.Contains(field, `\`) {
		return field
	}
	var b strings.Builder
	for i := 0; i < len(field); i++ {
		if field[i] != '\\' || i+3 >= len(field) {
			b.WriteByte(field[i])
			continue
		}
		var v int
		ok := true
		for _, c := range field[i+1 : i+4] {
			if c < '0' || c > '7' {
				ok = false
				break
			}
			v = v*8 + int(c-'0')
		}
		if !ok {
			b.WriteByte(field[i])
			continue
		}
		b.WriteByte(byte(v))
		i += 3
	}
	return b.String()
}

// remountArgs are mount(8)'s arguments for putting m back as it was.
func remountArgs(m deviceMount) []string {
	var args []string
	if m.FSType != "" {
		args = append(args, "-t", m.FSType)
	}
	if m.Options != "" {
		args = append(args, "-o", m.Options)
	}
	return append(args, m.Source, m.MountPoint)
}
