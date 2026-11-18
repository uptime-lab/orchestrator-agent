//go:build linux

package handlers

import "golang.org/x/sys/unix"

// readDiskUsedPercent returns the root filesystem's used space as a
// percentage (0 on error -> renders green). Statfs of "/" on purpose: the
// LED answers "is this node's disk filling", and the root filesystem is the
// one whose exhaustion takes the node down.
func readDiskUsedPercent() float64 {
	var st unix.Statfs_t
	if err := unix.Statfs("/", &st); err != nil || st.Blocks == 0 {
		return 0
	}
	used := float64(st.Blocks-st.Bfree) / float64(st.Blocks)
	return used * 100
}
