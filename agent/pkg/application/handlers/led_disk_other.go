//go:build !linux

package handlers

// readDiskUsedPercent is a stub off Linux so the color math stays unit
// testable on every platform.
func readDiskUsedPercent() float64 { return 0 }
