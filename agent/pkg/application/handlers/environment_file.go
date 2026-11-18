package handlers

import (
	"fmt"
	"sort"
	"strings"
)

// environmentMarker names the managed block in /etc/environment. The markers
// are the patch_file idiom (`# >>> orchestrator:environment >>>`), so the same
// parser rules apply: everything outside the block is operator-owned and
// preserved byte-for-byte, everything inside is platform-owned and replaced
// wholesale on every apply.
const environmentMarker = "environment"

// reconcileEnvironmentContent computes the new /etc/environment content for
// the given desired env-secret set. The incoming map is the RESOLVED effective
// set (node → OU → root union, built platform-side), so it is authoritative:
// the managed block is replaced with exactly this set, which is what makes a
// DETACHED secret disappear from the device — the old merge only overwrote
// incoming keys and could never remove one.
//
// An incoming key found OUTSIDE the block is dropped from there and written
// inside it: that is the one-time migration for files written by agents that
// predate the marker (they merged keys directly into the file body). Keys
// detached BEFORE the first marker-aware apply are indistinguishable from
// operator-owned lines and are deliberately left alone — guessing would risk
// deleting an operator's own variable.
//
// An empty incoming set removes the managed block entirely and keeps the rest
// of the file.
func reconcileEnvironmentContent(original []byte, env map[string]string) ([]byte, error) {
	begin, end := patchMarkerLines(environmentMarker)

	// Drop every line whose key is in the incoming set, wherever it sits:
	// outside the block it is a pre-marker copy (migration), inside it is
	// replaced wholesale below anyway. Marker and comment lines are kept.
	lines := strings.Split(string(original), "\n")
	kept := make([]string, 0, len(lines))
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == begin || trimmed == end {
			kept = append(kept, line)
			continue
		}
		if trimmed != "" && !strings.HasPrefix(trimmed, "#") {
			key := strings.TrimSpace(strings.SplitN(trimmed, "=", 2)[0])
			if _, managed := env[key]; managed {
				continue
			}
		}
		kept = append(kept, line)
	}
	cleaned := []byte(strings.Join(kept, "\n"))

	if len(env) == 0 {
		return removeManagedBlock(cleaned, environmentMarker)
	}

	names := make([]string, 0, len(env))
	for name := range env {
		names = append(names, name)
	}
	sort.Strings(names)

	var b strings.Builder
	for _, name := range names {
		fmt.Fprintf(&b, "%s=%s\n", name, env[name])
	}
	return patchManagedBlock(cleaned, b.String(), environmentMarker)
}

// removeManagedBlock strips the marker-delimited block (markers included) from
// the content, preserving every other line. A file with no markers is returned
// unchanged; broken or duplicated markers are refused with the same rules as
// patchManagedBlock, for the same reason — do not modify a file whose managed
// region cannot be identified unambiguously.
func removeManagedBlock(original []byte, marker string) ([]byte, error) {
	begin, end := patchMarkerLines(marker)
	lines := strings.Split(string(original), "\n")
	beginIdx, endIdx := -1, -1
	beginCount, endCount := 0, 0
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == begin {
			beginCount++
			if beginIdx == -1 {
				beginIdx = i
			}
		}
		if trimmed == end {
			endCount++
			if endIdx == -1 {
				endIdx = i
			}
		}
	}
	if beginCount == 0 && endCount == 0 {
		return original, nil
	}
	if beginCount > 1 || endCount > 1 {
		return nil, fmt.Errorf("managed block markers for '%s' appear more than once (%d begin, %d end); refusing to modify the file", marker, beginCount, endCount)
	}
	if beginIdx == -1 || endIdx <= beginIdx {
		return nil, fmt.Errorf("managed block markers for '%s' are malformed (begin at line %d, end at line %d); refusing to modify the file", marker, beginIdx+1, endIdx+1)
	}

	out := make([]string, 0, len(lines))
	out = append(out, lines[:beginIdx]...)
	out = append(out, lines[endIdx+1:]...)
	return []byte(strings.Join(out, "\n")), nil
}
