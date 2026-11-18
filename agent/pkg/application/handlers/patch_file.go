package handlers

import (
	"fmt"
	"strings"
)

// DefaultPatchMarker is used when a patch command does not name its block.
const DefaultPatchMarker = "orchestrator"

// patchMarkerPrefixes are the two shapes a managed-block delimiter can take.
// Compared by prefix rather than by exact line so a marker for ANY block name is
// caught, which is the point: an embedded foreign marker breaks that block.
var patchMarkerPrefixes = []string{"# >>> orchestrator:", "# <<< orchestrator:"}

// firstPatchMarkerLine reports the first line of content that would be read as a
// managed-block delimiter.
func firstPatchMarkerLine(content string) (string, bool) {
	for _, line := range strings.Split(content, "\n") {
		trimmed := strings.TrimSpace(line)
		for _, prefix := range patchMarkerPrefixes {
			if strings.HasPrefix(trimmed, prefix) {
				return trimmed, true
			}
		}
	}
	return "", false
}

func patchMarkerLines(marker string) (string, string) {
	return fmt.Sprintf("# >>> orchestrator:%s >>>", marker),
		fmt.Sprintf("# <<< orchestrator:%s <<<", marker)
}

// patchManagedBlock returns the file content with the marker-delimited block
// replaced (when present) or appended at the end. Every line outside the
// block is preserved byte-for-byte. A file with broken markers (begin without
// end, or end before begin) is refused rather than risk corrupting it.
func patchManagedBlock(original []byte, content, marker string) ([]byte, error) {
	if marker == "" {
		marker = DefaultPatchMarker
	}
	begin, end := patchMarkerLines(marker)

	// Refuse content that carries marker lines of its own.
	//
	// Writing it would produce a duplicated pair, and the very next apply of
	// that marker is then refused by the check below — including the `stock`
	// overclock revert, which is the one an operator reaches for when a node
	// will not boot. The node is stuck with whatever config.txt it has and
	// nothing in the product can change it.
	//
	// Any orchestrator marker is refused, not only this block's: a foreign
	// marker inside this block breaks the OTHER block's parsing just as
	// thoroughly, and the author gains nothing by embedding one.
	if line, found := firstPatchMarkerLine(content); found {
		return nil, fmt.Errorf("the content contains a managed-block marker line (%q); writing it would duplicate the markers and permanently refuse every later apply of this block", line)
	}

	block := begin + "\n" + strings.TrimRight(content, "\n") + "\n" + end

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
	// A DUPLICATED pair is as unsafe as a broken one: only the first block
	// would be rewritten, and config.txt's last-assignment-wins semantics make
	// the stale second copy the one the firmware actually reads — a success
	// report for settings the device never boots with.
	if beginCount > 1 || endCount > 1 {
		return nil, fmt.Errorf("managed block markers for '%s' appear more than once (%d begin, %d end); refusing to modify the file", marker, beginCount, endCount)
	}

	switch {
	case beginIdx == -1 && endIdx == -1:
		// Append a new block, keeping exactly one blank line before it and a
		// trailing newline after it.
		out := strings.TrimRight(string(original), "\n")
		if out != "" {
			out += "\n\n"
		}
		return []byte(out + block + "\n"), nil

	case beginIdx >= 0 && endIdx > beginIdx:
		// Replace the existing block in place.
		updated := make([]string, 0, len(lines))
		updated = append(updated, lines[:beginIdx]...)
		updated = append(updated, strings.Split(block, "\n")...)
		updated = append(updated, lines[endIdx+1:]...)
		return []byte(strings.Join(updated, "\n")), nil

	default:
		return nil, fmt.Errorf("managed block markers for '%s' are malformed (begin at line %d, end at line %d); refusing to modify the file", marker, beginIdx+1, endIdx+1)
	}
}
