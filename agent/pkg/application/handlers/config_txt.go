package handlers

import (
	"fmt"
	"strings"
)

// ensureConfigTxtSetting makes sure the given setting line exists inside the
// named model-filter section of a Raspberry Pi config.txt. The setting is
// only recognized (and only inserted) inside that section, so other models
// are never affected. Returns the updated content and whether it changed.
func ensureConfigTxtSetting(content, section, setting string) (string, bool) {
	header := fmt.Sprintf("[%s]", section)
	lines := strings.Split(content, "\n")

	inSection := false
	sectionExists := false
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "[") {
			inSection = trimmed == header
			if inSection {
				sectionExists = true
			}
			continue
		}
		if inSection && trimmed == setting {
			return content, false
		}
	}

	if !sectionExists {
		out := strings.TrimRight(content, "\n")
		if out != "" {
			out += "\n"
		}
		out += "\n" + header + "\n" + setting + "\n"
		return out, true
	}

	// Insert right after the first occurrence of the section header.
	var out []string
	inserted := false
	for _, line := range lines {
		out = append(out, line)
		if !inserted && strings.TrimSpace(line) == header {
			out = append(out, setting)
			inserted = true
		}
	}
	updated := strings.Join(out, "\n")
	if !strings.HasSuffix(updated, "\n") {
		updated += "\n"
	}
	return updated, true
}
