package handlers

import (
	"regexp"
	"strings"
)

// hostnameLabelRe validates a single RFC 1123 hostname label.
var hostnameLabelRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// setHostnameRejection returns the report to send when the device cannot accept
// a hostname, or "" when it can.
//
// The rejected value is deliberately never part of the report. A command report
// is stored in plaintext on the platform and listed to everyone who can read the
// node, while a hostname can be a resolved {{secrets.*}} — and a value that
// looks like a secret is exactly the shape that fails this check, so quoting it
// back leaked precisely the values worth protecting.
func setHostnameRejection(name string) string {
	if hostnameLabelRe.MatchString(strings.TrimSpace(name)) {
		return ""
	}
	return "invalid hostname (must be an RFC 1123 label: a-z, 0-9, '-', up to 63 chars)"
}
