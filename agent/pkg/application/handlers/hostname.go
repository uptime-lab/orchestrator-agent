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

// etcHostsWithHostname returns /etc/hosts content with every 127.0.1.1 line
// mapping name, appending one when there is none. Every line of the result
// ends in a newline, including one whose original lacked it, so applying the
// same name again returns the content unchanged.
func etcHostsWithHostname(content, name string) string {
	var lines []string
	if content != "" {
		lines = strings.Split(strings.TrimSuffix(content, "\n"), "\n")
	}
	found := false
	for i, ln := range lines {
		if fields := strings.Fields(ln); len(fields) >= 1 && fields[0] == "127.0.1.1" {
			lines[i] = "127.0.1.1\t" + name
			found = true
		}
	}
	if !found {
		lines = append(lines, "127.0.1.1\t"+name)
	}
	return strings.Join(lines, "\n") + "\n"
}
