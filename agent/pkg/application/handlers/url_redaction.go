package handlers

// URL redaction for anything the agent SENDS BACK to the platform. Deliberately
// not in a linux-tagged file: it is pure and worth testing on a dev machine.

import "agent/pkg/domain/redact"

// redactURLsInText rewrites every http(s) URL in a message down to
// scheme://host/path, dropping userinfo, query and fragment.
//
// Applied to every command status and result the agent reports, because the
// leak is not in any one handler's wording — it is in Go itself: *url.Error
// embeds the whole URL it was given, so `"download failed: " + err.Error()`
// copies a resolved {{secrets.token}} out of a query string and into
// `node_commands.details`, which is plaintext on the platform and on no rewrap
// list. The platform redacts on write too; this closes it at the source, which
// also keeps it out of the gRPC frame and the platform's logs.
//
// The definition lives in domain/redact so the gRPC client's log line and the
// handlers' status reports cannot disagree about what is stripped.
func redactURLsInText(text string) string {
	return redact.URLsInText(text)
}
