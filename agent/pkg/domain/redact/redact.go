// Package redact strips credential-bearing parts out of URLs, and out of the
// errors and log attributes that quote them. Pure and dependency-free so that
// both the command handlers (what the agent REPORTS to the platform) and the
// gRPC client (what the agent LOGS on the device) share one definition of what
// a redacted URL looks like — two copies is how userinfo survived in one of
// them.
package redact

import (
	"errors"
	"fmt"
	"log/slog"
	neturl "net/url"
	"regexp"
	"strings"
)

// urlInText matches an absolute http(s) URL inside free text, stopping at
// whitespace and at the quoting Go's own errors use ("Get \"https://…\": dial
// tcp …").
var urlInText = regexp.MustCompile(`https?://[^\s"'<>\x60]+`)

// UnparseableURL is what URL returns for a string url.Parse refuses: nothing
// of it is echoed, because an unparseable operator-authored URL can still
// carry a credential in a recognisable place.
const UnparseableURL = "(unparseable url)"

// URL rewrites one URL down to scheme://host/path. Userinfo, query and
// fragment all go: an operator-authored download URL routinely resolves a
// {{secrets.*}} value into its query (a repo token, a presigned capability),
// and a registry URL carries it as user:password@host. journald on the device
// keeps either long past its validity, readable through the node web terminal.
func URL(raw string) string {
	u, err := neturl.Parse(raw)
	if err != nil {
		return UnparseableURL
	}
	u.User = nil
	u.RawQuery = ""
	u.Fragment = ""
	return u.String()
}

// URLsInText rewrites every http(s) URL in a message down to
// scheme://host/path, dropping userinfo, query and fragment. A query that was
// removed leaves a "?[redacted]" marker so a reader can tell a bare URL from
// one that carried something.
//
// Host and path stay: a failure message with no target is close to useless
// for triage, and the credential lives in the userinfo or the query.
func URLsInText(text string) string {
	if text == "" || !strings.Contains(text, "://") {
		return text
	}
	return urlInText.ReplaceAllStringFunc(text, func(raw string) string {
		trailing := ""
		for len(raw) > 0 && strings.ContainsRune(".,;:)]}", rune(raw[len(raw)-1])) {
			trailing = string(raw[len(raw)-1]) + trailing
			raw = raw[:len(raw)-1]
		}
		parsed, err := neturl.Parse(raw)
		if err != nil {
			return "[redacted url]" + trailing
		}
		if parsed.RawQuery == "" && parsed.Fragment == "" && parsed.User == nil {
			return raw + trailing
		}
		suffix := ""
		if parsed.RawQuery != "" {
			suffix = "?[redacted]"
		}
		parsed.User = nil
		parsed.RawQuery = ""
		parsed.Fragment = ""
		return parsed.String() + suffix + trailing
	})
}

// Error returns err with every URL in its chain redacted, keeping the chain's
// shape so errors.Is and errors.As still answer as they did: a *url.Error is
// rebuilt as a *url.Error around the redacted URL and its (redacted) cause,
// and a wrapper whose message quoted a URL becomes a wrapper with the same
// cause and a clean message. An error with nothing to hide is returned as is,
// identity included, so a sentinel compared with errors.Is is still itself.
//
// The chain is REBUILT rather than wrapped: a wrapper that kept the raw
// *url.Error reachable through Unwrap would hand it straight back to any
// errors.As at the logging boundary, full URL and all.
func Error(err error) error {
	if err == nil {
		return nil
	}
	if ue, ok := err.(*neturl.Error); ok {
		return &neturl.Error{Op: ue.Op, URL: URL(ue.URL), Err: Error(ue.Err)}
	}
	msg := err.Error()
	clean := URLsInText(msg)
	// A multi-error (errors.Join, fmt.Errorf with several %w) unwraps to a
	// SLICE; errors.Unwrap answers nil for it, and rebuilding from that
	// dropped every cause — errors.Is(clean, os.ErrNotExist) went false
	// through a join that carried one *url.Error.
	if multi, ok := err.(interface{ Unwrap() []error }); ok {
		causes := multi.Unwrap()
		cleanCauses := make([]error, len(causes))
		same := clean == msg
		for i, c := range causes {
			cleanCauses[i] = Error(c)
			same = same && cleanCauses[i] == c
		}
		if same {
			return err
		}
		return &redactedMultiError{msg: clean, causes: cleanCauses}
	}
	inner := errors.Unwrap(err)
	cleanInner := Error(inner)
	if clean == msg && cleanInner == inner {
		return err
	}
	return &redactedError{msg: clean, cause: cleanInner}
}

type redactedError struct {
	msg   string
	cause error
}

func (e *redactedError) Error() string { return e.msg }
func (e *redactedError) Unwrap() error { return e.cause }

type redactedMultiError struct {
	msg    string
	causes []error
}

func (e *redactedMultiError) Error() string   { return e.msg }
func (e *redactedMultiError) Unwrap() []error { return e.causes }

// SlogAttr is a slog.HandlerOptions.ReplaceAttr that redacts URLs in every
// value shape that can carry one — a string, an error, a []string, a
// *url.URL, a fmt.Stringer, a []error — so a credential-bearing URL that
// reaches a log line through ANY call site, not only the ones somebody
// remembered to wrap, is stripped at the handler. A value with nothing to
// hide passes through untouched, shape included; a redacted one is rendered
// as the text the handler would have printed, minus the credential.
func SlogAttr(_ []string, a slog.Attr) slog.Attr {
	switch a.Value.Kind() {
	case slog.KindString:
		s := a.Value.String()
		if strings.Contains(s, "://") {
			return slog.String(a.Key, URLsInText(s))
		}
	case slog.KindAny:
		switch v := a.Value.Any().(type) {
		case error:
			if v != nil {
				if msg := v.Error(); strings.Contains(msg, "://") {
					return slog.String(a.Key, URLsInText(msg))
				}
			}
		case *neturl.URL:
			if v != nil {
				if s := v.String(); strings.Contains(s, "://") {
					return slog.String(a.Key, URL(s))
				}
			}
		case []string:
			for _, s := range v {
				if strings.Contains(s, "://") {
					out := make([]string, len(v))
					for i, s := range v {
						out[i] = URLsInText(s)
					}
					return slog.Any(a.Key, out)
				}
			}
		case []error:
			for _, e := range v {
				if e != nil && strings.Contains(e.Error(), "://") {
					out := make([]error, len(v))
					for i, e := range v {
						out[i] = Error(e)
					}
					return slog.Any(a.Key, out)
				}
			}
		case fmt.Stringer:
			if s := v.String(); strings.Contains(s, "://") {
				return slog.String(a.Key, URLsInText(s))
			}
		}
	}
	return a
}
