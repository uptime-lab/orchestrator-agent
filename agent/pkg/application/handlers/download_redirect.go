package handlers

import (
	"errors"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// newDownloadFileClient is the client behind download_file. Operator-supplied
// headers routinely carry a resolved secret (an API key, a registry token), and
// net/http forwards every header but Authorization, Cookie and WWW-Authenticate
// to whatever host a redirect names — and forwards even those after an https →
// http redirect on the same host. So the client drops EVERY operator-supplied
// header on a redirect that leaves the original host (scheme, host and port) or
// that downgrades from https; the download itself still follows the redirect,
// which is what an artifact registry handing out a presigned object-storage
// URL needs. dropped reports whether that happened, for the command result.
//
// The client also sends no Referer on any redirect, with or without operator
// headers: net/http fills it with the previous URL, query included, and a
// download URL's query routinely carries a resolved secret too.
func newDownloadFileClient(timeout time.Duration, headers map[string]string) (client *http.Client, dropped func() bool) {
	var didDrop bool
	client = &http.Client{
		Timeout: timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// The net/http default, kept.
			if len(via) >= 10 {
				return errors.New("stopped after 10 redirects")
			}
			req.Header.Del("Referer")
			if len(headers) == 0 || sameDownloadOrigin(via[0].URL, req.URL) {
				return nil
			}
			for name := range headers {
				if req.Header.Get(name) != "" {
					didDrop = true
				}
				req.Header.Del(name)
			}
			return nil
		},
	}
	return client, func() bool { return didDrop }
}

// sameDownloadOrigin reports whether next is the same scheme, host and port as
// orig. A change of port is a different service; an https → http change is a
// plaintext hop.
func sameDownloadOrigin(orig, next *url.URL) bool {
	if !strings.EqualFold(orig.Scheme, next.Scheme) {
		return false
	}
	return strings.EqualFold(hostWithPort(orig), hostWithPort(next))
}

func hostWithPort(u *url.URL) string {
	port := u.Port()
	if port == "" {
		switch strings.ToLower(u.Scheme) {
		case "https":
			port = "443"
		case "http":
			port = "80"
		}
	}
	return net.JoinHostPort(u.Hostname(), port)
}
