package handlers

import "testing"

func TestRedactURLsInText(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{
			// The real shape: Go's *url.Error quotes the whole URL it was given.
			name: "go transport error keeps the target but drops the query",
			in:   `download failed: Get "https://files.example.test/pkg.tar?token=s3cr3t": dial tcp: i/o timeout`,
			want: `download failed: Get "https://files.example.test/pkg.tar?[redacted]": dial tcp: i/o timeout`,
		},
		{
			name: "userinfo credentials are dropped",
			in:   "download failed: https://user:hunter2@files.example.test/pkg.tar",
			want: "download failed: https://files.example.test/pkg.tar",
		},
		{
			name: "a capability URL's signature is a bearer credential",
			in:   "upload failed for https://app.example.test/capture/abc?exp=1&sig=deadbeef.",
			want: "upload failed for https://app.example.test/capture/abc?[redacted].",
		},
		{
			name: "a URL with nothing to hide is left alone",
			in:   "download failed: https://files.example.test/pkg.tar (404)",
			want: "download failed: https://files.example.test/pkg.tar (404)",
		},
		{
			name: "text with no URL is untouched",
			in:   "apt-get install failed: exit status 100",
			want: "apt-get install failed: exit status 100",
		},
		{
			name: "empty stays empty",
			in:   "",
			want: "",
		},
	}
	for _, tc := range cases {
		if got := redactURLsInText(tc.in); got != tc.want {
			t.Errorf("%s:\n redactURLsInText(%q)\n            = %q\n       want %q", tc.name, tc.in, got, tc.want)
		}
	}
}
