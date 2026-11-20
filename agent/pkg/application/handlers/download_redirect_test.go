package handlers

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"
)

type seenHeaders struct {
	mu   sync.Mutex
	seen map[string]string
}

func (s *seenHeaders) record(r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.seen = map[string]string{
		"X-Api-Key":     r.Header.Get("X-Api-Key"),
		"Authorization": r.Header.Get("Authorization"),
	}
}

func (s *seenHeaders) get(name string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.seen[name]
}

func fetchWithOperatorHeaders(t *testing.T, rawURL string) (dropped bool) {
	t.Helper()
	headers := map[string]string{"X-Api-Key": "key-value", "Authorization": "Bearer token-value"}
	client, droppedFn := newDownloadFileClient(5*time.Second, headers)
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	return droppedFn()
}

// A redirect to another origin (here: another port, which net/http treats as
// the same host and so keeps even Authorization) receives none of the
// operator's headers; the download still follows it.
func TestDownloadFileDropsOperatorHeadersOnCrossOriginRedirect(t *testing.T) {
	var target seenHeaders
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		target.record(r)
		_, _ = w.Write([]byte("payload"))
	}))
	defer other.Close()
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Api-Key") != "key-value" {
			t.Errorf("the original host did not receive the operator header")
		}
		http.Redirect(w, r, other.URL+"/object", http.StatusFound)
	}))
	defer origin.Close()

	if !fetchWithOperatorHeaders(t, origin.URL+"/start") {
		t.Error("the result does not report that headers were dropped")
	}
	if v := target.get("X-Api-Key"); v != "" {
		t.Errorf("custom credential header reached the redirect target: %q", v)
	}
	if v := target.get("Authorization"); v != "" {
		t.Errorf("Authorization reached the redirect target: %q", v)
	}
}

// A redirect within the same origin keeps them: that is the registry that
// moves a path, and dropping the credential there would break the download.
func TestDownloadFileKeepsOperatorHeadersOnSameOriginRedirect(t *testing.T) {
	var target seenHeaders
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/start" {
			http.Redirect(w, r, "/final", http.StatusFound)
			return
		}
		target.record(r)
		_, _ = w.Write([]byte("payload"))
	}))
	defer srv.Close()

	if fetchWithOperatorHeaders(t, srv.URL+"/start") {
		t.Error("a same-origin redirect reported dropped headers")
	}
	if target.get("X-Api-Key") != "key-value" || target.get("Authorization") != "Bearer token-value" {
		t.Errorf("same-origin redirect lost the operator headers: %v", target.seen)
	}
}

func TestSameDownloadOriginTreatsDowngradeAsCrossOrigin(t *testing.T) {
	parse := func(s string) *url.URL {
		u, err := url.Parse(s)
		if err != nil {
			t.Fatal(err)
		}
		return u
	}
	for _, tc := range []struct {
		a, b string
		same bool
	}{
		{"https://reg.example/a", "https://REG.example:443/b", true},
		{"https://reg.example/a", "http://reg.example/b", false},
		{"https://reg.example/a", "https://objects.example/b", false},
		{"http://reg.example:8080/a", "http://reg.example:8081/b", false},
	} {
		if got := sameDownloadOrigin(parse(tc.a), parse(tc.b)); got != tc.same {
			t.Errorf("sameDownloadOrigin(%s, %s) = %v, want %v", tc.a, tc.b, got, tc.same)
		}
	}
}

// No redirect carries the previous URL as Referer, whatever the operator
// headers: the query of a download URL can hold a resolved secret.
func TestDownloadFileSendsNoRefererOnRedirect(t *testing.T) {
	for _, tc := range []struct {
		name    string
		headers map[string]string
		sameOrg bool
	}{
		{"cross-origin, no operator headers", nil, false},
		{"cross-origin, operator headers", map[string]string{"X-Api-Key": "key-value"}, false},
		{"same origin", nil, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var mu sync.Mutex
			referer := "unset"
			final := func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				referer = r.Header.Get("Referer")
				mu.Unlock()
				_, _ = w.Write([]byte("payload"))
			}
			other := httptest.NewServer(http.HandlerFunc(final))
			defer other.Close()
			origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/final" {
					final(w, r)
					return
				}
				next := other.URL + "/object"
				if tc.sameOrg {
					next = "/final"
				}
				http.Redirect(w, r, next, http.StatusFound)
			}))
			defer origin.Close()

			client, _ := newDownloadFileClient(5*time.Second, tc.headers)
			req, err := http.NewRequest(http.MethodGet, origin.URL+"/pkg.tar?token=secret-value", nil)
			if err != nil {
				t.Fatal(err)
			}
			for k, v := range tc.headers {
				req.Header.Set(k, v)
			}
			resp, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			_ = resp.Body.Close()
			mu.Lock()
			defer mu.Unlock()
			if referer != "" {
				t.Errorf("the redirect target received Referer %q", referer)
			}
		})
	}
}
