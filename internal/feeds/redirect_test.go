package feeds

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"

	"github.com/kugesh-rajasekaran/make-it-safer/internal/apperr"
)

// hitCounter is a server that counts the requests it gets and keeps the last body.
type hitCounter struct {
	*httptest.Server
	hits atomic.Int32
	body atomic.Value // string
}

func newHitCounter(t *testing.T) *hitCounter {
	t.Helper()
	h := &hitCounter{}
	h.body.Store("")
	h.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.hits.Add(1)
		b, _ := io.ReadAll(r.Body)
		h.body.Store(string(b))
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	t.Cleanup(h.Close)
	return h
}

func redirectTo(target string, code int) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target, code)
	})
}

func TestRedirectToAnotherHostIsRefused(t *testing.T) {
	other := newHitCounter(t)
	for name, code := range map[string]int{"302": http.StatusFound, "307": http.StatusTemporaryRedirect} {
		t.Run(name, func(t *testing.T) {
			start := httptest.NewServer(redirectTo(other.URL+"/steal", code))
			defer start.Close()
			c := NewForTest(start.URL) // only the first server is allowlisted

			var v struct{}
			err := c.GetJSON(context.Background(), start.URL+"/x", &v)
			if !apperr.Is(err, apperr.FeedsRequestFailed) {
				t.Fatalf("GetJSON() = %v, want %s", err, apperr.FeedsRequestFailed)
			}
			err = c.PostJSON(context.Background(), start.URL+"/x", map[string]string{"package": "openssl"}, &v)
			if !apperr.Is(err, apperr.FeedsRequestFailed) {
				t.Fatalf("PostJSON() = %v, want %s", err, apperr.FeedsRequestFailed)
			}
			if other.hits.Load() != 0 {
				t.Fatalf("the redirect was followed to a host that is not on the allowlist (%d requests, body %q)", other.hits.Load(), other.body.Load())
			}
		})
	}
}

// A host on the allowlist still may not send the client to plain HTTP.
func TestRedirectFromHTTPSToHTTPIsRefused(t *testing.T) {
	plain := newHitCounter(t)
	secure := httptest.NewTLSServer(redirectTo(plain.URL+"/x", http.StatusFound))
	defer secure.Close()
	plainURL, _ := url.Parse(plain.URL)
	secureURL, _ := url.Parse(secure.URL)
	hosts := map[string]bool{secureURL.Host: true, plainURL.Host: true} // both allowlisted
	c := newClient(secure.Client(), hosts, false, "test")

	var v struct{}
	if err := c.GetJSON(context.Background(), secure.URL+"/x", &v); !apperr.Is(err, apperr.FeedsRequestFailed) {
		t.Fatalf("GetJSON() = %v, want %s", err, apperr.FeedsRequestFailed)
	}
	if plain.hits.Load() != 0 {
		t.Fatal("the redirect to plain HTTP was followed")
	}
}

// Allowlisted hosts may hand a request to each other over HTTPS, as OSV's
// API does for its data files.
func TestRedirectBetweenAllowlistedHostsWorks(t *testing.T) {
	var gotBody atomic.Value
	gotBody.Store("")
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		gotBody.Store(string(b))
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer target.Close()
	start := httptest.NewTLSServer(redirectTo(target.URL+"/data", http.StatusTemporaryRedirect))
	defer start.Close()
	startURL, _ := url.Parse(start.URL)
	targetURL, _ := url.Parse(target.URL)
	c := newClient(start.Client(), map[string]bool{startURL.Host: true, targetURL.Host: true}, false, "test")

	var v struct{ OK bool }
	if err := c.GetJSON(context.Background(), start.URL+"/x", &v); err != nil || !v.OK {
		t.Fatalf("GetJSON() = %+v, %v", v, err)
	}
	v.OK = false
	if err := c.PostJSON(context.Background(), start.URL+"/x", map[string]string{"package": "openssl"}, &v); err != nil || !v.OK {
		t.Fatalf("PostJSON() = %+v, %v", v, err)
	}
	if gotBody.Load() != `{"package":"openssl"}` {
		t.Fatalf("the redirected POST arrived with body %q", gotBody.Load())
	}

	// The same redirect is refused once the target is not on the list.
	c = newClient(start.Client(), map[string]bool{startURL.Host: true}, false, "test")
	if err := c.GetJSON(context.Background(), start.URL+"/x", &v); !apperr.Is(err, apperr.FeedsRequestFailed) {
		t.Fatalf("redirect off the allowlist: %v", err)
	}
}

func TestRedirectWithinTheHostWorks(t *testing.T) {
	for name, tls := range map[string]bool{"http (tests)": false, "https": true} {
		t.Run(name, func(t *testing.T) {
			mux := http.NewServeMux()
			mux.Handle("/old", redirectTo("/new", http.StatusMovedPermanently))
			mux.HandleFunc("/new", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`{"ok":true}`)) })
			var srv *httptest.Server
			var c *Client
			if tls {
				srv = httptest.NewTLSServer(mux)
				u, _ := url.Parse(srv.URL)
				c = newClient(srv.Client(), map[string]bool{u.Host: true}, false, "test")
			} else {
				srv = httptest.NewServer(mux)
				c = NewForTest(srv.URL)
			}
			defer srv.Close()

			var v struct{ OK bool }
			if err := c.GetJSON(context.Background(), srv.URL+"/old", &v); err != nil || !v.OK {
				t.Fatalf("GetJSON() = %+v, %v", v, err)
			}
		})
	}
}

func TestRedirectLimit(t *testing.T) {
	c := NewForTest("http://127.0.0.1:1")
	req, _ := http.NewRequest(http.MethodGet, "http://127.0.0.1:1/next", nil)
	if err := c.checkRedirect(req, make([]*http.Request, 9)); err != nil {
		t.Fatalf("9 earlier requests: %v", err)
	}
	if err := c.checkRedirect(req, make([]*http.Request, 10)); err == nil {
		t.Fatal("redirects were not limited")
	}
}
