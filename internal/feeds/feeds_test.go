package feeds

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kugesh-rajasekaran/make-it-safer/internal/apperr"
)

func TestAllowlistIsEnforced(t *testing.T) {
	c := New("test")
	for _, u := range []string{
		"https://evil.example/collect",
		"http://api.osv.dev/v1/query", // plain HTTP
		"https://api.osv.dev.evil.example/v1/query",
	} {
		if _, err := c.Get(context.Background(), u, ""); !apperr.Is(err, apperr.FeedsHostNotAllowed) {
			t.Errorf("Get(%s) = %v, want %s", u, err, apperr.FeedsHostNotAllowed)
		}
	}
}

func TestGetJSONAndETag(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("If-None-Match") == `"v1"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", `"v1"`)
		_, _ = w.Write([]byte(`{"hello":"world"}`))
	}))
	defer srv.Close()
	c := NewForTest(srv.URL)

	var v struct{ Hello string }
	if err := c.GetJSON(context.Background(), srv.URL+"/x", &v); err != nil || v.Hello != "world" {
		t.Fatalf("GetJSON() = %+v, %v", v, err)
	}
	r, err := c.Get(context.Background(), srv.URL+"/x", `"v1"`)
	if err != nil || !r.NotModified {
		t.Fatalf("Get with ETag = %+v, %v", r, err)
	}
}

func TestRetriesTemporaryFailures(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if calls.Add(1) == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()
	var v struct{}
	if err := NewForTest(srv.URL).GetJSON(context.Background(), srv.URL, &v); err != nil || calls.Load() != 2 {
		t.Fatalf("GetJSON() = %v after %d calls", err, calls.Load())
	}
}

func TestNotFoundAndBadJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/missing" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(`not json`))
	}))
	defer srv.Close()
	c := NewForTest(srv.URL)
	var v struct{}
	if err := c.GetJSON(context.Background(), srv.URL+"/missing", &v); !errors.Is(err, ErrNotFound) {
		t.Fatalf("404: %v", err)
	}
	if err := c.GetJSON(context.Background(), srv.URL+"/bad", &v); !apperr.Is(err, apperr.FeedsInvalidData) {
		t.Fatalf("bad JSON: %v", err)
	}
}

func TestGetStart(t *testing.T) {
	data := []byte(strings.Repeat("0123456789", 100)) // 1000 bytes
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/ignores-range" {
			_, _ = w.Write(data)
			return
		}
		http.ServeContent(w, r, "log.json", time.Time{}, bytes.NewReader(data)) // answers ranges with 206
	}))
	defer srv.Close()
	c := NewForTest(srv.URL)
	ctx := context.Background()

	for _, tc := range []struct {
		path    string
		n       int64
		want    int
		partial bool
	}{
		{"/log.json", 64, 64, true},
		{"/log.json", 1000, 1000, false},
		{"/log.json", 5000, 1000, false}, // more than the file
		{"/ignores-range", 64, 1000, false},
	} {
		r, err := c.GetStart(ctx, srv.URL+tc.path, tc.n)
		if err != nil || len(r.Body) != tc.want || r.Partial != tc.partial || !bytes.Equal(r.Body, data[:tc.want]) {
			t.Errorf("GetStart(%s, %d) = %d bytes, partial %v, %v; want %d bytes, partial %v", tc.path, tc.n, len(r.Body), r.Partial, err, tc.want, tc.partial)
		}
	}
}

func TestContentRange(t *testing.T) {
	for h, want := range map[string]bool{
		"bytes 0-65535/37299812": true,
		"bytes 0-999/1000":       true,
		"bytes 10-99/1000":       false, // not from the start
		"bytes 0-999/999":        false,
		"bytes 0-99/*":           false,
		"":                       false,
	} {
		if _, _, ok := contentRange(h); ok != want {
			t.Errorf("contentRange(%q) ok = %v, want %v", h, ok, want)
		}
	}
}
