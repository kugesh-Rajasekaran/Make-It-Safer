package eol

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/kugesh-rajasekaran/make-it-safer/internal/apperr"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/feeds"
)

func TestCycles(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`[{"cycle":"24.04","eol":"2029-04-25","lts":true},{"cycle":"22.04","eol":"2027-04-01","extendedSupport":"2032-04-01"},{"cycle":"15","eol":false}]`))
	}))
	defer srv.Close()
	c := &Client{Feeds: feeds.NewForTest(srv.URL), API: srv.URL}
	cycles, err := c.Cycles(context.Background(), "ubuntu")
	if err != nil || len(cycles) != 3 {
		t.Fatalf("Cycles() = %+v, %v", cycles, err)
	}
	now := time.Date(2026, 11, 8, 0, 0, 0, 0, time.UTC)
	for release, want := range map[string]Status{"24.04": Supported, "22.04": Supported, "15": Supported, "20.04": Unknown} {
		if got, _ := StatusOf(cycles, release, now); got != want {
			t.Errorf("StatusOf(%s) = %v, want %v", release, got, want)
		}
	}
}

// An empty answer is not "every release is supported": it must be an error,
// so the end-of-life findings stay as they are.
func TestEmptyAnswerIsAnError(t *testing.T) {
	for _, body := range []string{`[]`, `null`} {
		t.Run(body, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(body)) }))
			defer srv.Close()
			c := &Client{Feeds: feeds.NewForTest(srv.URL), API: srv.URL}
			if cycles, err := c.Cycles(context.Background(), "macos"); !apperr.Is(err, apperr.FeedsInvalidData) {
				t.Fatalf("Cycles() = %v, %v; want %s", cycles, err, apperr.FeedsInvalidData)
			}
		})
	}
}
