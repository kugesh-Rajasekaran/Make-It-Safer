// Package feeds is the HTTP client every data source uses. It only talks
// HTTPS to the hosts in docs/design.md §4.9, bounds response sizes and
// retries briefly on temporary failures.
package feeds

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/kugesh-rajasekaran/make-it-safer/internal/apperr"
)

// AllowedHosts is the network allowlist (docs/design.md §4.9).
var AllowedHosts = []string{
	"api.osv.dev",
	"osv-vulnerabilities.storage.googleapis.com",
	"raw.githubusercontent.com",
	"www.cisa.gov",
	"api.first.org",
	"endoflife.date",
}

const (
	maxResponse = 64 << 20 // some kernel advisories are several MB
	timeout     = 60 * time.Second
	attempts    = 3
)

// Client is an HTTPS client restricted to the allowlist.
type Client struct {
	hc        *http.Client
	hosts     map[string]bool
	allowHTTP bool
	userAgent string
}

// New returns a client for the real data sources.
func New(version string) *Client {
	hosts := map[string]bool{}
	for _, h := range AllowedHosts {
		hosts[h] = true
	}
	return &Client{
		hc:        &http.Client{Timeout: timeout},
		hosts:     hosts,
		userAgent: "make-it-safer/" + version,
	}
}

// NewForTest returns a client that may only reach the given test server.
func NewForTest(serverURL string) *Client {
	u, err := url.Parse(serverURL)
	if err != nil {
		panic(err) // test setup error
	}
	return &Client{hc: &http.Client{Timeout: 10 * time.Second}, hosts: map[string]bool{u.Host: true}, allowHTTP: true, userAgent: "make-it-safer/test"}
}

// Response is a successful answer.
type Response struct {
	Body        []byte
	ETag        string
	NotModified bool
}

// Get fetches rawURL. With an etag it may answer NotModified.
func (c *Client) Get(ctx context.Context, rawURL, etag string) (*Response, error) {
	return c.do(ctx, http.MethodGet, rawURL, nil, etag)
}

// Head returns the ETag of rawURL without downloading it.
func (c *Client) Head(ctx context.Context, rawURL string) (string, error) {
	r, err := c.do(ctx, http.MethodHead, rawURL, nil, "")
	if err != nil {
		return "", err
	}
	return r.ETag, nil
}

// GetJSON fetches rawURL and decodes the JSON answer into v.
func (c *Client) GetJSON(ctx context.Context, rawURL string, v any) error {
	r, err := c.do(ctx, http.MethodGet, rawURL, nil, "")
	if err != nil {
		return err
	}
	return decode(rawURL, r.Body, v)
}

// PostJSON sends body as JSON and decodes the JSON answer into v.
func (c *Client) PostJSON(ctx context.Context, rawURL string, body, v any) error {
	data, err := json.Marshal(body)
	if err != nil {
		return apperr.Wrap(apperr.FeedsRequestFailed, err, "cannot encode request")
	}
	r, err := c.do(ctx, http.MethodPost, rawURL, data, "")
	if err != nil {
		return err
	}
	return decode(rawURL, r.Body, v)
}

// ErrNotFound is returned (wrapped) for HTTP 404.
var ErrNotFound = errors.New("not found")

func (c *Client) do(ctx context.Context, method, rawURL string, body []byte, etag string) (*Response, error) {
	u, err := url.Parse(rawURL)
	if err != nil || !c.hosts[u.Host] || (u.Scheme != "https" && !c.allowHTTP) {
		return nil, apperr.New(apperr.FeedsHostNotAllowed, "refusing to contact "+rawURL+": not on the allowlist (docs/design.md §4.9)")
	}
	var lastErr error
	for attempt := range attempts {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return nil, apperr.Wrap(apperr.FeedsRequestFailed, ctx.Err(), "request to "+u.Host+" cancelled")
			case <-time.After(time.Duration(attempt) * 2 * time.Second):
			}
		}
		resp, retry, err := c.once(ctx, method, u.String(), body, etag)
		if err == nil {
			return resp, nil
		}
		lastErr = err
		if !retry {
			break
		}
	}
	return nil, lastErr
}

func (c *Client) once(ctx context.Context, method, rawURL string, body []byte, etag string) (*Response, bool, error) {
	req, err := http.NewRequestWithContext(ctx, method, rawURL, bytes.NewReader(body))
	if err != nil {
		return nil, false, apperr.Wrap(apperr.FeedsRequestFailed, err, "invalid request")
	}
	req.Header.Set("User-Agent", c.userAgent)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, true, apperr.Wrap(apperr.FeedsUnavailable, err, "cannot reach "+req.URL.Host)
	}
	defer func() { _ = resp.Body.Close() }()

	switch {
	case resp.StatusCode == http.StatusNotModified:
		return &Response{ETag: etag, NotModified: true}, false, nil
	case resp.StatusCode == http.StatusNotFound:
		return nil, false, apperr.Wrap(apperr.FeedsRequestFailed, ErrNotFound, req.URL.Host+" has no "+req.URL.Path)
	case resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500:
		return nil, true, apperr.New(apperr.FeedsUnavailable, fmt.Sprintf("%s answered %s", req.URL.Host, resp.Status))
	case resp.StatusCode != http.StatusOK:
		return nil, false, apperr.New(apperr.FeedsRequestFailed, fmt.Sprintf("%s answered %s", req.URL.Host, resp.Status))
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse+1))
	if err != nil {
		return nil, true, apperr.Wrap(apperr.FeedsUnavailable, err, "reading from "+req.URL.Host+" failed")
	}
	if len(data) > maxResponse {
		return nil, false, apperr.New(apperr.FeedsRequestFailed, req.URL.Host+" sent a response larger than allowed")
	}
	return &Response{Body: data, ETag: resp.Header.Get("ETag")}, false, nil
}

func decode(rawURL string, data []byte, v any) error {
	if err := json.Unmarshal(data, v); err != nil {
		return apperr.Wrap(apperr.FeedsInvalidData, err, "unexpected data from "+rawURL)
	}
	return nil
}
