// Package kev reads CISA's Known Exploited Vulnerabilities catalog: CVEs
// that attackers are using right now.
package kev

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/kugesh-rajasekaran/make-it-safer/internal/apperr"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/config"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/feeds"
)

// Default sources: CISA, with CISA's GitHub mirror as a fallback.
const (
	DefaultURL    = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
	DefaultMirror = "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json"
)

// Entry is one exploited vulnerability.
type Entry struct {
	CVE        string `json:"cveID"`
	Name       string `json:"vulnerabilityName"`
	DateAdded  string `json:"dateAdded"`
	Ransomware string `json:"knownRansomwareCampaignUse"`
}

// Catalog maps CVE IDs to entries.
type Catalog struct {
	Version string
	Entries map[string]Entry
}

// Has reports whether a CVE is actively exploited.
func (c *Catalog) Has(cve string) bool {
	if c == nil {
		return false
	}
	_, ok := c.Entries[cve]
	return ok
}

// Client downloads the catalog, keeping a copy on disk.
type Client struct {
	Feeds  *feeds.Client
	URLs   []string
	Cache  string // catalog copy
	ETag   string // its ETag file
	loaded *Catalog
}

// New returns a client for CISA's catalog caching under paths.Cache.
func New(fc *feeds.Client, paths config.Paths) *Client {
	return &Client{
		Feeds: fc, URLs: []string{DefaultURL, DefaultMirror},
		Cache: filepath.Join(paths.Cache, "kev.json"), ETag: filepath.Join(paths.Cache, "kev.etag"),
	}
}

// Refresh downloads the catalog when it changed and returns it. If no
// source answers, the last saved copy is used.
func (c *Client) Refresh(ctx context.Context) (*Catalog, error) {
	etag := ""
	if b, err := os.ReadFile(c.ETag); err == nil {
		etag = string(b)
	}
	var lastErr error
	for _, u := range c.URLs {
		resp, err := c.Feeds.Get(ctx, u, etag)
		if err != nil {
			lastErr = err
			etag = "" // the mirror has its own ETags
			continue
		}
		if !resp.NotModified {
			if _, err := parse(resp.Body); err != nil {
				lastErr = err
				continue
			}
			if err := config.WriteFileAtomic(c.Cache, resp.Body); err != nil {
				return nil, err
			}
			_ = config.WriteFileAtomic(c.ETag, []byte(resp.ETag))
			c.loaded = nil
		}
		return c.Cached()
	}
	if cat, err := c.Cached(); err == nil {
		return cat, nil // offline: use the saved copy
	}
	return nil, lastErr
}

// Cached returns the saved catalog without going online.
func (c *Client) Cached() (*Catalog, error) {
	if c.loaded != nil {
		return c.loaded, nil
	}
	data, err := os.ReadFile(c.Cache)
	if err != nil {
		return nil, apperr.Wrap(apperr.FeedsUnavailable, err, "no copy of the CISA KEV catalog yet")
	}
	cat, err := parse(data)
	if err != nil {
		return nil, err
	}
	c.loaded = cat
	return cat, nil
}

func parse(data []byte) (*Catalog, error) {
	var raw struct {
		Version         string  `json:"catalogVersion"`
		Vulnerabilities []Entry `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(data, &raw); err != nil || len(raw.Vulnerabilities) == 0 {
		return nil, apperr.New(apperr.FeedsInvalidData, "the CISA KEV catalog is not in the expected format")
	}
	cat := &Catalog{Version: raw.Version, Entries: make(map[string]Entry, len(raw.Vulnerabilities))}
	for _, e := range raw.Vulnerabilities {
		cat.Entries[e.CVE] = e
	}
	return cat, nil
}
