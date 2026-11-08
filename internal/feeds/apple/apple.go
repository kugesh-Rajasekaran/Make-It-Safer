// Package apple reads Apple's security notes: the list of security releases
// (support.apple.com/en-us/100100) and, for each release, the CVEs it fixes.
// Apple publishes no machine-readable feed, so this parses HTML. The parsers
// are strict and tested against saved pages: a change to Apple's markup
// shows up as missing data, never as made-up findings. ADR 0003.
package apple

import (
	"context"
	"encoding/json"
	"errors"
	"html"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/kugesh-rajasekaran/make-it-safer/internal/apperr"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/config"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/feeds"
)

// IndexURL lists Apple's recent security releases.
const IndexURL = "https://support.apple.com/en-us/100100"

// Products this package understands.
const (
	MacOS  = "macOS"
	Safari = "Safari"
)

// Release is one Apple security release for a Mac.
type Release struct {
	Name    string `json:"name"`    // e.g. "macOS Sequoia 15.8.2", "Safari 27.2"
	Product string `json:"product"` // MacOS or Safari
	Version string `json:"version"` // e.g. "15.8.2"
	URL     string `json:"url"`     // its security note
}

// Client reads the notes through the allowlisted feeds client and caches
// them under Cache. Release notes are re-read after a week (Apple sometimes
// adds CVEs later), with ETags so unchanged pages aren't downloaded again.
type Client struct {
	Feeds    *feeds.Client
	IndexURL string
	Base     string // tests: replaces https://support.apple.com in release links
	Cache    string
	Now      func() time.Time
}

// New returns a client for the real notes.
func New(fc *feeds.Client, paths config.Paths) *Client {
	return &Client{Feeds: fc, IndexURL: IndexURL, Cache: filepath.Join(paths.Cache, "apple"), Now: time.Now}
}

// cached is one page's parsed content.
type cached struct {
	Fetched  time.Time `json:"fetched"`
	ETag     string    `json:"etag,omitempty"`
	Releases []Release `json:"releases,omitempty"` // the index
	CVEs     []string  `json:"cves,omitempty"`     // a release note
}

const (
	indexMaxAge = 6 * time.Hour
	noteMaxAge  = 7 * 24 * time.Hour
)

// Releases lists the macOS and Safari security releases.
func (c *Client) Releases(ctx context.Context) ([]Release, error) {
	page, err := c.page(ctx, c.IndexURL, "index", indexMaxAge, func(body []byte) (cached, error) {
		rs := ParseIndex(body)
		if len(rs) == 0 {
			return cached{}, apperr.New(apperr.FeedsInvalidData, "Apple's security releases page had no macOS or Safari releases; its layout may have changed")
		}
		return cached{Releases: rs}, nil
	})
	return page.Releases, err
}

// CVEs lists the CVEs a release fixes.
func (c *Client) CVEs(ctx context.Context, r Release) ([]string, error) {
	url := r.URL
	if c.Base != "" {
		url = strings.Replace(url, "https://support.apple.com", c.Base, 1)
	}
	page, err := c.page(ctx, url, "note-"+noteID(r.URL), noteMaxAge, func(body []byte) (cached, error) {
		return cached{CVEs: ParseCVEs(body)}, nil
	})
	return page.CVEs, err
}

// page returns a cached page, fetching it again when it's older than maxAge.
// If the fetch fails, a stale copy is still used.
func (c *Client) page(ctx context.Context, url, name string, maxAge time.Duration, parse func([]byte) (cached, error)) (cached, error) {
	file := filepath.Join(c.Cache, name+".json")
	var old cached
	data, err := os.ReadFile(file) //nolint:gosec // our own cache directory
	haveOld := err == nil && json.Unmarshal(data, &old) == nil
	if haveOld && c.Now().Sub(old.Fetched) < maxAge {
		return old, nil
	}
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return cached{}, apperr.Wrap(apperr.ConfigUnreadable, err, "cannot read "+file)
	}
	resp, ferr := c.Feeds.Get(ctx, url, old.ETag)
	switch {
	case ferr != nil && haveOld:
		return old, nil // keep using the last good copy
	case ferr != nil:
		return cached{}, ferr
	case resp.NotModified:
		old.Fetched = c.Now()
		return old, c.save(file, old)
	}
	fresh, err := parse(resp.Body)
	if err != nil {
		if haveOld {
			return old, nil
		}
		return cached{}, err
	}
	fresh.Fetched, fresh.ETag = c.Now(), resp.ETag
	return fresh, c.save(file, fresh)
}

func (c *Client) save(file string, p cached) error {
	if err := os.MkdirAll(c.Cache, 0o700); err != nil {
		return apperr.Wrap(apperr.ConfigWriteFailed, err, "cannot create "+c.Cache)
	}
	data, err := json.Marshal(p)
	if err != nil {
		return apperr.Wrap(apperr.ConfigWriteFailed, err, "cannot encode "+file)
	}
	return config.WriteFileAtomic(file, data)
}

var (
	rowPattern     = regexp.MustCompile(`(?s)<tr>(.*?)</tr>`)
	cellPattern    = regexp.MustCompile(`(?s)<td[^>]*>(.*?)</td>`)
	linkPattern    = regexp.MustCompile(`href="(https://support\.apple\.com/[a-z]{2}-[a-z]{2}/[0-9]+)"`)
	tagPattern     = regexp.MustCompile(`<[^>]+>`)
	versionPattern = regexp.MustCompile(`^[0-9]+(\.[0-9]+){0,3}$`)
	cvePattern     = regexp.MustCompile(`CVE-[0-9]{4}-[0-9]{4,7}`)
	noteIDPattern  = regexp.MustCompile(`[0-9]+$`)
)

// ParseIndex reads the macOS and Safari releases from the security releases
// page. Rows without a security note ("no published CVE entries") are skipped.
func ParseIndex(page []byte) []Release {
	var out []Release
	for _, row := range rowPattern.FindAllSubmatch(page, -1) {
		cells := cellPattern.FindAllSubmatch(row[1], -1)
		if len(cells) < 2 {
			continue
		}
		link := linkPattern.FindSubmatch(cells[0][1])
		if link == nil {
			continue
		}
		name := strings.Join(strings.Fields(html.UnescapeString(tagPattern.ReplaceAllString(string(cells[0][1]), " "))), " ")
		if r, ok := parseName(name); ok {
			r.URL = string(link[1])
			out = append(out, r)
		}
	}
	return out
}

// parseName understands "macOS Sequoia 15.8.2", "macOS 27.2" and "Safari 27.2".
func parseName(name string) (Release, bool) {
	fields := strings.Fields(name)
	if len(fields) < 2 || !versionPattern.MatchString(fields[len(fields)-1]) {
		return Release{}, false
	}
	r := Release{Name: name, Version: fields[len(fields)-1]}
	switch {
	case fields[0] == "Safari" && len(fields) == 2:
		r.Product = Safari
	case fields[0] == "macOS" && len(fields) <= 3:
		r.Product = MacOS
	default:
		return Release{}, false
	}
	return r, true
}

// ParseCVEs lists the CVE IDs in a release note, each once, sorted.
func ParseCVEs(page []byte) []string {
	seen := map[string]bool{}
	var out []string
	for _, m := range cvePattern.FindAll(page, -1) {
		if id := string(m); !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	slices.Sort(out)
	return out
}

func noteID(url string) string { return noteIDPattern.FindString(url) }

// CompareVersions compares dotted versions like "15.7.7" and "15.8":
// -1, 0 or +1. Missing parts count as 0.
func CompareVersions(a, b string) int {
	as, bs := strings.Split(a, "."), strings.Split(b, ".")
	for i := range max(len(as), len(bs)) {
		var x, y int
		if i < len(as) {
			x, _ = strconv.Atoi(as[i])
		}
		if i < len(bs) {
			y, _ = strconv.Atoi(bs[i])
		}
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	return 0
}

// Major returns a version's first part, e.g. "15" for "15.7.7".
func Major(v string) string {
	major, _, _ := strings.Cut(v, ".")
	return major
}
