// Package cvelist reads CVE records from the official CVE List (mirrored on
// GitHub by the CVE Program). It provides severity scores and, for early
// warnings, newly published CVEs.
package cvelist

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/kugesh-rajasekaran/make-it-safer/internal/apperr"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/config"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/feeds"
)

// DefaultBase is the CVE Program's CVE List repository.
const DefaultBase = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main"

// refreshAfter is how long a cached record is trusted (scores get added later).
const refreshAfter = 7 * 24 * time.Hour

var idPattern = regexp.MustCompile(`^CVE-([0-9]{4})-([0-9]{4,})$`)

// Record is the part of a CVE record Make-It-Safer uses.
type Record struct {
	ID        string    `json:"id"`
	Title     string    `json:"title,omitempty"`
	Score     float64   `json:"score"` // highest CVSS base score from the CNA or CISA (0 = none)
	Products  []Product `json:"products,omitempty"`
	Published time.Time `json:"published"`
	Fetched   time.Time `json:"fetched"`
}

// Product is an affected vendor/product pair.
type Product struct {
	Vendor  string `json:"vendor,omitempty"`
	Product string `json:"product,omitempty"`
	Package string `json:"package,omitempty"`
}

// Client reads CVE records and caches them on disk.
type Client struct {
	Feeds *feeds.Client
	Base  string
	Cache string
	Now   func() time.Time
}

// New returns a client for the CVE List caching under paths.Cache.
func New(fc *feeds.Client, paths config.Paths) *Client {
	return &Client{Feeds: fc, Base: DefaultBase, Cache: filepath.Join(paths.Cache, "cve"), Now: time.Now}
}

// Get returns a CVE record, from the cache when it's recent enough.
func (c *Client) Get(ctx context.Context, id string) (*Record, error) {
	m := idPattern.FindStringSubmatch(id)
	if m == nil {
		return nil, apperr.New(apperr.CVEInvalidID, "not a CVE id: "+strconv.Quote(id))
	}
	path := filepath.Join(c.Cache, id+".json")
	if data, err := os.ReadFile(path); err == nil { //nolint:gosec // validated id inside our cache dir
		var r Record
		if json.Unmarshal(data, &r) == nil && c.Now().Sub(r.Fetched) < refreshAfter {
			return &r, nil
		}
	}
	n, _ := strconv.Atoi(m[2])
	url := c.Base + "/cves/" + m[1] + "/" + strconv.Itoa(n/1000) + "xxx/" + id + ".json"
	var raw recordJSON
	if err := c.Feeds.GetJSON(ctx, url, &raw); err != nil {
		return nil, err
	}
	r := raw.compact(c.Now())
	if r.ID != id {
		return nil, apperr.New(apperr.FeedsInvalidData, "the CVE List returned a different record than requested")
	}
	if err := os.MkdirAll(c.Cache, 0o700); err == nil {
		if data, err := json.Marshal(r); err == nil {
			_ = config.WriteFileAtomic(path, data)
		}
	}
	return r, nil
}

// recordJSON is the CVE JSON 5 layout, reduced to what we read.
type recordJSON struct {
	Metadata struct {
		ID        string `json:"cveId"`
		Published string `json:"datePublished"`
	} `json:"cveMetadata"`
	Containers struct {
		CNA struct {
			Title    string      `json:"title"`
			Metrics  []metricSet `json:"metrics"`
			Affected []struct {
				Vendor      string `json:"vendor"`
				Product     string `json:"product"`
				PackageName string `json:"packageName"`
			} `json:"affected"`
		} `json:"cna"`
		ADP []struct {
			Metrics []metricSet `json:"metrics"`
		} `json:"adp"`
	} `json:"containers"`
}

type metricSet map[string]json.RawMessage

func (r recordJSON) compact(now time.Time) *Record {
	out := &Record{ID: r.Metadata.ID, Title: r.Containers.CNA.Title, Fetched: now}
	if t, err := time.Parse(time.RFC3339, strings.TrimSuffix(r.Metadata.Published, "Z")+"Z"); err == nil {
		out.Published = t
	}
	sets := r.Containers.CNA.Metrics
	for _, adp := range r.Containers.ADP {
		sets = append(sets, adp.Metrics...)
	}
	out.Score = maxScore(sets)
	for _, a := range r.Containers.CNA.Affected {
		out.Products = append(out.Products, Product{Vendor: a.Vendor, Product: a.Product, Package: a.PackageName})
	}
	return out
}

// maxScore returns the highest CVSS base score (v4.0, v3.1, v3.0) found.
func maxScore(sets []metricSet) float64 {
	best := 0.0
	for _, set := range sets {
		for key, raw := range set {
			if !strings.HasPrefix(key, "cvssV4") && !strings.HasPrefix(key, "cvssV3") {
				continue
			}
			var m struct {
				BaseScore float64 `json:"baseScore"`
			}
			if json.Unmarshal(raw, &m) == nil && m.BaseScore > best && m.BaseScore <= 10 {
				best = m.BaseScore
			}
		}
	}
	return best
}
