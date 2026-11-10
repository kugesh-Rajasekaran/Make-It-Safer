// Package cvelist reads CVE records from the official CVE List (mirrored on
// GitHub by the CVE Program). It provides severity scores and, for early
// warnings, newly published CVEs.
package cvelist

import (
	"context"
	"encoding/json"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/kugesh-rajasekaran/make-it-safer/internal/apperr"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/config"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/feeds"
)

// DefaultBase is the CVE Program's CVE List repository.
const DefaultBase = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main"

// refreshAfter is how long a cached record is trusted (scores get added later).
const refreshAfter = 7 * 24 * time.Hour

// recordFormat 2 added Vector and Weakness.
const recordFormat = 2

var idPattern = regexp.MustCompile(`^CVE-([0-9]{4})-([0-9]{4,})$`)

// Record is the part of a CVE record Make-It-Safer uses. Its text is data
// from outside: display it, never run or interpret it.
type Record struct {
	ID          string    `json:"id"`
	Title       string    `json:"title,omitempty"`
	Description string    `json:"description,omitempty"` // shortened
	Score       float64   `json:"score"`                 // highest CVSS base score from the CNA or CISA (0 = none)
	Vector      string    `json:"vector,omitempty"`      // the CVSS vector of that score, e.g. CVSS:3.1/AV:N/…
	Weakness    string    `json:"weakness,omitempty"`    // the first CWE, e.g. "CWE-364: Signal Handler Race Condition"
	Format      int       `json:"format,omitempty"`      // recordFormat; older cached records are read again
	KEV         bool      `json:"kev,omitempty"`         // CISA marked it actively exploited
	Products    []Product `json:"products,omitempty"`    // from the CNA and CISA (ADP)
	Rejected    bool      `json:"rejected,omitempty"`
	Published   time.Time `json:"published"`
	Fetched     time.Time `json:"fetched"`
}

// Product is an affected vendor/product pair.
type Product struct {
	Vendor        string `json:"vendor,omitempty"`
	Product       string `json:"product,omitempty"`
	Package       string `json:"package,omitempty"`
	CollectionURL string `json:"collection_url,omitempty"` // where Package lives, e.g. a registry
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
func (c *Client) Get(ctx context.Context, id string) (*Record, error) { return c.get(ctx, id, false) }

// Fetch returns the current CVE record, skipping the cache (e.g. after the
// CVE List said it changed).
func (c *Client) Fetch(ctx context.Context, id string) (*Record, error) { return c.get(ctx, id, true) }

func (c *Client) get(ctx context.Context, id string, fresh bool) (*Record, error) {
	m := idPattern.FindStringSubmatch(id)
	if m == nil {
		return nil, apperr.New(apperr.CVEInvalidID, "not a CVE id: "+strconv.Quote(id))
	}
	path := filepath.Join(c.Cache, id+".json")
	var older *Record                                         // a recent copy in an older format: used if the CVE List can't be reached
	if data, err := os.ReadFile(path); err == nil && !fresh { //nolint:gosec // validated id inside our cache dir
		var r Record
		if json.Unmarshal(data, &r) == nil && c.Now().Sub(r.Fetched) < refreshAfter {
			if r.Format == recordFormat {
				return &r, nil
			}
			older = &r
		}
	}
	n, _ := strconv.Atoi(m[2])
	url := c.Base + "/cves/" + m[1] + "/" + strconv.Itoa(n/1000) + "xxx/" + id + ".json"
	resp, err := c.Feeds.Get(ctx, url, "")
	if err != nil {
		if older != nil {
			return older, nil
		}
		return nil, err
	}
	r, err := Parse(resp.Body, c.Now())
	if err != nil {
		return nil, err
	}
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

// Parse reads a CVE JSON 5 record.
func Parse(data []byte, now time.Time) (*Record, error) {
	var raw recordJSON
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, apperr.Wrap(apperr.FeedsInvalidData, err, "unexpected data in a CVE record")
	}
	if !idPattern.MatchString(raw.Metadata.ID) {
		return nil, apperr.New(apperr.FeedsInvalidData, "a CVE record without a valid CVE id")
	}
	return raw.compact(now), nil
}

// recordJSON is the CVE JSON 5 layout, reduced to what we read.
type recordJSON struct {
	Metadata struct {
		ID        string `json:"cveId"`
		State     string `json:"state"`
		Published string `json:"datePublished"`
	} `json:"cveMetadata"`
	Containers struct {
		CNA struct {
			Title        string         `json:"title"`
			Descriptions []description  `json:"descriptions"`
			Metrics      []metricSet    `json:"metrics"`
			Affected     []affectedJSON `json:"affected"`
			ProblemTypes []problemType  `json:"problemTypes"`
		} `json:"cna"`
		ADP []struct {
			Metrics      []metricSet    `json:"metrics"`
			Affected     []affectedJSON `json:"affected"`
			ProblemTypes []problemType  `json:"problemTypes"`
		} `json:"adp"`
	} `json:"containers"`
}

type description struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

type problemType struct {
	Descriptions []struct {
		CWE         string `json:"cweId"`
		Description string `json:"description"`
	} `json:"descriptions"`
}

type affectedJSON struct {
	Vendor        string `json:"vendor"`
	Product       string `json:"product"`
	PackageName   string `json:"packageName"`
	CollectionURL string `json:"collectionURL"`
}

type metricSet map[string]json.RawMessage

// Limits on what a record may contribute (they come from outside).
const (
	maxProducts    = 200
	maxText        = 300 // runes
	maxProductText = 200 // bytes per field
)

func (r recordJSON) compact(now time.Time) *Record {
	out := &Record{ID: r.Metadata.ID, Title: shorten(r.Containers.CNA.Title, maxText), Fetched: now, Rejected: r.Metadata.State == "REJECTED", Format: recordFormat}
	if t, err := time.Parse(time.RFC3339, strings.TrimSuffix(r.Metadata.Published, "Z")+"Z"); err == nil {
		out.Published = t
	}
	for _, d := range r.Containers.CNA.Descriptions {
		if out.Description == "" || strings.HasPrefix(d.Lang, "en") {
			out.Description = shorten(d.Value, maxText)
		}
		if strings.HasPrefix(d.Lang, "en") {
			break
		}
	}
	sets := r.Containers.CNA.Metrics
	affected := r.Containers.CNA.Affected
	problems := r.Containers.CNA.ProblemTypes
	for _, adp := range r.Containers.ADP {
		sets = append(sets, adp.Metrics...)
		affected = append(affected, adp.Affected...)
		problems = append(problems, adp.ProblemTypes...)
	}
	out.Score, out.Vector = maxScore(sets)
	out.KEV, out.Weakness = kevListed(sets), firstWeakness(problems)
	for _, a := range affected {
		p := Product{Vendor: a.Vendor, Product: a.Product, Package: a.PackageName, CollectionURL: a.CollectionURL}
		if len(p.Vendor) > maxProductText || len(p.Product) > maxProductText || len(p.Package) > maxProductText || len(p.CollectionURL) > maxProductText {
			continue
		}
		if len(out.Products) == maxProducts {
			break
		}
		if !slices.Contains(out.Products, p) {
			out.Products = append(out.Products, p)
		}
	}
	return out
}

// shorten collapses whitespace and cuts s to n runes.
func shorten(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	if r := []rune(s); len(r) > n {
		return string(r[:n-1]) + "…"
	}
	return s
}

// kevListed reports whether CISA added the CVE to its KEV catalog, which
// it notes in the record as {"other": {"type": "kev", …}}.
func kevListed(sets []metricSet) bool {
	for _, set := range sets {
		var other struct {
			Type string `json:"type"`
		}
		if raw, ok := set["other"]; ok && json.Unmarshal(raw, &other) == nil && other.Type == "kev" {
			return true
		}
	}
	return false
}

var (
	vectorPattern = regexp.MustCompile(`^CVSS:[0-9.]+(/[A-Za-z]+:[A-Za-z]+)+$`) // v4 has values like U:Amber
	cweInText     = regexp.MustCompile(`CWE-[0-9]+`)
	emptyBrackets = regexp.MustCompile(`\(\s*[|,\s]*\)`) // "(CWE-787|CWE-125)" once the ids are gone
	cwePattern    = regexp.MustCompile(`^CWE-[0-9]{1,6}$`)
)

// maxScore returns the highest CVSS base score (v4.0, v3.1, v3.0) found,
// with its vector ("" if the vector looks wrong). Ties keep the first, in a
// fixed order, so the result doesn't change between runs.
func maxScore(sets []metricSet) (float64, string) {
	best, vector := 0.0, ""
	for _, set := range sets {
		for _, key := range slices.Sorted(maps.Keys(set)) {
			if !strings.HasPrefix(key, "cvssV4") && !strings.HasPrefix(key, "cvssV3") {
				continue
			}
			var m struct {
				BaseScore float64 `json:"baseScore"`
				Vector    string  `json:"vectorString"`
			}
			if json.Unmarshal(set[key], &m) == nil && m.BaseScore > best && m.BaseScore <= 10 {
				best, vector = m.BaseScore, ""
				if len(m.Vector) <= 200 && vectorPattern.MatchString(m.Vector) {
					vector = m.Vector
				}
			}
		}
	}
	return best, vector
}

// firstWeakness returns the first CWE named in the record, with its name.
func firstWeakness(problems []problemType) string {
	for _, p := range problems {
		for _, d := range p.Descriptions {
			if !cwePattern.MatchString(d.CWE) {
				continue
			}
			// Some records repeat CWE ids in the name ("CWE-190: Integer
			// Overflow CWE-190", "(CWE-787|CWE-125)", "->CWE-281"): keep words only.
			name := strings.ReplaceAll(cweInText.ReplaceAllString(d.Description, " "), "->", " ")
			name = emptyBrackets.ReplaceAllString(name, " ")
			name = strings.Trim(strings.Join(strings.Fields(name), " "), " :|")
			if !strings.ContainsFunc(name, unicode.IsLetter) {
				return d.CWE
			}
			return shorten(d.CWE+": "+name, 120)
		}
	}
	return ""
}
