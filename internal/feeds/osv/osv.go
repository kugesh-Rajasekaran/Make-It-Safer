// Package osv talks to OSV.dev, which republishes Debian's and Ubuntu's own
// vulnerability data. OSV compares the distro package versions; this package
// asks the questions and reads the answers.
package osv

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/kugesh-rajasekaran/make-it-safer/internal/apperr"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/config"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/feeds"
)

// DefaultAPI is OSV's API.
const DefaultAPI = "https://api.osv.dev"

const batchSize = 1000 // OSV's limit per querybatch request

// Query asks whether one package version is vulnerable.
type Query struct {
	Ecosystem string
	Name      string
	Version   string
}

// Ref is a vulnerability OSV matched, with its last change time.
type Ref struct {
	ID       string    `json:"id"`
	Modified time.Time `json:"modified"`
}

// Vuln is the part of an OSV record Make-It-Safer uses. The long lists of
// affected versions are skipped on purpose: OSV already did the matching.
type Vuln struct {
	ID       string     `json:"id"`
	Modified time.Time  `json:"modified"`
	Aliases  []string   `json:"aliases,omitempty"`
	Upstream []string   `json:"upstream,omitempty"`
	Summary  string     `json:"summary,omitempty"`
	Details  string     `json:"details,omitempty"`
	Severity []Severity `json:"severity,omitempty"`
	Affected []Affected `json:"affected"`
}

// Severity is a scoring entry (CVSS vectors, Ubuntu priority words).
type Severity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

// Affected lists the vulnerable versions of one package in one ecosystem.
type Affected struct {
	Package struct {
		Name      string `json:"name"`
		Ecosystem string `json:"ecosystem"`
	} `json:"package"`
	Ranges            []Range `json:"ranges,omitempty"`
	EcosystemSpecific struct {
		Availability string `json:"availability,omitempty"` // Ubuntu: whether the fix needs Ubuntu Pro
		Urgency      string `json:"urgency,omitempty"`      // Debian's urgency
	} `json:"ecosystem_specific"`
}

// Range is a list of version events.
type Range struct {
	Type   string  `json:"type"`
	Events []Event `json:"events"`
}

// Event marks where a vulnerable range starts or ends.
type Event struct {
	Introduced string `json:"introduced,omitempty"`
	Fixed      string `json:"fixed,omitempty"`
}

// CVE returns the CVE this record is about, or "".
func (v *Vuln) CVE() string {
	for _, id := range slices.Concat(v.Upstream, v.Aliases) {
		if strings.HasPrefix(id, "CVE-") {
			return id
		}
	}
	if i := strings.Index(v.ID, "CVE-"); i >= 0 {
		return v.ID[i:]
	}
	return ""
}

// Fix returns the first fixed version after installed for a package, and
// whether that fix needs an Ubuntu Pro subscription. fixed is "" when the
// distro has no fix yet.
func (v *Vuln) Fix(ecosystem, pkg, installed string) (fixed string, proOnly bool) {
	for _, a := range v.Affected {
		if a.Package.Ecosystem != ecosystem || a.Package.Name != pkg {
			continue
		}
		for _, r := range a.Ranges {
			for _, e := range r.Events {
				if e.Fixed == "" || CompareVersions(e.Fixed, installed) <= 0 {
					continue
				}
				if fixed == "" || CompareVersions(e.Fixed, fixed) < 0 {
					fixed = e.Fixed
				}
			}
		}
		proOnly = strings.HasPrefix(a.EcosystemSpecific.Availability, "Available with Ubuntu Pro") ||
			strings.HasPrefix(ecosystem, "Ubuntu:Pro:")
	}
	return fixed, proOnly && fixed != ""
}

// DistroPriority returns the distro's own rating (Ubuntu priority or Debian
// urgency), lowercased, or "".
func (v *Vuln) DistroPriority(ecosystem, pkg string) string {
	for _, s := range v.Severity {
		if s.Type == "Ubuntu" {
			return strings.ToLower(s.Score)
		}
	}
	for _, a := range v.Affected {
		if a.Package.Ecosystem == ecosystem && a.Package.Name == pkg {
			return strings.ToLower(a.EcosystemSpecific.Urgency)
		}
	}
	return ""
}

// Client queries OSV and caches records on disk.
type Client struct {
	Feeds *feeds.Client
	API   string
	Cache string // directory for cached records
}

// New returns a client for OSV.dev that caches under paths.Cache.
func New(fc *feeds.Client, paths config.Paths) *Client {
	return &Client{Feeds: fc, API: DefaultAPI, Cache: filepath.Join(paths.Cache, "osv")}
}

type batchRequest struct {
	Queries []batchQuery `json:"queries"`
}

type batchQuery struct {
	Package   batchPackage `json:"package"`
	Version   string       `json:"version"`
	PageToken string       `json:"page_token,omitempty"`
}

type batchPackage struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

type batchResponse struct {
	Results []struct {
		Vulns         []Ref  `json:"vulns"`
		NextPageToken string `json:"next_page_token"`
	} `json:"results"`
}

// QueryBatch returns, for each query, the vulnerabilities OSV matched.
func (c *Client) QueryBatch(ctx context.Context, queries []Query) ([][]Ref, error) {
	out := make([][]Ref, len(queries))
	for start := 0; start < len(queries); start += batchSize {
		end := min(start+batchSize, len(queries))
		pending := map[int]string{} // query index → page token
		for i := start; i < end; i++ {
			pending[i] = ""
		}
		for len(pending) > 0 {
			idx := make([]int, 0, len(pending))
			for i := range pending {
				idx = append(idx, i)
			}
			slices.Sort(idx)
			req := batchRequest{}
			for _, i := range idx {
				q := queries[i]
				req.Queries = append(req.Queries, batchQuery{Package: batchPackage{Name: q.Name, Ecosystem: q.Ecosystem}, Version: q.Version, PageToken: pending[i]})
			}
			var resp batchResponse
			if err := c.Feeds.PostJSON(ctx, c.API+"/v1/querybatch", req, &resp); err != nil {
				return nil, apperr.Wrap(apperr.OSVQueryFailed, err, "OSV.dev query failed")
			}
			if len(resp.Results) != len(idx) {
				return nil, apperr.New(apperr.OSVQueryFailed, fmt.Sprintf("OSV.dev returned %d results for %d queries", len(resp.Results), len(idx)))
			}
			for n, i := range idx {
				out[i] = append(out[i], resp.Results[n].Vulns...)
				if t := resp.Results[n].NextPageToken; t != "" {
					pending[i] = t
				} else {
					delete(pending, i)
				}
			}
		}
	}
	return out, nil
}

var idPattern = regexp.MustCompile(`^[A-Z][A-Z0-9]*-[A-Za-z0-9._-]{1,100}$`)

// Vuln returns a record, from the cache when it's as new as ref.
func (c *Client) Vuln(ctx context.Context, ref Ref) (*Vuln, error) {
	if !idPattern.MatchString(ref.ID) {
		return nil, apperr.New(apperr.FeedsInvalidData, "unexpected vulnerability id from OSV.dev")
	}
	path := filepath.Join(c.Cache, ref.ID+".json")
	if v, err := readCached(path); err == nil && !v.Modified.Before(ref.Modified) {
		return v, nil
	}
	var v Vuln
	if err := c.Feeds.GetJSON(ctx, c.API+"/v1/vulns/"+url.PathEscape(ref.ID), &v); err != nil {
		return nil, apperr.Wrap(apperr.OSVQueryFailed, err, "cannot read "+ref.ID+" from OSV.dev")
	}
	if v.ID != ref.ID {
		return nil, apperr.New(apperr.FeedsInvalidData, "OSV.dev returned a different record than requested")
	}
	if err := os.MkdirAll(c.Cache, 0o700); err == nil {
		if data, err := json.Marshal(&v); err == nil {
			_ = config.WriteFileAtomic(path, data) // a cache miss next time is fine
		}
	}
	return &v, nil
}

func readCached(path string) (*Vuln, error) {
	data, err := os.ReadFile(path) //nolint:gosec // path is our cache dir + a validated id
	if err != nil {
		return nil, err
	}
	var v Vuln
	if err := json.Unmarshal(data, &v); err != nil {
		return nil, err
	}
	return &v, nil
}

// Ecosystems returns the OSV ecosystems to query for a server's OS. LTS
// releases of Ubuntu also get their Ubuntu Pro ecosystem, where extended
// security fixes are published.
func Ecosystems(osID, version string) []string {
	switch osID {
	case "debian":
		major, _, _ := strings.Cut(version, ".")
		return []string{"Debian:" + major}
	case "ubuntu":
		if isLTS(version) {
			return []string{"Ubuntu:" + version + ":LTS", "Ubuntu:Pro:" + version + ":LTS"}
		}
		return []string{"Ubuntu:" + version}
	}
	return nil
}

// isLTS: Ubuntu LTS releases are YY.04 with an even year.
func isLTS(version string) bool {
	year, month, ok := strings.Cut(version, ".")
	return ok && month == "04" && len(year) == 2 && (year[1]-'0')%2 == 0
}

// Relevant reports whether a matched record is a per-CVE distro record.
// Advisory records (DSA, DLA, USN) repeat the same CVEs, so they're skipped.
func Relevant(id string) bool {
	return strings.HasPrefix(id, "UBUNTU-CVE-") || strings.HasPrefix(id, "DEBIAN-CVE-")
}
