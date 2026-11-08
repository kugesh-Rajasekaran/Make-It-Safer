// Package epss reads EPSS scores from FIRST: the probability that a CVE is
// exploited in the next 30 days.
package epss

import (
	"context"
	"net/url"
	"strconv"
	"strings"

	"github.com/kugesh-rajasekaran/make-it-safer/internal/feeds"
)

// DefaultAPI is FIRST's EPSS API.
const DefaultAPI = "https://api.first.org/data/v1/epss"

const batch = 100 // CVEs per request, keeping URLs short

// Client fetches EPSS scores.
type Client struct {
	Feeds *feeds.Client
	API   string
}

// New returns a client for FIRST's API.
func New(fc *feeds.Client) *Client { return &Client{Feeds: fc, API: DefaultAPI} }

// Scores returns the EPSS score (0–1) of each CVE that has one.
func (c *Client) Scores(ctx context.Context, cves []string) (map[string]float64, error) {
	out := map[string]float64{}
	for start := 0; start < len(cves); start += batch {
		chunk := cves[start:min(start+batch, len(cves))]
		var resp struct {
			Data []struct {
				CVE  string `json:"cve"`
				EPSS string `json:"epss"`
			} `json:"data"`
		}
		u := c.API + "?cve=" + url.QueryEscape(strings.Join(chunk, ","))
		if err := c.Feeds.GetJSON(ctx, u, &resp); err != nil {
			return out, err
		}
		for _, d := range resp.Data {
			if v, err := strconv.ParseFloat(d.EPSS, 64); err == nil && v >= 0 && v <= 1 {
				out[d.CVE] = v
			}
		}
	}
	return out, nil
}
