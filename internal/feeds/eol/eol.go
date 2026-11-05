// Package eol reads OS support dates from endoflife.date, so a release that
// no longer gets security fixes is flagged even though it shows no new
// vulnerabilities.
package eol

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/kugesh-rajasekaran/make-it-safer/internal/feeds"
)

// DefaultAPI is endoflife.date's API.
const DefaultAPI = "https://endoflife.date/api"

// Cycle is one release and its support dates. Zero dates mean unknown.
type Cycle struct {
	Cycle           string
	SecurityEnds    time.Time // end of standard security support
	ExtendedEnds    time.Time // end of Ubuntu ESM / Debian LTS, if any
	StillSupported  bool      // endoflife.date says "false" (no end date yet)
	LongTermSupport bool
}

// Status describes where a release stands today.
type Status int

// Release support states.
const (
	Supported    Status = iota
	ExtendedOnly        // standard support ended; Ubuntu Pro / Debian LTS still fix things
	Unsupported         // no more security fixes at all
	Unknown             // release not listed
)

// Client fetches support dates.
type Client struct {
	Feeds *feeds.Client
	API   string
}

// New returns a client for endoflife.date.
func New(fc *feeds.Client) *Client { return &Client{Feeds: fc, API: DefaultAPI} }

// Cycles returns the releases of a product ("ubuntu" or "debian").
func (c *Client) Cycles(ctx context.Context, product string) ([]Cycle, error) {
	var raw []struct {
		Cycle    string          `json:"cycle"`
		EOL      json.RawMessage `json:"eol"`
		Extended json.RawMessage `json:"extendedSupport"`
		LTS      json.RawMessage `json:"lts"`
	}
	if err := c.Feeds.GetJSON(ctx, fmt.Sprintf("%s/%s.json", c.API, product), &raw); err != nil {
		return nil, err
	}
	out := make([]Cycle, 0, len(raw))
	for _, r := range raw {
		eolDate, eolBool := dateOrBool(r.EOL)
		ext, _ := dateOrBool(r.Extended)
		_, lts := dateOrBool(r.LTS)
		out = append(out, Cycle{
			Cycle: r.Cycle, SecurityEnds: eolDate, ExtendedEnds: ext,
			StillSupported: eolDate.IsZero() && !eolBool, LongTermSupport: lts,
		})
	}
	return out, nil
}

// StatusOf returns the support status of a release on a given day, and the
// date its current kind of support ends.
func StatusOf(cycles []Cycle, release string, now time.Time) (Status, time.Time) {
	for _, c := range cycles {
		if c.Cycle != release {
			continue
		}
		final := c.SecurityEnds
		if !c.ExtendedEnds.IsZero() {
			final = c.ExtendedEnds
		}
		switch {
		case c.StillSupported || (!c.SecurityEnds.IsZero() && now.Before(c.SecurityEnds)):
			return Supported, c.SecurityEnds
		case !final.IsZero() && now.Before(final):
			return ExtendedOnly, final
		case !final.IsZero():
			return Unsupported, final
		}
		return Unknown, time.Time{}
	}
	return Unknown, time.Time{}
}

// dateOrBool reads endoflife.date fields that are either a date or a boolean.
func dateOrBool(raw json.RawMessage) (time.Time, bool) {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		if t, err := time.Parse("2006-01-02", s); err == nil {
			return t, true
		}
	}
	var b bool
	_ = json.Unmarshal(raw, &b)
	return time.Time{}, b
}
