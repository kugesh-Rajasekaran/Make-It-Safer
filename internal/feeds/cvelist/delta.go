package cvelist

import (
	"bytes"
	"context"
	"encoding/json"
	"time"

	"github.com/kugesh-rajasekaran/make-it-safer/internal/apperr"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/feeds"
)

// Change is a CVE that was published or updated in the CVE List.
type Change struct {
	ID  string `json:"id"`
	New bool   `json:"new"` // first published, rather than updated
}

// Delta is what changed in the CVE List since an earlier read.
type Delta struct {
	Changes []Change
	Newest  time.Time // time of the newest change set; pass it as since next time
	Reset   bool      // since was zero or older than the log: no changes, start from Newest
}

// The delta log lists every change set of the last 30 days, newest first
// (about 37 MB; a new set every ~11 minutes). Only its start is read: 64 KB
// usually covers the 15 minutes since the last read. After a longer gap,
// more is read; 0 means the whole file.
var readSizes = []int64{64 << 10, 1 << 20, 8 << 20, 0}

// Changes returns the CVEs published or updated after since, each once.
func (c *Client) Changes(ctx context.Context, since time.Time) (*Delta, error) {
	url := c.Base + "/cves/deltaLog.json"
	for _, n := range readSizes {
		var resp *feeds.Response
		var err error
		if n > 0 {
			resp, err = c.Feeds.GetStart(ctx, url, n)
		} else {
			resp, err = c.Feeds.Get(ctx, url, "")
		}
		if err != nil {
			return nil, apperr.Wrap(apperr.CVEListFailed, err, "cannot read the CVE List changes")
		}
		sets, whole := parseLog(resp.Body)
		if len(sets) == 0 {
			if whole || !resp.Partial {
				return nil, apperr.New(apperr.CVEListFailed, "the CVE List change log is empty or unreadable")
			}
			continue // the first change set is longer than this read
		}
		d := &Delta{Newest: sets[0].FetchTime}
		index := map[string]int{} // CVE → position in d.Changes
		if since.IsZero() {
			d.Reset = true
			return d, nil
		}
		reached := false
		for _, s := range sets {
			if !s.FetchTime.After(since) {
				reached = true
				break
			}
			d.add(s, index)
		}
		switch {
		case reached:
			return d, nil
		case whole || !resp.Partial: // since is older than the whole log
			return &Delta{Newest: d.Newest, Reset: true}, nil
		}
	}
	return nil, apperr.New(apperr.CVEListFailed, "the CVE List change log is larger than expected")
}

// changeSet is one entry of the delta log.
type changeSet struct {
	FetchTime time.Time `json:"fetchTime"`
	New       []entry   `json:"new"`
	Updated   []entry   `json:"updated"`
}

type entry struct {
	ID string `json:"cveId"`
}

func (d *Delta) add(s changeSet, index map[string]int) {
	for _, list := range []struct {
		entries []entry
		isNew   bool
	}{{s.New, true}, {s.Updated, false}} {
		for _, e := range list.entries {
			if !idPattern.MatchString(e.ID) {
				continue // not a CVE id: ignore it
			}
			i, seen := index[e.ID]
			if !seen {
				index[e.ID] = len(d.Changes)
				d.Changes = append(d.Changes, Change{ID: e.ID, New: list.isNew})
			} else if list.isNew {
				d.Changes[i].New = true
			}
		}
	}
}

// parseLog decodes change sets from the start of the log. A cut-off read
// ends mid-set: the complete sets before it are returned. whole reports
// whether the log ended properly.
func parseLog(data []byte) (sets []changeSet, whole bool) {
	dec := json.NewDecoder(bytes.NewReader(data))
	if t, err := dec.Token(); err != nil || t != json.Delim('[') {
		return nil, false
	}
	for dec.More() {
		var s changeSet
		if err := dec.Decode(&s); err != nil {
			return sets, false
		}
		sets = append(sets, s)
	}
	_, err := dec.Token()
	return sets, err == nil
}
