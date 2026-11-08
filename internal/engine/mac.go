package engine

import (
	"context"
	"fmt"
	"strings"

	"github.com/kugesh-rajasekaran/make-it-safer/internal/feeds/apple"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/feeds/kev"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/findings"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/inventory"
)

// macFindings turns a Mac's inventory into findings (ADR 0003):
//   - every CVE fixed by a macOS or Safari update Apple offers this Mac,
//     from Apple's security notes: all security releases newer than what's
//     installed, up to the offered update. A major upgrade (e.g. macOS 27 on
//     a Sequoia Mac) isn't needed for security while the release is
//     supported, so it's skipped; end of life is reported separately.
//   - one "can be updated" finding for outdated Homebrew packages.
//
// Each CVE is enriched and prioritised like a server's (KEV, EPSS, CVSS).
func (e *Engine) macFindings(ctx context.Context, server string, inv *inventory.Inventory, catalog *kev.Catalog) ([]*findings.Finding, error) {
	var out []*findings.Finding
	seen := map[string]bool{}
	var releases []apple.Release
	for _, u := range inv.Mac.Updates {
		product, installed := appleProduct(u, inv)
		if product == "" {
			continue
		}
		if releases == nil {
			var err error
			if releases, err = e.Apple.Releases(ctx); err != nil {
				return nil, err
			}
		}
		for _, r := range releases {
			if r.Product != product || apple.CompareVersions(r.Version, installed) <= 0 || apple.CompareVersions(r.Version, u.Version) > 0 ||
				(product == apple.MacOS && apple.Major(r.Version) != apple.Major(installed)) {
				continue
			}
			cves, err := e.Apple.CVEs(ctx, r)
			if err != nil {
				return nil, err
			}
			for _, cve := range cves {
				id := findings.MakeID(server, findings.KindVulnerability, cve+"/"+strings.ToLower(product))
				if seen[id] || !cvePattern.MatchString(cve) {
					continue
				}
				seen[id] = true
				out = append(out, &findings.Finding{
					ID: id, Server: server, Kind: findings.KindVulnerability, CVE: cve, VulnID: r.Name,
					Source: strings.ToLower(product), Installed: installed, Fixed: u.Version,
					Summary: "Fixed in " + r.Name + " (Apple security note " + r.URL + ")", KEV: catalog.Has(cve),
				})
			}
		}
	}
	if n := len(inv.Mac.Homebrew); n > 0 {
		names := make([]string, 0, min(n, 5))
		for _, p := range inv.Mac.Homebrew[:min(n, 5)] {
			names = append(names, p.Name)
		}
		more := ""
		if n > 5 {
			more = fmt.Sprintf(" and %d more", n-5)
		}
		out = append(out, &findings.Finding{
			ID: findings.MakeID(server, findings.KindUpdates, "homebrew"), Server: server, Kind: findings.KindUpdates,
			Source: "homebrew", Installed: fmt.Sprintf("%d outdated", n), Fixed: "brew upgrade",
			Summary: fmt.Sprintf("%d Homebrew packages can be updated: %s%s", n, strings.Join(names, ", "), more),
		})
	}
	return out, nil
}

// appleProduct says which product an offered update is for, and the version
// installed now. A major macOS upgrade or another component returns "".
func appleProduct(u inventory.AppleUpdate, inv *inventory.Inventory) (product, installed string) {
	switch {
	case strings.HasPrefix(u.Title, "Safari") && inv.Mac.Safari != "":
		return apple.Safari, inv.Mac.Safari
	case strings.HasPrefix(u.Title, "macOS ") && apple.Major(u.Version) == apple.Major(inv.OSVersion):
		return apple.MacOS, inv.OSVersion
	}
	return "", ""
}
