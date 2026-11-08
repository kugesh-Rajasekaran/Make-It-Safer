package engine

import (
	"fmt"
	"regexp"
	"time"

	"github.com/kugesh-rajasekaran/make-it-safer/internal/feeds/eol"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/feeds/osv"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/findings"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/inventory"
)

// kernelImage matches versioned kernel packages (not meta-packages like
// linux-image-generic or linux-image-amd64).
var kernelImage = regexp.MustCompile(`^linux-image-(unsigned-)?[0-9]`)

// rebootFinding reports a server that installed a newer kernel than it runs.
func rebootFinding(server string, inv *inventory.Inventory) *findings.Finding {
	running, newest, newestName := "", "", ""
	for _, p := range inv.Packages {
		if !kernelImage.MatchString(p.Name) {
			continue
		}
		if p.Name == "linux-image-"+inv.Kernel || p.Name == "linux-image-unsigned-"+inv.Kernel {
			running = p.Version
		}
		if newest == "" || osv.CompareVersions(p.Version, newest) > 0 {
			newest, newestName = p.Version, p.Name
		}
	}
	summary := ""
	switch {
	case running != "" && osv.CompareVersions(newest, running) > 0:
		summary = fmt.Sprintf("kernel %s is installed but %s is running; restart to use the patched kernel", newestName, inv.Kernel)
	case inv.RebootRequired:
		summary = "the server says a restart is required to finish installing updates"
	default:
		return nil
	}
	return &findings.Finding{
		ID: findings.MakeID(server, findings.KindReboot, "kernel"), Server: server, Kind: findings.KindReboot,
		Source: "linux", Installed: inv.Kernel, Summary: summary,
	}
}

// eolFinding reports a release whose security support has ended. release is
// the cycle endoflife.date uses: "24.04", "12", or macOS's major version.
func eolFinding(server, osID, release string, cycles []eol.Cycle, now time.Time) *findings.Finding {
	status, until := eol.StatusOf(cycles, release, now)
	name := map[string]string{"ubuntu": "Ubuntu", "debian": "Debian", "macos": "macOS"}[osID] + " " + release
	f := &findings.Finding{
		ID: findings.MakeID(server, findings.KindEndOfLife, osID+"-"+release), Server: server,
		Kind: findings.KindEndOfLife, Installed: name,
	}
	switch {
	case status == eol.Unsupported:
		f.Priority, f.Summary = findings.Urgent, fmt.Sprintf("%s stopped receiving security updates on %s; upgrade to a supported release", name, until.Format("2006-01-02"))
	case status == eol.ExtendedOnly && osID == "ubuntu":
		f.Priority, f.Summary = findings.High, fmt.Sprintf("%s's standard support has ended; security fixes now need Ubuntu Pro (until %s)", name, until.Format("2006-01-02"))
	case status == eol.ExtendedOnly:
		f.Priority, f.Summary = findings.High, fmt.Sprintf("%s's regular security support has ended; Debian LTS covers it until %s", name, until.Format("2006-01-02"))
	default:
		return nil
	}
	return f
}
