package cli

import (
	"cmp"
	"context"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/kugesh-rajasekaran/make-it-safer/internal/apperr"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/config"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/engine"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/explain"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/feeds/cvelist"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/findings"
)

// showView is mis show --json: each matching finding, with the facts.
type showView struct {
	findingView
	Facts []explain.Fact `json:"facts,omitempty"`
}

func (a *app) showCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "show <CVE-…>",
		Short: "Show a vulnerability: should you act now, which servers have it, and the fix",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			cve, err := parseCVE(args[0])
			if err != nil {
				return err
			}
			paths, cfg, err := a.setup()
			if err != nil {
				return err
			}
			st, err := findings.Load(paths)
			if err != nil {
				return err
			}
			matches := slices.DeleteFunc(slices.Clone(st.Findings), func(f *findings.Finding) bool { return f.CVE != cve })
			if len(matches) == 0 {
				return apperr.New(apperr.FindingsNotFound, cve+" doesn't affect any of your servers (as of the last check)")
			}
			sortFindings(matches)
			top := *matches[0] // a copy: what is looked up here isn't saved
			a.complete(paths, cfg, &top)
			out := make([]showView, len(matches))
			for i, m := range matches {
				if i == 0 {
					m = &top
				}
				out[i] = showView{findingView{m, explain.Verdict(m), explain.Why(m)}, explain.Facts(m)}
			}
			return a.emit(out, func(w io.Writer) { writeShow(w, &top, matches) })
		},
	}
}

// lookupCVE reads a CVE record (cached, or from the CVE List). A variable
// so tests never go online.
var lookupCVE = func(ctx context.Context, e *engine.Engine, id string) (*cvelist.Record, error) {
	return e.CVE.Get(ctx, id)
}

// complete looks up the CVE record when the finding has none: only
// findings with a fix are looked up during checks. Best effort.
func (a *app) complete(paths config.Paths, cfg *config.Config, f *findings.Finding) {
	if f.Kind != findings.KindVulnerability || f.Vector != "" || f.Details != "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	r, err := lookupCVE(ctx, engine.New(paths, cfg, version, a.log), f.CVE)
	if err != nil {
		return
	}
	f.Vector, f.Weakness, f.Details = r.Vector, r.Weakness, r.Description
	if f.Score == 0 {
		f.Score = r.Score
	}
}

// writeShow prints the "should I act?" page for one CVE.
func writeShow(w io.Writer, top *findings.Finding, matches []*findings.Finding) {
	row := func(label, value string) {
		if value != "" {
			_, _ = fmt.Fprintf(w, "  %-26s %s\n", label, value)
		}
	}
	_, _ = fmt.Fprintf(w, "%s · %s\n\n", top.CVE, clean(top.Source))
	verdict := strings.ToUpper(explain.Verdict(top))
	if why := explain.Why(top); why != "" {
		verdict += " — " + why
	}
	_, _ = fmt.Fprintf(w, "  %s\n\n", verdict)
	for _, fact := range explain.Facts(top) {
		row(fact.Label, fact.Value)
	}

	early, fix := false, ""
	for i, m := range matches {
		state, fixed := string(m.State), clean(cmp.Or(m.Fixed, "no fix yet"))
		if !m.Open() {
			state = cmp.Or(m.Resolution, "fixed") + " " + m.ResolvedAt.Local().Format("2006-01-02")
		}
		if m.Kind == findings.KindEarlyWarning {
			early, fixed, state = true, "not assessed by your distro yet", "early warning, "+state
		}
		label := ""
		if i == 0 {
			label = "Your servers"
		}
		row(label, fmt.Sprintf("%s  %s %s → %s  [%s]", m.Server, m.Source, m.Installed, fixed, state))
		if fix == "" && m.Open() && m.HasFix() {
			fix = "mis fix " + m.Server + " " + m.CVE
			if isAppleSource(m.Source) {
				fix = "System Settings › General › Software Update"
			}
		}
	}
	row("Fix", fix)
	row("Details", wrap(clean(cmp.Or(top.Details, top.Summary)), 70, strings.Repeat(" ", 29)))
	row("Weakness", clean(top.Weakness))
	if early {
		_, _ = fmt.Fprintln(w, "\n  Early warnings come from the CVE List before your distro has assessed the CVE.\n"+
			"  They're matched by product name, so they may not apply. The distro's verdict replaces them.")
	}
	more := "https://www.cve.org/CVERecord?id=" + top.CVE
	if slices.ContainsFunc(matches, func(m *findings.Finding) bool { return !isAppleSource(m.Source) }) {
		more += " · https://ubuntu.com/security/" + top.CVE + " · https://security-tracker.debian.org/tracker/" + top.CVE
	} else {
		more += " · https://support.apple.com/en-us/100100"
	}
	_, _ = fmt.Fprintf(w, "\n  More: %s\n", more)
}

func isAppleSource(s string) bool { return s == "macos" || s == "safari" }

// wrap breaks s into lines of at most width characters; lines after the
// first start with indent.
func wrap(s string, width int, indent string) string {
	var lines []string
	cur := ""
	for _, word := range strings.Fields(s) {
		if cur != "" && len([]rune(cur))+1+len([]rune(word)) > width {
			lines, cur = append(lines, cur), word
			continue
		}
		cur = strings.TrimSpace(cur + " " + word)
	}
	if cur != "" {
		lines = append(lines, cur)
	}
	return strings.Join(lines, "\n"+indent)
}
