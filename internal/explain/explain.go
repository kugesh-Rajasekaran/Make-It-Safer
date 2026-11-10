// Package explain puts a finding's risk into plain words: a verdict (act
// now or later) and one line saying why, built by fixed rules from what the
// finding already holds. Text that came from a feed is cleaned here, so the
// result is always one safe line.
package explain

import (
	"cmp"
	"fmt"
	"strings"
	"unicode"

	"github.com/kugesh-rajasekaran/make-it-safer/internal/findings"
)

// MaxImpact is the longest a source's impact sentence gets.
const MaxImpact = 80

// likelyEPSS is the EPSS from which attacks count as likely soon (the
// default rules.alert_when.min_epss).
const likelyEPSS = 0.10

// Verdict says when to act on a finding. It follows the priority, so the
// words can't disagree with it.
func Verdict(f *findings.Finding) string {
	switch {
	case f.Kind == findings.KindEarlyWarning:
		return "Heads-up"
	case f.Kind == findings.KindVulnerability && !f.HasFix():
		return "No fix yet"
	}
	switch f.Priority {
	case findings.Urgent:
		return "Act now"
	case findings.High:
		return "This week"
	case findings.Normal:
		return "Can wait"
	}
	return "Ignored" // a fix exists, but it matches your ignore list
}

// Why is one plain line on what makes the finding dangerous, for example
// "being exploited · can be triggered remotely, no login · could take it
// over". It never claims more than the data says: a CVSS "network" vector
// means the attack data can arrive over the network, not that the server is
// reachable from the internet. "" when nothing is known.
func Why(f *findings.Finding) string {
	if f == nil {
		return ""
	}
	alert := ""
	switch {
	case f.KEV:
		alert = "being exploited"
	case f.EPSS >= likelyEPSS:
		alert = "attacks likely soon"
	}
	return join(alert, Risk(f))
}

// Risk is Why without "being exploited", for places that already say so:
// how the flaw is reached and what it allows, else the source's impact
// sentence, else the distro's rating. Apple's own sentence comes first for
// Apple's software.
func Risk(f *findings.Finding) string {
	if f == nil {
		return ""
	}
	if isApple(f) && f.Impact != "" {
		return Impact(f)
	}
	if v := parse(f.Vector); v != nil {
		if s := join(v.access(), v.effect()); s != "" {
			return s
		}
	}
	return cmp.Or(Impact(f), rating(f.DistroPriority))
}

// Impact is the source's own sentence on what an attacker could do
// (Apple's "Impact:", CISA's description): its first sentence, cleaned and
// shortened at a word.
func Impact(f *findings.Finding) string {
	if f == nil {
		return ""
	}
	s := clean(f.Impact)
	if i := strings.Index(s, ". "); i > 0 {
		s = s[:i]
	}
	return words(strings.TrimSuffix(s, "."), MaxImpact)
}

// Worst is the most severe vulnerability among fs: highest priority, then
// exploited, then CVSS, then EPSS. nil when there is none.
func Worst(fs []*findings.Finding) *findings.Finding {
	var worst *findings.Finding
	for _, f := range fs {
		if f.Kind != findings.KindVulnerability {
			continue
		}
		if worst == nil || cmp.Or(cmp.Compare(f.Priority, worst.Priority), compareBool(f.KEV, worst.KEV),
			cmp.Compare(f.Score, worst.Score), cmp.Compare(f.EPSS, worst.EPSS)) > 0 {
			worst = f
		}
	}
	return worst
}

// Fact is one labelled line of mis show.
type Fact struct {
	Label string `json:"label"`
	Value string `json:"value"`
}

// Facts are the "should I act?" lines of mis show: what an attacker could
// do, how it's triggered, how severe it is and whether it's being
// exploited. Unknown lines are left out.
func Facts(f *findings.Finding) []Fact {
	v := parse(f.Vector)
	var out []Fact
	add := func(label, value string) {
		if value != "" {
			out = append(out, Fact{label, Capitalize(value)})
		}
	}
	what := ""
	if isApple(f) {
		what = Impact(f)
	}
	if what == "" && v != nil {
		what = v.effect()
	}
	add("What an attacker could do", cmp.Or(what, Impact(f)))
	if v != nil {
		how := []string{v.access()}
		if v["UI"] == "N" {
			how = append(how, "no user action")
		}
		if v["AC"] == "H" || v["AT"] == "P" {
			how = append(how, "hard to pull off")
		}
		add("How it's triggered", join(how...))
	}
	severity := rating(f.DistroPriority)
	if f.Score > 0 {
		severity = fmt.Sprintf("CVSS %.1f of 10", f.Score)
	}
	add("Severity", severity)
	exploited := "not on CISA's list of exploited vulnerabilities"
	switch {
	case f.KEV:
		exploited = "yes: on CISA's list of exploited vulnerabilities"
	case f.EPSS > 0:
		exploited += " · " + chance(f.EPSS) + " chance of attacks in the next 30 days (EPSS)"
	}
	add("Being exploited?", exploited)
	return out
}

func chance(epss float64) string {
	if epss < 0.005 {
		return "under 1%"
	}
	return fmt.Sprintf("%.0f%%", epss*100)
}

// rating words a distro's priority; "" when it says nothing useful.
func rating(p string) string {
	switch p = strings.ToLower(clean(p)); p {
	case "negligible", "unimportant":
		return "minor, says the distro"
	case "low", "medium", "high", "critical":
		return "rated " + p + " by the distro"
	}
	return ""
}

func isApple(f *findings.Finding) bool { return f.Source == "macos" || f.Source == "safari" }

// vector is a parsed CVSS v3.x or v4.0 vector: metric → value.
type vector map[string]string

// parse reads "CVSS:3.1/AV:N/…" or "CVSS:4.0/AV:N/…"; nil if it isn't one
// or its attack vector isn't a known value.
func parse(s string) vector {
	parts := strings.Split(s, "/")
	if len(parts) < 2 || (!strings.HasPrefix(parts[0], "CVSS:3.") && parts[0] != "CVSS:4.0") {
		return nil
	}
	v := vector{}
	for _, p := range parts[1:] {
		if k, val, ok := strings.Cut(p, ":"); ok {
			v[k] = val
		}
	}
	if !strings.Contains("NALP", v["AV"]) || len(v["AV"]) != 1 {
		return nil
	}
	return v
}

// access says how the flaw is reached: from where, and with or without a
// login and a user's help.
func (v vector) access() string {
	av, pr, ui := v["AV"], v["PR"], v["UI"]
	user := ui == "R" || ui == "P" || ui == "A" // v3 "required", v4 "passive"/"active"
	var parts []string
	switch {
	case av == "N":
		parts = append(parts, "can be triggered remotely")
	case av == "A":
		parts = append(parts, "from the local network")
	case av == "L" && user: // e.g. a crafted file someone opens
		parts, user = append(parts, "needs someone to open a malicious file"), false
	case av == "L":
		parts = append(parts, "needs local access")
	case av == "P":
		parts = append(parts, "needs physical access")
	}
	switch {
	case pr == "N" && (av == "L" || av == "P"): // "local access, no login" says nothing
	case pr == "N":
		parts = append(parts, "no login")
	case pr == "L":
		parts = append(parts, "needs a login")
	case pr == "H":
		parts = append(parts, "needs an admin login")
	}
	if user {
		parts = append(parts, "needs user action")
	}
	return strings.Join(parts, ", ")
}

// effect says what a successful attack does to the affected software, from
// the confidentiality, integrity and availability impacts (v3 C/I/A, v4
// VC/VI/VA).
func (v vector) effect() string {
	high := func(v3, v4 string) bool { return v[v3] == "H" || v[v4] == "H" }
	low := func(v3, v4 string) bool { return v[v3] == "L" || v[v4] == "L" }
	c, i, a := high("C", "VC"), high("I", "VI"), high("A", "VA")
	switch {
	case c && i && a:
		return "could take it over"
	case c && i:
		return "could read or change data"
	case c && a:
		return "could read data or crash it"
	case i && a:
		return "could change data or crash it"
	case c:
		return "could read data"
	case i:
		return "could change data"
	case a:
		return "could crash it"
	case low("C", "VC") || low("I", "VI") || low("A", "VA"):
		return "limited impact"
	}
	return ""
}

// join puts the non-empty parts together with " · ".
func join(parts ...string) string {
	var keep []string
	for _, p := range parts {
		if p != "" {
			keep = append(keep, p)
		}
	}
	return strings.Join(keep, " · ")
}

// Clean makes feed text one safe line: no control or invisible formatting
// characters (bidi overrides, zero-width), single spaces.
func Clean(s string) string { return clean(s) }

func clean(s string) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == ' ' || r == ' ' {
			return ' '
		}
		return r
	}, s)
	return strings.Join(strings.Fields(s), " ")
}

// words shortens s to at most n characters, at a word boundary.
func words(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	cut := string(r[:n-1])
	if i := strings.LastIndex(cut, " "); i > n/2 {
		cut = cut[:i]
	}
	return strings.TrimRight(cut, " ,;:") + "…"
}

func compareBool(a, b bool) int {
	switch {
	case a == b:
		return 0
	case a:
		return 1
	}
	return -1
}

// Capitalize upper-cases the first letter, to start a sentence.
func Capitalize(s string) string {
	if s == "" {
		return s
	}
	r := []rune(s)
	r[0] = unicode.ToUpper(r[0])
	return string(r)
}
