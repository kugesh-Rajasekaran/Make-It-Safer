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

// MaxWhy is the longest a Why line gets.
const MaxWhy = 80

// Verdict says when to act on a finding.
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
	return "Low risk"
}

// Why is one plain line on what makes the finding dangerous, for example
// "being exploited · can be triggered remotely, no login · could gain full
// control". It never claims more than the data says: a CVSS "network"
// vector means the attack data can arrive over the network, not that the
// server is reachable from the internet. "" when nothing is known.
func Why(f *findings.Finding) string {
	if f == nil {
		return ""
	}
	exploited := ""
	if f.KEV {
		exploited = "being exploited"
	}
	return cut(join([]string{exploited, Risk(f)}), MaxWhy)
}

// Risk is Why without "being exploited", for places that already say so:
// how the flaw is reached and what it allows, else the source's impact
// sentence, else the distro's rating.
func Risk(f *findings.Finding) string {
	if f == nil {
		return ""
	}
	v := parse(f.Vector)
	switch {
	case v != nil:
		return cut(join([]string{v.access(), v.effect()}), MaxWhy)
	case f.Impact != "":
		return Impact(f)
	case f.DistroPriority != "":
		return "rated " + clean(f.DistroPriority) + " by the distro"
	}
	return ""
}

// Impact is the source's own sentence on what an attacker could do (Apple's
// "Impact:", CISA's description), cleaned and at most MaxWhy characters.
func Impact(f *findings.Finding) string {
	if f == nil {
		return ""
	}
	return cut(strings.TrimSuffix(clean(f.Impact), "."), MaxWhy)
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

func compareBool(a, b bool) int {
	switch {
	case a == b:
		return 0
	case a:
		return 1
	}
	return -1
}

// Fact is one labelled line of mis show.
type Fact struct {
	Label string `json:"label"`
	Value string `json:"value"`
}

// Facts are the "should I act?" lines of mis show: what an attacker could
// do, how it's triggered and whether it's being exploited. Unknown lines
// are left out.
func Facts(f *findings.Finding) []Fact {
	v := parse(f.Vector)
	var out []Fact
	switch {
	case f.Impact != "":
		out = append(out, Fact{"What an attacker could do", strings.TrimSuffix(clean(f.Impact), ".")})
	case v != nil && v.effect() != "":
		out = append(out, Fact{"What an attacker could do", Capitalize(v.effect())})
	}
	if v != nil {
		how := []string{v.access()}
		if v["UI"] == "N" {
			how = append(how, "no user action")
		}
		if v["AC"] == "H" || v["AT"] == "P" {
			how = append(how, "hard to pull off")
		}
		out = append(out, Fact{"How it's triggered", Capitalize(strings.Join(how, " · "))})
	}
	exploited := "no known attacks"
	switch {
	case f.KEV:
		exploited = "yes: on CISA's list of exploited vulnerabilities"
	case f.EPSS > 0:
		exploited += fmt.Sprintf(" · %.0f%% chance of attacks in the next 30 days (EPSS)", f.EPSS*100)
	}
	return append(out, Fact{"Being exploited?", Capitalize(exploited)})
}

// vector is a parsed CVSS v3.x or v4.0 vector: metric → value.
type vector map[string]string

// parse reads "CVSS:3.1/AV:N/…" or "CVSS:4.0/AV:N/…"; nil if it isn't one
// or misses the attack vector.
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
	if v["AV"] == "" {
		return nil
	}
	return v
}

// access says how the flaw is reached: from where, and with or without a
// login and a user's help.
func (v vector) access() string {
	where := map[string]string{
		"N": "can be triggered remotely", "A": "from the local network",
		"L": "needs local access", "P": "needs physical access",
	}[v["AV"]]
	var parts []string
	if where != "" {
		parts = append(parts, where)
	}
	switch v["PR"] {
	case "N":
		parts = append(parts, "no login")
	case "L", "H":
		parts = append(parts, "needs a login")
	}
	if u := v["UI"]; u == "R" || u == "P" || u == "A" { // v3 "required", v4 "passive"/"active"
		parts = append(parts, "needs user action")
	}
	return strings.Join(parts, ", ")
}

// effect says what a successful attack does, from the confidentiality,
// integrity and availability impacts (v3 C/I/A, v4 VC/VI/VA).
func (v vector) effect() string {
	high := func(v3, v4 string) bool { return v[v3] == "H" || v[v4] == "H" }
	low := func(v3, v4 string) bool { return v[v3] == "L" || v[v4] == "L" }
	c, i, a := high("C", "VC"), high("I", "VI"), high("A", "VA")
	switch {
	case c && i && a:
		return "could gain full control"
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
func join(parts []string) string {
	var keep []string
	for _, p := range parts {
		if p != "" {
			keep = append(keep, p)
		}
	}
	return strings.Join(keep, " · ")
}

// clean makes feed text one safe line: no control or invisible formatting
// characters, single spaces.
func clean(s string) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == '\u2028' || r == '\u2029' {
			return ' '
		}
		return r
	}, s)
	return strings.Join(strings.Fields(s), " ")
}

// cut shortens s to n characters.
func cut(s string, n int) string {
	if r := []rune(s); len(r) > n {
		return string(r[:n-1]) + "…"
	}
	return s
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
