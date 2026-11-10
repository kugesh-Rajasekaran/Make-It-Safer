package explain

import (
	"strings"
	"testing"

	"github.com/kugesh-rajasekaran/make-it-safer/internal/findings"
)

func vuln(p findings.Priority, fixed string) *findings.Finding {
	return &findings.Finding{Kind: findings.KindVulnerability, Priority: p, Fixed: fixed}
}

func TestVerdict(t *testing.T) {
	cases := []struct {
		f    *findings.Finding
		want string
	}{
		{vuln(findings.Urgent, "2"), "Act now"},
		{vuln(findings.High, "2"), "This week"},
		{vuln(findings.Normal, "2"), "Can wait"},
		{vuln(findings.Silent, "2"), "Ignored"},
		{vuln(findings.Urgent, ""), "No fix yet"},
		{&findings.Finding{Kind: findings.KindEarlyWarning, Priority: findings.High}, "Heads-up"},
		{&findings.Finding{Kind: findings.KindReboot, Priority: findings.High}, "This week"},
	}
	for _, c := range cases {
		if got := Verdict(c.f); got != c.want {
			t.Errorf("Verdict(%s, fixed %q) = %q, want %q", c.f.Priority, c.f.Fixed, got, c.want)
		}
	}
}

func TestWhy(t *testing.T) {
	cases := []struct {
		name string
		f    findings.Finding
		want string
	}{
		{"remote takeover, exploited (v3.1)", findings.Finding{KEV: true, Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
			"being exploited · can be triggered remotely, no login · could take it over"},
		{"the effect is never cut", findings.Finding{KEV: true, Vector: "CVSS:3.1/AV:A/AC:L/PR:H/UI:R/S:U/C:N/I:H/A:H"},
			"being exploited · from the local network, needs an admin login, needs user action · could change data or crash it"},
		{"local read with a login (v3.0)", findings.Finding{Vector: "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"},
			"needs local access, needs a login · could read data"},
		{"local without a login says nothing about logins", findings.Finding{Vector: "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"},
			"needs local access · could read data"},
		{"a malicious file someone opens", findings.Finding{Vector: "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H"},
			"needs someone to open a malicious file · could take it over"},
		{"remote with user action (v3.1)", findings.Finding{Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H"},
			"can be triggered remotely, no login, needs user action · could crash it"},
		{"v4.0 with supplemental metrics", findings.Finding{Vector: "CVSS:4.0/AV:A/AC:L/AT:N/PR:N/UI:A/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N/U:Amber"},
			"from the local network, no login, needs user action · could read or change data"},
		{"EPSS that raised the priority", findings.Finding{EPSS: 0.4, Priority: findings.High, Vector: "CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"},
			"40% chance of attacks soon · needs physical access · limited impact"},
		{"EPSS that didn't raise it", findings.Finding{EPSS: 0.4, Priority: findings.Normal, Vector: "CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"},
			"needs physical access · limited impact"},
		{"line and paragraph separators", findings.Finding{Impact: "An app\u2028may\u2029crash."}, "An app may crash"},
		{"Apple's words for Apple software", findings.Finding{Source: "macos", Vector: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
			Impact: "An app may be able to gain root privileges. Apple is aware of a report that this issue may have been exploited."},
			"An app may be able to gain root privileges"},
		{"CISA's words without a vector", findings.Finding{KEV: true, Impact: "Example Server contains an injection flaw."},
			"being exploited · Example Server contains an injection flaw"},
		{"distro rating only", findings.Finding{DistroPriority: "medium"}, "rated medium by the distro"},
		{"minor distro rating", findings.Finding{DistroPriority: "unimportant"}, "minor, says the distro"},
		{"unhelpful distro rating", findings.Finding{DistroPriority: "not yet assigned"}, ""},
		{"garbled vector falls back", findings.Finding{Vector: "CVSS:3.1/AV:Q/C:H", DistroPriority: "low"}, "rated low by the distro"},
		{"nothing known", findings.Finding{}, ""},
		{"feed text is cleaned", findings.Finding{Impact: "An app\u202e may\x1b[31m crash.\n"}, "An app may [31m crash"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := Why(&c.f); got != c.want {
				t.Errorf("Why() = %q\n           want %q", got, c.want)
			}
		})
	}
	long := findings.Finding{Impact: "An app may be able to " + strings.Repeat("do something ", 20)}
	if got := Impact(&long); len([]rune(got)) > MaxImpact || !strings.HasPrefix(long.Impact, strings.TrimSuffix(got, "…")+" ") {
		t.Errorf("long impact is cut at a word: %q", got)
	}
}

func TestFacts(t *testing.T) {
	f := &findings.Finding{Vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", Score: 8.1, EPSS: 0.094}
	want := []Fact{
		{"What an attacker could do", "Could take it over"},
		{"How it's triggered", "Can be triggered remotely, no login · no user action · hard to pull off"},
		{"Severity", "CVSS 8.1 of 10"},
		{"Being exploited?", "Not on CISA's list of exploited vulnerabilities · 9% chance of attacks in the next 30 days (EPSS)"},
	}
	got := Facts(f)
	if len(got) != len(want) {
		t.Fatalf("facts = %+v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("fact %d = %+v, want %+v", i, got[i], want[i])
		}
	}

	mac := Facts(&findings.Finding{Source: "safari", KEV: true, Impact: "An app may be able to read kernel memory.", DistroPriority: "high"})
	if len(mac) != 3 || mac[0].Value != "An app may be able to read kernel memory" || mac[1].Value != "Rated high by the distro" ||
		!strings.HasPrefix(mac[2].Value, "Yes: on CISA's list") {
		t.Errorf("mac facts = %+v", mac)
	}
	for _, e := range []float64{0.001, 0.005, 0.009} {
		if low := Facts(&findings.Finding{EPSS: e}); low[0].Value != "Not on CISA's list of exploited vulnerabilities · under 1% chance of attacks in the next 30 days (EPSS)" {
			t.Errorf("EPSS %v = %+v", e, low)
		}
	}
	long := "An app may be able to cause unexpected app termination or arbitrary code execution with kernel privileges."
	if got := Facts(&findings.Finding{Source: "macos", Impact: long}); got[0].Value != strings.TrimSuffix(long, ".") {
		t.Errorf("mis show keeps the whole sentence: %q", got[0].Value)
	}
}

func TestWorstAndImpact(t *testing.T) {
	reboot := &findings.Finding{Kind: findings.KindReboot, Priority: findings.Urgent}
	high := &findings.Finding{Kind: findings.KindVulnerability, Priority: findings.High, Score: 9.8}
	exploited := &findings.Finding{Kind: findings.KindVulnerability, Priority: findings.High, KEV: true, Score: 5,
		Impact: "An app may be able to gain root privileges.\n"}
	if got := Worst([]*findings.Finding{reboot, high, exploited}); got != exploited {
		t.Errorf("Worst = %+v", got)
	}
	if Worst([]*findings.Finding{reboot}) != nil || Why(nil) != "" || Impact(nil) != "" || Risk(nil) != "" {
		t.Error("no vulnerability: nil worst, empty why, risk and impact")
	}
	if got := Impact(exploited); got != "An app may be able to gain root privileges" {
		t.Errorf("Impact = %q", got)
	}
	if got := Clean("a\u200bb\u202ec\nd"); got != "a b c d" {
		t.Errorf("Clean = %q", got)
	}
}
