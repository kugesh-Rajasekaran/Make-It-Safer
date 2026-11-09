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
		{vuln(findings.Silent, "2"), "Low risk"},
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
			"being exploited · can be triggered remotely, no login · could gain full control"},
		{"local read with a login (v3.0)", findings.Finding{Vector: "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"},
			"needs local access, needs a login · could read data"},
		{"crafted file (v3.1)", findings.Finding{Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H"},
			"can be triggered remotely, no login, needs user action · could crash it"},
		{"v4.0 with active user", findings.Finding{Vector: "CVSS:4.0/AV:A/AC:L/AT:N/PR:N/UI:A/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N"},
			"from the local network, no login, needs user action · could read or change data"},
		{"low impact only", findings.Finding{Vector: "CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"},
			"needs physical access, no login · limited impact"},
		{"Apple impact, no vector", findings.Finding{Impact: "An app may be able to gain root privileges."},
			"An app may be able to gain root privileges"},
		{"distro rating only", findings.Finding{DistroPriority: "medium"}, "rated medium by the distro"},
		{"garbled vector falls back", findings.Finding{Vector: "AV:N; rm -rf /", DistroPriority: "low"}, "rated low by the distro"},
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
	long := findings.Finding{KEV: true, Impact: strings.Repeat("word ", 40)}
	if got := []rune(Why(&long)); len(got) != MaxWhy || got[MaxWhy-1] != '…' {
		t.Errorf("long why: %d runes", len(got))
	}
}

func TestFacts(t *testing.T) {
	f := &findings.Finding{Vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", EPSS: 0.094}
	got := Facts(f)
	want := []Fact{
		{"What an attacker could do", "Could gain full control"},
		{"How it's triggered", "Can be triggered remotely, no login · no user action · hard to pull off"},
		{"Being exploited?", "No known attacks · 9% chance of attacks in the next 30 days (EPSS)"},
	}
	if len(got) != len(want) {
		t.Fatalf("facts = %+v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("fact %d = %+v, want %+v", i, got[i], want[i])
		}
	}

	mac := Facts(&findings.Finding{KEV: true, Impact: "An app may be able to read kernel memory."})
	if len(mac) != 2 || mac[0].Value != "An app may be able to read kernel memory" || !strings.HasPrefix(mac[1].Value, "Yes: on CISA's list") {
		t.Errorf("mac facts = %+v", mac)
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
	if Worst([]*findings.Finding{reboot}) != nil || Why(nil) != "" || Impact(nil) != "" {
		t.Error("no vulnerability: nil worst, empty why and impact")
	}
	if got := Impact(exploited); got != "An app may be able to gain root privileges" {
		t.Errorf("Impact = %q", got)
	}
}
