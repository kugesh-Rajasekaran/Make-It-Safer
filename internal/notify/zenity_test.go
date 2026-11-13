package notify

import (
	"slices"
	"testing"

	"github.com/kugesh-rajasekaran/make-it-safer/internal/explain"
)

func TestZenity(t *testing.T) {
	d := Dialog{ID: "cve:CVE-1", Title: "CVE-1 · openssh", Verdict: "Act now",
		Facts:   []explain.Fact{{Label: "What an attacker could do", Value: "Could take it over"}, {Label: "Being exploited?", Value: "Yes"}},
		Fix:     "Update opens your terminal with this typed in.",
		Command: "sudo apt-get install --only-upgrade openssh-server",
		Rows: []Row{
			{Name: "db", Detail: "openssh 1 → 2", Button: &Button{ID: "fix:db", Title: "Update"}},
			{Name: "web", Detail: "openssh 1 → 2", Command: "sudo reboot", Button: &Button{ID: "fix:web", Title: "Update"}, Opened: true},
			{Name: "old", Detail: "openssh 1 → no fix yet"},
		}}

	want := "CVE-1 · openssh\nAct now\n\nWhat it is\nWhat an attacker could do: Could take it over\nBeing exploited? Yes\n\n" +
		"The fix\nUpdate opens your terminal with this typed in.\nsudo apt-get install --only-upgrade openssh-server\n\n" +
		"What it affects\ndb · openssh 1 → 2\nweb · openssh 1 → 2\n    sudo reboot\nold · openssh 1 → no fix yet"
	if got := dialogText(d); got != want {
		t.Errorf("dialogText =\n%s\nwant\n%s", got, want)
	}

	args := zenityArgs(d)
	for _, a := range []string{"--no-markup", "--extra-button=Update db", "--extra-button=Update web ✓", "--text=" + want} {
		if !slices.Contains(args, a) {
			t.Errorf("args %q lack %q", args, a)
		}
	}
	if slices.ContainsFunc(args, func(a string) bool { return a == "--extra-button=old" }) {
		t.Error("a row without a fix has no button")
	}

	for out, action := range map[string]string{"Update web ✓\n": "fix:web", "Update db\n": "fix:db", "": "", "Update old\n": "", "Update db extra\n": ""} {
		if got := zenityAction(d, out); got != action {
			t.Errorf("zenityAction(%q) = %q, want %q", out, got, action)
		}
	}
}
