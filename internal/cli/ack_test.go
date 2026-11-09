package cli

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/kugesh-rajasekaran/make-it-safer/internal/config"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/findings"
)

// putFindings stores findings as they are (callers set the state).
func putFindings(t *testing.T, paths config.Paths, fs ...*findings.Finding) {
	t.Helper()
	err := findings.Update(paths, func(st *findings.Store) error {
		st.Findings = append(st.Findings, fs...)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func openVuln(server string) *findings.Finding {
	return &findings.Finding{
		ID: testFindingID(server), Server: server, Kind: findings.KindVulnerability, CVE: testCVE,
		Source: "openssh", Installed: "1", Fixed: "2", Priority: findings.High, State: findings.StateNew,
	}
}

// day is a date n days from now, as typed after --until.
func day(n int) (string, time.Time) {
	d := time.Now().AddDate(0, 0, n)
	s := d.Format("2006-01-02")
	at, _ := time.ParseInLocation("2006-01-02", s, time.Local)
	return s, at
}

func TestParseCVE(t *testing.T) {
	for in, want := range map[string]string{"CVE-2024-6387": "CVE-2024-6387", " cve-2024-0001 ": "CVE-2024-0001"} {
		if got, err := parseCVE(in); err != nil || got != want {
			t.Errorf("parseCVE(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "  ", "foo", "CVE-1", "CVE-2024-12", "CVE-2024-6387 CVE-2024-6388"} {
		if got, err := parseCVE(bad); err == nil {
			t.Errorf("parseCVE(%q) = %q, want an error", bad, got)
		}
	}
}

// An empty argument used to match every finding without a CVE (restarts,
// end of support) and accept them all.
func TestCVEArgumentIsChecked(t *testing.T) {
	paths := newConfigHome(t)
	withServers(t, paths, false, "web")
	putFindings(t, paths, &findings.Finding{
		ID: "web/reboot/", Server: "web", Kind: findings.KindReboot, Priority: findings.High, State: findings.StateNew,
	})
	before, _ := os.ReadFile(paths.State + "/findings.json")

	for _, args := range [][]string{{"ack", ""}, {"ack", "foo"}, {"show", ""}, {"fix", "web", ""}, {"pick", ""}} {
		code, out, _ := runCLI(t, append(args, "--json")...)
		if e := decode(t, out); code != 1 || e.Error == nil || e.Error.Code != "CLI_USAGE_INVALID" {
			t.Errorf("%v: exit %d: %s", args, code, out)
		}
	}
	if after, _ := os.ReadFile(paths.State + "/findings.json"); string(after) != string(before) {
		t.Error("findings.json changed")
	}
}

func TestAckMovesSnoozeAndConvertsAccepted(t *testing.T) {
	paths := newConfigHome(t)
	withServers(t, paths, false, "web", "db")
	putFindings(t, paths, openVuln("web"), openVuln("db"))
	first, _ := day(30)
	second, secondAt := day(60)

	ack := func(args ...string) (int, string) {
		code, out, errOut := runCLI(t, append([]string{"ack", testCVE, "--json"}, args...)...)
		if code != 0 {
			t.Logf("stderr: %s", errOut)
		}
		return code, out
	}
	state := func(server string) *findings.Finding {
		f := loadFindings(t, paths).Find(testFindingID(server))
		if f == nil {
			t.Fatalf("%s: finding gone", server)
		}
		return f
	}

	if code, out := ack("--until", first, "--server", "web"); code != 0 {
		t.Fatalf("snooze web: exit %d: %s", code, out)
	}
	if code, out := ack("--server", "db"); code != 0 { // accept db
		t.Fatalf("accept db: exit %d: %s", code, out)
	}

	// One command moves web's snooze and turns db's accepted risk into a snooze.
	if code, out := ack("--until", second, "--reason", "waiting for the maintenance window"); code != 0 {
		t.Fatalf("move: exit %d: %s", code, out)
	}
	for _, server := range []string{"web", "db"} {
		f := state(server)
		if f.State != findings.StateSnoozed || !f.SnoozedUntil.Equal(secondAt) {
			t.Errorf("%s: state %s until %v, want snoozed until %v", server, f.State, f.SnoozedUntil, secondAt)
		}
	}

	// The same command again changes nothing, and says so instead of "no open finding".
	code, out := ack("--until", second)
	e := decode(t, out)
	var res map[string]int
	if code != 0 || !e.OK || json.Unmarshal(e.Data, &res) != nil || res["acknowledged"] != 0 || res["already"] != 2 {
		t.Fatalf("repeat: exit %d: %s", code, out)
	}
	if got := state("web").AckReason; got != "waiting for the maintenance window" {
		t.Errorf("moving the date without --reason lost the reason: %q", got)
	}

	// And a snooze can go back to an accepted risk.
	if code, out := ack(); code != 0 {
		t.Fatalf("accept: exit %d: %s", code, out)
	}
	if f := state("web"); f.State != findings.StateAccepted || !f.SnoozedUntil.IsZero() {
		t.Errorf("web: state %s until %v, want accepted", f.State, f.SnoozedUntil)
	}

	// Nothing open for the CVE at all is still FINDINGS_NOT_FOUND.
	code, out, _ = runCLI(t, "ack", "CVE-2030-0001", "--json")
	if e := decode(t, out); code != 1 || e.Error == nil || e.Error.Code != "FINDINGS_NOT_FOUND" {
		t.Errorf("unknown CVE: exit %d: %s", code, out)
	}
}

func TestAckUntilMustBeInTheFuture(t *testing.T) {
	paths := newConfigHome(t)
	withServers(t, paths, false, "web")
	putFindings(t, paths, openVuln("web"))
	today, _ := day(0)

	for _, until := range []string{"2020-01-01", today} {
		code, out, _ := runCLI(t, "ack", testCVE, "--until", until, "--json")
		if e := decode(t, out); code != 1 || e.Error == nil || e.Error.Code != "CLI_USAGE_INVALID" {
			t.Errorf("--until %s: exit %d: %s", until, code, out)
		}
	}
	if f := loadFindings(t, paths).Find(testFindingID("web")); f.State != findings.StateNew {
		t.Errorf("state = %s, want it untouched", f.State)
	}

	tomorrow, at := day(1)
	if code, out, _ := runCLI(t, "ack", testCVE, "--until", tomorrow, "--json"); code != 0 {
		t.Fatalf("--until %s: exit %d: %s", tomorrow, code, out)
	}
	if f := loadFindings(t, paths).Find(testFindingID("web")); f.State != findings.StateSnoozed || !f.SnoozedUntil.Equal(at) {
		t.Errorf("state %s until %v, want snoozed until %v", f.State, f.SnoozedUntil, at)
	}
}

func TestUnknownServerIsAnError(t *testing.T) {
	paths := newConfigHome(t)
	withServers(t, paths, false, "web")
	putFindings(t, paths, openVuln("web"))

	for _, args := range [][]string{{"findings", "--server", "wbe"}, {"ack", testCVE, "--server", "wbe"}} {
		code, out, _ := runCLI(t, append(args, "--json")...)
		if e := decode(t, out); code != 1 || e.Error == nil || e.Error.Code != "SERVER_NOT_FOUND" {
			t.Errorf("%v: exit %d: %s", args, code, out)
		}
	}
	if f := loadFindings(t, paths).Find(testFindingID("web")); f.State != findings.StateNew {
		t.Errorf("state = %s, want it untouched", f.State)
	}
	if code, out, _ := runCLI(t, "findings", "--server", "web", "--json"); code != 0 || !strings.Contains(out, testCVE) {
		t.Errorf("a configured server must still work: exit %d: %s", code, out)
	}
}
