package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/kugesh-rajasekaran/make-it-safer/internal/config"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/findings"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/secret"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/vault"
)

// withServers saves a config with the given servers (and this computer on or off).
func withServers(t *testing.T, paths config.Paths, thisComputer bool, names ...string) {
	t.Helper()
	cfg := config.Default()
	cfg.ThisComputer = thisComputer
	for _, n := range names {
		cfg.Servers = append(cfg.Servers, config.Server{Name: n, Host: "203.0.113.5", Port: 22, AdminSSH: "root@203.0.113.5"})
	}
	if err := cfg.Save(paths.Config); err != nil {
		t.Fatal(err)
	}
}

const testCVE = "CVE-2024-6387"

func testFindingID(server string) string {
	return findings.MakeID(server, findings.KindVulnerability, testCVE)
}

// seedFindings records an accepted finding and a completed check per server.
func seedFindings(t *testing.T, paths config.Paths, servers ...string) {
	t.Helper()
	err := findings.Update(paths, func(st *findings.Store) error {
		for _, s := range servers {
			st.Findings = append(st.Findings, &findings.Finding{
				ID: testFindingID(s), Server: s, Kind: findings.KindVulnerability, CVE: testCVE,
				Priority: findings.Urgent, State: findings.StateAccepted, AckReason: "test",
			})
			st.Checked[s] = time.Now()
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func loadFindings(t *testing.T, paths config.Paths) *findings.Store {
	t.Helper()
	st, err := findings.Load(paths)
	if err != nil {
		t.Fatal(err)
	}
	return st
}

func TestServerRemoveForgetsFindings(t *testing.T) {
	paths := newConfigHome(t)
	withServers(t, paths, false, "web", "db")
	seedFindings(t, paths, "web", "db")

	code, out, errOut := runCLI(t, "server", "remove", "web", "--forget", "--json")
	if e := decode(t, out); code != 0 || !e.OK {
		t.Fatalf("exit %d: %s %s", code, out, errOut)
	}

	st := loadFindings(t, paths)
	if st.Find(testFindingID("web")) != nil {
		t.Error("the removed server's finding is still stored")
	}
	if _, ok := st.Checked["web"]; ok {
		t.Error("the removed server still has a last-checked time")
	}
	if st.Find(testFindingID("db")) == nil || st.Checked["db"].IsZero() {
		t.Error("removing web also dropped db's findings")
	}

	// Added again under the same name, it starts fresh: the old
	// acknowledgement does not carry over.
	again := &findings.Finding{ID: testFindingID("web"), Server: "web", Kind: findings.KindVulnerability, CVE: testCVE, Priority: findings.Urgent}
	ch := st.Merge("web", []*findings.Finding{again}, []findings.Kind{findings.KindVulnerability}, time.Now())
	if len(ch.New) != 1 || again.State != findings.StateNew {
		t.Errorf("after re-adding: new=%d state=%q, want one new finding", len(ch.New), again.State)
	}
}

func TestServerRemoveThisComputer(t *testing.T) {
	local := config.LocalName()
	for _, tc := range []struct {
		name string
		args []string
	}{
		{"forget", []string{"server", "remove", local, "--forget", "--json"}},
		// Without --forget a real server is reached through ssh; this computer never is.
		{"without forget", []string{"server", "remove", local, "--json"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			paths := newConfigHome(t)
			withServers(t, paths, true, "web")
			seedFindings(t, paths, "web", local)

			code, out, errOut := runCLI(t, tc.args...)
			if e := decode(t, out); code != 0 || !e.OK {
				t.Fatalf("exit %d: %s %s", code, out, errOut)
			}
			cfg, err := config.Load(paths.Config)
			if err != nil {
				t.Fatal(err)
			}
			if cfg.ThisComputer {
				t.Error("this computer is still checked")
			}
			if len(cfg.Servers) != 1 || cfg.Servers[0].Name != "web" {
				t.Errorf("servers = %+v, want only web", cfg.Servers)
			}
			st := loadFindings(t, paths)
			if st.Find(testFindingID(local)) != nil {
				t.Error("this computer's finding is still stored")
			}
			if st.Find(testFindingID("web")) == nil {
				t.Error("web's finding was dropped")
			}
		})
	}
}

func TestServerRemoveThisComputerWhenOff(t *testing.T) {
	paths := newConfigHome(t)
	withServers(t, paths, false, "web")
	before, _ := os.ReadFile(paths.Config)

	code, out, _ := runCLI(t, "server", "remove", config.LocalName(), "--forget", "--json")
	if e := decode(t, out); code != 1 || e.Error == nil || e.Error.Code != "SERVER_NOT_FOUND" {
		t.Fatalf("exit %d: %s", code, out)
	}
	if after, _ := os.ReadFile(paths.Config); string(after) != string(before) {
		t.Error("config.yaml changed")
	}
}

func TestServerListJSONKeys(t *testing.T) {
	paths := newConfigHome(t)
	withServers(t, paths, false, "web")

	code, out, _ := runCLI(t, "server", "list", "--json")
	e := decode(t, out)
	var rows []map[string]json.RawMessage
	if code != 0 || json.Unmarshal(e.Data, &rows) != nil || len(rows) != 1 {
		t.Fatalf("exit %d: %s", code, out)
	}
	want := map[string]string{"name": `"web"`, "host": `"203.0.113.5"`, "port": "22", "admin_ssh": `"root@203.0.113.5"`}
	if len(rows[0]) != len(want) {
		t.Errorf("keys = %v, want exactly %v", rows[0], want)
	}
	for k, v := range want {
		if got := string(rows[0][k]); got != v {
			t.Errorf("%q = %s, want %s", k, got, v)
		}
	}
}

// TestServerAddUnlocksBeforeChangingAnything runs without a terminal, so the
// passphrase can't be asked. That has to fail before the server is contacted
// (port 1 on localhost would answer "unreachable") and before config.yaml changes.
func TestServerAddUnlocksBeforeChangingAnything(t *testing.T) {
	paths := newConfigHome(t)
	if _, err := vault.Create(paths.KeyFile, paths.PublicKey, secret.Bytes("correct horse battery"),
		vault.Params{Time: 1, MemoryKiB: 8 << 10, Threads: 1}); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(paths.Config)

	code, out, _ := runCLI(t, "server", "add", "web", "--host", "127.0.0.1", "--port", "1",
		"--admin", "root@127.0.0.1", "--fingerprint", "SHA256:none", "--yes", "--json")
	if e := decode(t, out); code != 1 || e.Error == nil || e.Error.Code != "VAULT_TTY_REQUIRED" {
		t.Fatalf("exit %d: %s", code, out)
	}
	if after, _ := os.ReadFile(paths.Config); string(after) != string(before) {
		t.Error("config.yaml changed")
	}
}

func TestFirstCheckHint(t *testing.T) {
	for _, tc := range []struct {
		name string
		json bool
		want string
	}{
		{"human", false, "mis check web"},
		{"json", true, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out, errOut bytes.Buffer
			a := newApp(nil, nil, &out, &errOut)
			a.json = tc.json
			a.hintFirstCheck("web")
			if tc.want == "" && errOut.Len() > 0 || !strings.Contains(errOut.String(), tc.want) {
				t.Errorf("stderr = %q, want it to contain %q", errOut.String(), tc.want)
			}
			if out.Len() > 0 {
				t.Errorf("stdout = %q, want nothing (stdout carries the result)", out.String())
			}
		})
	}
}
