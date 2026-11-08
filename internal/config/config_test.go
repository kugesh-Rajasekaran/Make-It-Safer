package config

import (
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kugesh-rajasekaran/make-it-safer/internal/apperr"
)

func validServer() Server {
	return Server{Name: "ovh-web-1", Host: "203.0.113.10", Port: 22, AdminSSH: "ubuntu@203.0.113.10"}
}

func TestDefaultIsValid(t *testing.T) {
	cfg := Default()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("default config is invalid: %v", err)
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	cfg := Default()
	cfg.Servers = []Server{validServer(), {Name: "other-1", Host: "example.org", Port: 2222, AdminSSH: "ovh1"}}
	cfg.Rules.Ignore.CVEs = []string{"CVE-2024-6387"}
	if err := cfg.Save(path); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("config saved with mode %o, want 600", info.Mode().Perm())
	}
	got, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Servers) != 2 || got.Servers[1] != cfg.Servers[1] {
		t.Fatalf("servers did not round-trip: %+v", got.Servers)
	}
	if got.Rules.Remind.Normal != Duration(7*24*time.Hour) || got.Rules.Ignore.CVEs[0] != "CVE-2024-6387" {
		t.Fatalf("rules did not round-trip: %+v", got.Rules)
	}
	data, _ := os.ReadFile(path)
	if !strings.Contains(string(data), "normal: 7d") {
		t.Fatalf("durations should be written compactly, got:\n%s", data)
	}
}

func TestLoadKeepsDefaultsForMissingFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	writePrivate(t, path, "version: 1\nrules:\n  alert_when:\n    min_severity: 8\n")
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Rules.AlertWhen.MinSeverity != 8 {
		t.Fatalf("min_severity = %v, want 8", cfg.Rules.AlertWhen.MinSeverity)
	}
	if !cfg.Rules.AlertWhen.ActivelyExploited || cfg.Rules.EarlyWarning.MinSeverity != 9 || cfg.Terminal.App != "default" {
		t.Fatalf("defaults were lost: %+v", cfg)
	}
}

func TestLoadRejectsUnknownFieldsAndBadValues(t *testing.T) {
	cases := map[string]string{
		"typo":         "version: 1\nrulez: {}\n",
		"bad duration": "version: 1\nrules:\n  remind:\n    urgent: soon\n",
		"bad version":  "version: 2\n",
	}
	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.yaml")
			writePrivate(t, path, content)
			_, err := Load(path)
			if !apperr.Is(err, apperr.ConfigInvalid) {
				t.Fatalf("Load() error = %v, want %s", err, apperr.ConfigInvalid)
			}
		})
	}
}

func TestLoadMissingFile(t *testing.T) {
	_, err := Load(filepath.Join(t.TempDir(), "config.yaml"))
	if !apperr.Is(err, apperr.ConfigNotInitialized) {
		t.Fatalf("Load() error = %v, want %s", err, apperr.ConfigNotInitialized)
	}
}

func TestValidateRejects(t *testing.T) {
	cases := map[string]func(*Config){
		"uppercase name":           func(c *Config) { c.Servers[0].Name = "Web1" },
		"host like an ssh option":  func(c *Config) { c.Servers[0].Host = "-oProxyCommand=sh" },
		"admin like an ssh option": func(c *Config) { c.Servers[0].AdminSSH = "-oProxyCommand=sh" },
		"admin with spaces":        func(c *Config) { c.Servers[0].AdminSSH = "ubuntu@host; rm -rf /" },
		"port zero":                func(c *Config) { c.Servers[0].Port = 0 },
		"duplicate names":          func(c *Config) { c.Servers = append(c.Servers, c.Servers[0]) },
		"severity above 10":        func(c *Config) { c.Rules.AlertWhen.MinSeverity = 11 },
		"epss above 1":             func(c *Config) { c.Rules.AlertWhen.MinEPSS = 2 },
		"unknown unfixed policy":   func(c *Config) { c.Rules.Unfixed = "never" },
		"bad ignored cve":          func(c *Config) { c.Rules.Ignore.CVEs = []string{"CVE-24-1"} },
		"bad ignored package":      func(c *Config) { c.Rules.Ignore.Packages = []string{"Bad Name"} },
		"reminder too often":       func(c *Config) { c.Rules.Remind.Urgent = Duration(time.Second) },
		"unknown terminal":         func(c *Config) { c.Terminal.App = "hyper" },
		"custom without {script}":  func(c *Config) { c.Terminal = Terminal{App: "custom", Command: "foot"} },
		"too few buttons":          func(c *Config) { c.Notifications.MaxButtons = 1 },
		"too many buttons":         func(c *Config) { c.Notifications.MaxButtons = 11 },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := Default()
			cfg.Servers = []Server{validServer()}
			mutate(&cfg)
			if err := cfg.Validate(); !apperr.Is(err, apperr.ConfigInvalid) {
				t.Fatalf("Validate() = %v, want %s", err, apperr.ConfigInvalid)
			}
		})
	}
}

func TestDurations(t *testing.T) {
	for in, want := range map[string]time.Duration{"7d": 7 * 24 * time.Hour, "4h": 4 * time.Hour, "90m": 90 * time.Minute} {
		got, err := ParseDuration(in)
		if err != nil || got != want {
			t.Errorf("ParseDuration(%q) = %v, %v; want %v", in, got, err, want)
		}
		if FormatDuration(got) != in {
			t.Errorf("FormatDuration(%v) = %q, want %q", got, FormatDuration(got), in)
		}
	}
	for _, bad := range []string{"xd", "-1d", "soon"} {
		if _, err := ParseDuration(bad); err == nil {
			t.Errorf("ParseDuration(%q) succeeded", bad)
		}
	}
}

func TestCheckPrivate(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "f")
	writePrivate(t, file, "x")
	if err := CheckPrivate(file); err != nil {
		t.Fatalf("0600 file rejected: %v", err)
	}
	if err := os.Chmod(file, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := CheckPrivate(file); !apperr.Is(err, apperr.ConfigPermissionsTooOpen) {
		t.Fatalf("0644 file: got %v", err)
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := CheckPrivate(dir); !apperr.Is(err, apperr.ConfigPermissionsTooOpen) {
		t.Fatalf("0755 dir: got %v", err)
	}
	if err := CheckPrivate(filepath.Join(dir, "missing")); err != nil {
		t.Fatalf("missing path should be fine, got %v", err)
	}
}

func TestPathsEnsureAndCheck(t *testing.T) {
	t.Setenv(EnvHome, filepath.Join(t.TempDir(), "mis"))
	p, err := DefaultPaths()
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Ensure(); err != nil {
		t.Fatal(err)
	}
	if err := p.CheckPermissions(); err != nil {
		t.Fatalf("fresh layout rejected: %v", err)
	}
	if err := p.RequireInitialized(); !apperr.Is(err, apperr.ConfigNotInitialized) {
		t.Fatalf("RequireInitialized() = %v before init", err)
	}
	if err := os.Chmod(p.Home, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := p.CheckPermissions(); !apperr.Is(err, apperr.ConfigPermissionsTooOpen) {
		t.Fatalf("loose home accepted: %v", err)
	}
}

func TestWriteFileAtomic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	for _, content := range []string{"first", "second"} {
		if err := WriteFileAtomic(path, []byte(content)); err != nil {
			t.Fatal(err)
		}
		got, _ := os.ReadFile(path)
		if string(got) != content {
			t.Fatalf("content = %q, want %q", got, content)
		}
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatalf("temporary files left behind: %v", entries)
	}
}

func TestLockSerialises(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".lock")
	unlock, err := Lock(path)
	if err != nil {
		t.Fatal(err)
	}
	var acquired atomic.Bool
	done := make(chan struct{})
	go func() {
		release, err := Lock(path)
		if err == nil {
			acquired.Store(true)
			release()
		}
		close(done)
	}()
	time.Sleep(100 * time.Millisecond)
	if acquired.Load() {
		t.Fatal("second lock acquired while the first was held")
	}
	unlock()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("second lock never acquired")
	}
	if !acquired.Load() {
		t.Fatal("second lock failed")
	}
}

func writePrivate(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}
