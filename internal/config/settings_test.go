package config

import (
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/kugesh-rajasekaran/make-it-safer/internal/apperr"
)

func TestEverySettingRoundTrips(t *testing.T) {
	seen := map[string]bool{}
	for _, s := range Settings() {
		if seen[s.Key] {
			t.Fatalf("duplicate key %s", s.Key)
		}
		seen[s.Key] = true
		if s.Label == "" || (s.Kind == KindText && s.Question == "") || (s.Kind == KindChoice && len(s.Choices) == 0) {
			t.Errorf("%s: missing label, question or choices", s.Key)
		}
		c := Default()
		before := c
		if err := s.Set(&c, s.Value(&c)); err != nil && s.Key != "terminal.command" {
			t.Errorf("%s: setting its own value %q failed: %v", s.Key, s.Value(&c), err)
		}
		if !reflect.DeepEqual(c, before) {
			t.Errorf("%s: setting its own value changed the config", s.Key)
		}
	}
}

func TestSetAndShow(t *testing.T) {
	cases := []struct {
		key, in, value, show string
	}{
		{"rules.alert_when.min_severity", "5", "5.0", "5.0"},
		{"rules.alert_when.min_severity", "6.25", "6.3", "6.3"},
		{"rules.alert_when.min_epss", "25%", "25%", "25%"},
		{"rules.alert_when.min_epss", "1.5", "1.5%", "1.5%"},
		{"rules.alert_when.actively_exploited", "no", "no", "no"},
		{"rules.unfixed", "all", "all", "all"},
		{"rules.early_warning", "off", "off", "off"},
		{"rules.early_warning", "8", "8.0", "on, from CVSS 8.0"},
		{"rules.remind.high", "10m", "10m", "every 10m"},
		{"rules.remind.normal", "2d", "2d", "every 2d"},
		{"rules.ignore.packages", " linux-firmware , tzdata ", "linux-firmware,tzdata", "linux-firmware, tzdata"},
		{"rules.ignore.cves", "cve-2024-6387", "CVE-2024-6387", "CVE-2024-6387"},
		{"rules.ignore.cves", "", "", "none"},
		{"terminal.app", "default", "default", "default (" + DefaultTerminalName(runtime.GOOS) + ")"},
		{"notifications.sound", "off", "no", "no"},
		{"notifications.max_buttons", "5", "5", "5"},
	}
	for _, tc := range cases {
		t.Run(tc.key+"="+tc.in, func(t *testing.T) {
			s, ok := Lookup(tc.key)
			if !ok {
				t.Fatalf("no setting %s", tc.key)
			}
			c := Default()
			if err := s.Set(&c, tc.in); err != nil {
				t.Fatal(err)
			}
			if got := s.Value(&c); got != tc.value {
				t.Errorf("value = %q, want %q", got, tc.value)
			}
			if got := s.Show(&c); got != tc.show {
				t.Errorf("show = %q, want %q", got, tc.show)
			}
			if err := c.Validate(); err != nil {
				t.Errorf("result doesn't validate: %v", err)
			}
		})
	}
	c := Default()
	s, _ := Lookup("rules.remind.urgent")
	if err := s.Set(&c, "90m"); err != nil || time.Duration(c.Rules.Remind.Urgent) != 90*time.Minute {
		t.Fatalf("90m: %v, %v", err, c.Rules.Remind.Urgent)
	}
}

func TestSetRejectsAndLeavesConfigUnchanged(t *testing.T) {
	cases := []struct{ key, in, reason string }{
		{"schedule.new_cves", "1m", "at least 5m"},
		{"schedule.data_changes", "5m", "at least 10m"},
		{"schedule.full_check", "10m", "at least 30m"},
		{"schedule.servers", "30m", "at least 1h"},
		{"schedule.servers", "30d", "between 1h and 7d"},
		{"rules.alert_when.min_severity", "11", "0 to 10"},
		{"rules.alert_when.min_severity", "high", "0 to 10"},
		{"rules.alert_when.min_epss", "150%", "0 to 100"},
		{"rules.alert_when.actively_exploited", "maybe", `"yes" or "no"`},
		{"rules.unfixed", "sometimes", "pick one of"},
		{"rules.early_warning", "on", `"off"`},
		{"rules.remind.high", "2x", "at least 1m"},
		{"rules.remind.high", "30s", "at least 1m"},
		{"rules.ignore.packages", "Bad_Name", "not a package name"},
		{"rules.ignore.packages", "tzdata,none", "empties the list"},
		{"rules.ignore.cves", "CVE-2024-6387, NONE", "empties the list"},
		{"schedule.servers", "187649984473771d", "at least 1h"},
		{"rules.ignore.cves", "CVE-1", "not a CVE ID"},
		{"terminal.app", "notepad", "pick one of"},
		{"terminal.app", "custom", "{script}"}, // needs terminal.command first
		{"notifications.max_buttons", "1", "between 2 and 10"},
		{"notifications.max_buttons", "three", "whole number"},
	}
	for _, tc := range cases {
		t.Run(tc.key+"="+tc.in, func(t *testing.T) {
			s, _ := Lookup(tc.key)
			c := Default()
			before := c
			err := s.Set(&c, tc.in)
			if !apperr.Is(err, apperr.ConfigInvalid) || !strings.Contains(err.Error(), tc.reason) {
				t.Fatalf("got %v, want CONFIG_INVALID mentioning %q", err, tc.reason)
			}
			if !reflect.DeepEqual(c, before) {
				t.Fatal("a rejected value changed the config")
			}
		})
	}
}

func TestCustomTerminalNeedsItsCommand(t *testing.T) {
	c := Default()
	command, _ := Lookup("terminal.command")
	app, _ := Lookup("terminal.app")
	if err := command.Set(&c, "foot {script}"); err != nil {
		t.Fatal(err)
	}
	if err := app.Set(&c, "custom"); err != nil {
		t.Fatal(err)
	}
	if got := app.Show(&c); got != "custom: foot {script}" {
		t.Fatalf("show = %q", got)
	}
	if !command.Hidden || app.Hidden {
		t.Fatal("terminal.command should be hidden from the screen; terminal.app shown")
	}
}

func TestLookupUnknown(t *testing.T) {
	if _, ok := Lookup("rules.nope"); ok {
		t.Fatal("found a setting that doesn't exist")
	}
}

func TestIgnoreListsCanBeEmptied(t *testing.T) {
	for _, tc := range []struct {
		key, list string
		items     func(*Config) []string
	}{
		{"rules.ignore.packages", "tzdata,linux-firmware", func(c *Config) []string { return c.Rules.Ignore.Packages }},
		{"rules.ignore.cves", "CVE-2024-6387", func(c *Config) []string { return c.Rules.Ignore.CVEs }},
	} {
		for _, in := range []string{"none", "None", " NONE ", ""} {
			t.Run(tc.key+"="+in, func(t *testing.T) {
				s, _ := Lookup(tc.key)
				c := Default()
				if err := s.Set(&c, tc.list); err != nil {
					t.Fatal(err)
				}
				if err := s.Set(&c, in); err != nil {
					t.Fatal(err)
				}
				if got := tc.items(&c); got == nil || len(got) != 0 {
					t.Errorf("items = %#v, want an empty list (not a list holding \"none\")", got)
				}
				if err := c.Validate(); err != nil {
					t.Errorf("result doesn't validate: %v", err)
				}
			})
		}
	}
}
