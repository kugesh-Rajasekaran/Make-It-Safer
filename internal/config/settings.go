package config

import (
	"fmt"
	"math"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/kugesh-rajasekaran/make-it-safer/internal/apperr"
)

// Kind says how mis config edits a setting.
type Kind int

// Kinds of settings.
const (
	KindText   Kind = iota // you type a value
	KindToggle             // yes/no: Enter flips it
	KindChoice             // you pick one of Choices
)

// Choice is one option of a KindChoice setting.
type Choice struct {
	Value string // as stored and as mis config set takes it
	Label string // as people read it
}

// Setting is one value in config.yaml that mis config reads and changes.
// Servers are not settings: mis server add/remove manages them.
type Setting struct {
	Key      string // dotted name for mis config get/set, e.g. rules.remind.high
	Group    string // heading on the mis config screen
	Label    string
	Kind     Kind
	Choices  []Choice // KindChoice
	Question string   // KindText: what to type
	Hidden   bool     // only through get/set (terminal.command is asked for when you pick "custom")

	value func(*Config) string // as get prints it and set takes it
	show  func(*Config) string // as people read it
	set   func(*Config, string) error
}

// Value returns the setting as mis config get prints it.
func (s Setting) Value(c *Config) string { return s.value(c) }

// Show returns the setting in words, e.g. "every 4h".
func (s Setting) Show(c *Config) string {
	if s.show != nil {
		return s.show(c)
	}
	return s.value(c)
}

// Set parses value into c. The whole configuration must still be valid
// afterwards; on any error c is left unchanged.
func (s Setting) Set(c *Config, value string) error {
	value = strings.TrimSpace(value)
	if s.Kind == KindChoice && !hasChoice(s.Choices, value) {
		values := make([]string, len(s.Choices))
		for i, ch := range s.Choices {
			values[i] = ch.Value
		}
		return apperr.New(apperr.ConfigInvalid, s.Key+": pick one of: "+strings.Join(values, ", "))
	}
	next := *c
	if err := s.set(&next, value); err != nil {
		return apperr.New(apperr.ConfigInvalid, s.Key+": "+err.Error())
	}
	if err := next.Validate(); err != nil {
		return err
	}
	*c = next
	return nil
}

// Lookup finds a setting by its key.
func Lookup(key string) (Setting, bool) {
	for _, s := range Settings() {
		if s.Key == key {
			return s, true
		}
	}
	return Setting{}, false
}

// Settings lists everything mis config can change, in screen order.
func Settings() []Setting {
	r := func(c *Config) *Rules { return &c.Rules }
	thisComputer := toggle("this_computer", "Also check "+strings.ToLower(LocalLabel()[:1])+LocalLabel()[1:],
		func(c *Config) *bool { return &c.ThisComputer })
	thisComputer.Group = "Devices"
	return []Setting{
		thisComputer,
		{Key: "rules.alert_when.min_severity", Group: "Alerts", Label: "Alert for fixable vulnerabilities from CVSS",
			Question: "CVSS score (0–10)",
			value:    func(c *Config) string { return score(r(c).AlertWhen.MinSeverity) },
			set: func(c *Config, v string) (err error) {
				r(c).AlertWhen.MinSeverity, err = parseScore(v)
				return err
			}},
		{Key: "rules.alert_when.min_epss", Label: "…or when the exploit chance (EPSS) is at least",
			Question: "Exploit chance in % (0–100)",
			value:    func(c *Config) string { return percent(r(c).AlertWhen.MinEPSS) },
			set: func(c *Config, v string) (err error) {
				r(c).AlertWhen.MinEPSS, err = parsePercent(v)
				return err
			}},
		toggle("rules.alert_when.actively_exploited", "Always alert actively exploited (CISA KEV)",
			func(c *Config) *bool { return &r(c).AlertWhen.ActivelyExploited }),
		{Key: "rules.unfixed", Label: "Alert when there's no fix yet", Kind: KindChoice,
			Choices: []Choice{{UnfixedUrgentOnly, "only when urgent"}, {UnfixedAll, "always"}},
			value:   func(c *Config) string { return r(c).Unfixed },
			set:     func(c *Config, v string) error { r(c).Unfixed = v; return nil }},
		{Key: "rules.early_warning", Group: "Early warnings", Label: "Heads-ups before your distro confirms",
			Question: `CVSS score (0–10), or "off"`,
			value: func(c *Config) string {
				if !r(c).EarlyWarning.Enabled {
					return "off"
				}
				return score(r(c).EarlyWarning.MinSeverity)
			},
			show: func(c *Config) string {
				if !r(c).EarlyWarning.Enabled {
					return "off"
				}
				return "on, from CVSS " + score(r(c).EarlyWarning.MinSeverity)
			},
			set: func(c *Config, v string) error {
				if strings.EqualFold(v, "off") {
					r(c).EarlyWarning.Enabled = false
					return nil
				}
				n, err := parseScore(v)
				if err != nil {
					return fmt.Errorf(`type a number from 0 to 10, or "off"`)
				}
				r(c).EarlyWarning.Enabled, r(c).EarlyWarning.MinSeverity = true, n
				return nil
			}},
		remind("rules.remind.urgent", "Reminders", "Remind urgent findings", func(c *Config) *Duration { return &r(c).Remind.Urgent }),
		remind("rules.remind.high", "", "Remind high findings", func(c *Config) *Duration { return &r(c).Remind.High }),
		remind("rules.remind.normal", "", "Summary of normal findings", func(c *Config) *Duration { return &r(c).Remind.Normal }),
		check("new_cves", "Checks", "Look for brand-new CVEs (early warnings)", func(c *Config) *Duration { return &c.Schedule.NewCVEs }),
		check("data_changes", "", "Look for new data from Debian, Ubuntu, CISA", func(c *Config) *Duration { return &c.Schedule.DataChanges }),
		check("full_check", "", "Check everything again, incl. "+strings.ToLower(LocalLabel()[:1])+LocalLabel()[1:],
			func(c *Config) *Duration { return &c.Schedule.FullCheck }),
		check("servers", "", "Read your servers' installed packages", func(c *Config) *Duration { return &c.Schedule.Servers }),
		list("rules.ignore.packages", "Ignore", "Never alert for these packages", "Packages, separated by commas (type none to clear the list)", false,
			func(c *Config) *[]string { return &r(c).Ignore.Packages }),
		list("rules.ignore.cves", "", "Never alert for these CVEs", "CVE IDs, separated by commas (type none to clear the list)", true,
			func(c *Config) *[]string { return &r(c).Ignore.CVEs }),
		{Key: "terminal.app", Group: "Notifications", Label: "Terminal for fix sessions", Kind: KindChoice,
			Choices: terminalChoices(),
			value:   func(c *Config) string { return c.Terminal.App },
			show: func(c *Config) string {
				if c.Terminal.App == "custom" {
					return "custom: " + c.Terminal.Command
				}
				return labelOf(terminalChoices(), c.Terminal.App)
			},
			set: func(c *Config, v string) error { c.Terminal.App = v; return nil }},
		{Key: "terminal.command", Label: "Custom terminal command", Hidden: true,
			Question: "Command that opens a script, with {script} (e.g. foot {script}). Separate parts with spaces; quotes are not understood",
			value:    func(c *Config) string { return c.Terminal.Command },
			set:      func(c *Config, v string) error { c.Terminal.Command = v; return nil }},
		toggle("notifications.sound", "Play a sound with alerts", func(c *Config) *bool { return &c.Notifications.Sound }),
		{Key: "notifications.max_buttons", Label: "Buttons per notification (servers + All)",
			Question: "A number from 2 to 10",
			value:    func(c *Config) string { return strconv.Itoa(c.Notifications.MaxButtons) },
			set: func(c *Config, v string) (err error) {
				c.Notifications.MaxButtons, err = strconv.Atoi(v)
				if err != nil {
					return fmt.Errorf("type a whole number from 2 to 10")
				}
				return nil
			}},
	}
}

func toggle(key, label string, field func(*Config) *bool) Setting {
	return Setting{Key: key, Label: label, Kind: KindToggle,
		value: func(c *Config) string { return yesNo(*field(c)) },
		set: func(c *Config, v string) error {
			switch strings.ToLower(v) {
			case "yes", "true", "on":
				*field(c) = true
			case "no", "false", "off":
				*field(c) = false
			default:
				return fmt.Errorf(`type "yes" or "no"`)
			}
			return nil
		}}
}

func remind(key, group, label string, field func(*Config) *Duration) Setting {
	return interval(key, group, label, time.Minute, field)
}

// check is one of the background service's timers (schedule.<name>).
func check(name, group, label string, field func(*Config) *Duration) Setting {
	return interval("schedule."+name, group, label, ScheduleMinimums[name], field)
}

// interval is a duration setting of at least lowest, shown as "every 4h".
func interval(key, group, label string, lowest time.Duration, field func(*Config) *Duration) Setting {
	return Setting{Key: key, Group: group, Label: label,
		Question: fmt.Sprintf("Every (at least %s, e.g. 30m, 4h, 1d)", FormatDuration(lowest)),
		value:    func(c *Config) string { return FormatDuration(time.Duration(*field(c))) },
		show:     func(c *Config) string { return "every " + FormatDuration(time.Duration(*field(c))) },
		set: func(c *Config, v string) error {
			d, err := ParseDuration(v)
			if err != nil || d < lowest {
				return fmt.Errorf("use a duration of at least %s, like 30m, 4h or 1d", FormatDuration(lowest))
			}
			*field(c) = Duration(d)
			return nil
		}}
}

func list(key, group, label, question string, upper bool, field func(*Config) *[]string) Setting {
	return Setting{Key: key, Group: group, Label: label, Question: question,
		value: func(c *Config) string { return strings.Join(*field(c), ",") },
		show: func(c *Config) string {
			if len(*field(c)) == 0 {
				return "none"
			}
			return strings.Join(*field(c), ", ")
		},
		set: func(c *Config, v string) error {
			items := []string{}
			for _, item := range strings.Split(v, ",") {
				if item = strings.TrimSpace(item); item != "" {
					items = append(items, item)
				}
			}
			// "none" empties the list; it is never an item (there is no package called none).
			if i := slices.IndexFunc(items, func(item string) bool { return strings.EqualFold(item, "none") }); i >= 0 {
				if len(items) > 1 {
					return fmt.Errorf(`"none" empties the list; don't combine it with other items`)
				}
				items = items[:0]
			}
			if upper {
				for i := range items {
					items[i] = strings.ToUpper(items[i])
				}
			}
			*field(c) = items
			return nil
		}}
}

// TerminalChoices are the terminal apps offered on an OS (runtime.GOOS).
func TerminalChoices(goos string) []string {
	if goos == "darwin" {
		return []string{"default", "iterm2", "ghostty", "kitty", "alacritty", "wezterm", "custom"}
	}
	return []string{"default", "gnome-terminal", "kgx", "konsole", "xfce4-terminal", "kitty", "alacritty", "wezterm", "ghostty", "xterm", "custom"}
}

// DefaultTerminalName says what "default" opens on an OS.
func DefaultTerminalName(goos string) string {
	if goos == "darwin" {
		return "Terminal"
	}
	return "your desktop's terminal"
}

func terminalChoices() []Choice {
	var out []Choice
	for _, app := range TerminalChoices(runtime.GOOS) {
		label := app
		switch app {
		case "default":
			label = "default (" + DefaultTerminalName(runtime.GOOS) + ")"
		case "custom":
			label = "custom command"
		}
		out = append(out, Choice{Value: app, Label: label})
	}
	return out
}

func hasChoice(choices []Choice, value string) bool {
	for _, c := range choices {
		if c.Value == value {
			return true
		}
	}
	return false
}

func labelOf(choices []Choice, value string) string {
	for _, c := range choices {
		if c.Value == value {
			return c.Label
		}
	}
	return value
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func score(f float64) string { return strconv.FormatFloat(f, 'f', 1, 64) }

func percent(f float64) string {
	return strconv.FormatFloat(math.Round(f*10000)/100, 'f', -1, 64) + "%"
}

func parseScore(v string) (float64, error) {
	f, err := strconv.ParseFloat(v, 64)
	if err != nil || f < 0 || f > 10 || math.IsNaN(f) {
		return 0, fmt.Errorf("type a number from 0 to 10")
	}
	return math.Round(f*10) / 10, nil
}

func parsePercent(v string) (float64, error) {
	f, err := strconv.ParseFloat(strings.TrimSuffix(v, "%"), 64)
	if err != nil || f < 0 || f > 100 || math.IsNaN(f) {
		return 0, fmt.Errorf("type a percentage from 0 to 100")
	}
	return f / 100, nil
}
