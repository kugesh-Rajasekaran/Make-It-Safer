package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/kugesh-rajasekaran/make-it-safer/internal/apperr"
)

// Config is config.yaml. It never holds secrets.
type Config struct {
	Version       int           `yaml:"version"`
	Servers       []Server      `yaml:"servers"`
	Rules         Rules         `yaml:"rules"`
	Terminal      Terminal      `yaml:"terminal"`
	Notifications Notifications `yaml:"notifications"`
}

// Server is a VPS registered with Make-It-Safer.
type Server struct {
	Name     string `yaml:"name"`      // short name shown in notifications, e.g. ovh-web-1
	Host     string `yaml:"host"`      // IP address or hostname
	Port     int    `yaml:"port"`      // SSH port
	AdminSSH string `yaml:"admin_ssh"` // your own login as typed after `ssh`: user@host or an ~/.ssh/config alias
}

// Rules decide which vulnerabilities alert you and how often you're reminded.
type Rules struct {
	AlertWhen    AlertWhen    `yaml:"alert_when"`
	EarlyWarning EarlyWarning `yaml:"early_warning"`
	Unfixed      string       `yaml:"unfixed"` // UnfixedUrgentOnly or UnfixedAll
	Ignore       Ignore       `yaml:"ignore"`
	Remind       Remind       `yaml:"remind"`
}

// AlertWhen sets the thresholds for confirmed vulnerabilities.
type AlertWhen struct {
	ActivelyExploited bool    `yaml:"actively_exploited"` // always alert for CISA KEV entries
	MinSeverity       float64 `yaml:"min_severity"`       // CVSS score
	MinEPSS           float64 `yaml:"min_epss"`           // probability of exploitation, 0–1
}

// EarlyWarning controls unconfirmed heads-ups from the CVE List.
type EarlyWarning struct {
	Enabled     bool    `yaml:"enabled"`
	MinSeverity float64 `yaml:"min_severity"`
}

// Ignore lists packages and CVEs you never want alerts for.
type Ignore struct {
	Packages []string `yaml:"packages"`
	CVEs     []string `yaml:"cves"`
}

// Remind sets how often open findings are repeated, by priority.
type Remind struct {
	Urgent Duration `yaml:"urgent"`
	High   Duration `yaml:"high"`
	Normal Duration `yaml:"normal"`
}

// Terminal is the app that opens when you click a server button.
type Terminal struct {
	App     string `yaml:"app"`               // one of TerminalApps
	Command string `yaml:"command,omitempty"` // only for "custom", e.g. "foot {script}"
}

// Notifications tunes desktop notifications.
type Notifications struct {
	MaxButtons int  `yaml:"max_buttons"` // server buttons + "All servers…"
	Sound      bool `yaml:"sound"`
}

// Values for Rules.Unfixed.
const (
	UnfixedUrgentOnly = "urgent_only" // alert without a fix only when urgent
	UnfixedAll        = "all"         // alert for unfixed vulnerabilities like any other
)

// TerminalApps are the supported values for Terminal.App.
var TerminalApps = []string{
	"default", "terminal", "iterm2", "ghostty", "gnome-terminal", "kgx", "konsole",
	"xfce4-terminal", "kitty", "alacritty", "wezterm", "xterm", "custom",
}

// Default returns the configuration `mis init` starts from.
func Default() Config {
	return Config{
		Version: 1,
		Rules: Rules{
			AlertWhen:    AlertWhen{ActivelyExploited: true, MinSeverity: 7.0, MinEPSS: 0.10},
			EarlyWarning: EarlyWarning{Enabled: true, MinSeverity: 9.0},
			Unfixed:      UnfixedUrgentOnly,
			Ignore:       Ignore{Packages: []string{}, CVEs: []string{}},
			Remind: Remind{
				Urgent: Duration(4 * time.Hour),
				High:   Duration(24 * time.Hour),
				Normal: Duration(7 * 24 * time.Hour),
			},
		},
		Terminal:      Terminal{App: "default"},
		Notifications: Notifications{MaxButtons: 3, Sound: true},
	}
}

// Load reads and validates config.yaml. Fields missing from the file keep
// their defaults; unknown fields are an error so typos don't go unnoticed.
func Load(path string) (*Config, error) {
	if err := CheckPrivate(path); err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path) //nolint:gosec // path comes from our own Paths layout
	if errors.Is(err, fs.ErrNotExist) {
		return nil, apperr.New(apperr.ConfigNotInitialized, "Make-It-Safer isn't set up yet; run: mis init")
	}
	if err != nil {
		return nil, apperr.Wrap(apperr.ConfigUnreadable, err, "cannot read "+path)
	}
	cfg := Default()
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil && !errors.Is(err, io.EOF) {
		return nil, apperr.Wrap(apperr.ConfigInvalid, err, path+" is not valid")
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

const fileHeader = `# Make-It-Safer configuration. It holds no secrets.
# Servers are managed with "mis server add/remove"; rules, terminal and
# notifications are yours to edit. See docs/design.md §4.4.
`

// Save validates the configuration and writes it atomically with mode 0600.
func (c *Config) Save(path string) error {
	if err := c.Validate(); err != nil {
		return err
	}
	var buf bytes.Buffer
	buf.WriteString(fileHeader)
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(c); err != nil {
		return apperr.Wrap(apperr.ConfigWriteFailed, err, "cannot encode configuration")
	}
	if err := enc.Close(); err != nil {
		return apperr.Wrap(apperr.ConfigWriteFailed, err, "cannot encode configuration")
	}
	return WriteFileAtomic(path, buf.Bytes())
}

// Server returns the server with the given name.
func (c *Config) Server(name string) (Server, bool) {
	i := slices.IndexFunc(c.Servers, func(s Server) bool { return s.Name == name })
	if i < 0 {
		return Server{}, false
	}
	return c.Servers[i], true
}

var (
	serverNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}$`)
	hostPattern       = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.:-]{0,252}$`)
	adminSSHPattern   = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._-]{0,63}(@[A-Za-z0-9][A-Za-z0-9.:-]{0,252})?$`)
	cvePattern        = regexp.MustCompile(`^CVE-[0-9]{4}-[0-9]{4,}$`)
	packagePattern    = regexp.MustCompile(`^[a-z0-9][a-z0-9+.-]*$`)
)

// Validate checks a server entry. Names, hosts and logins can never start
// with "-", so they can't be mistaken for ssh options.
func (s Server) Validate() error {
	switch {
	case !serverNamePattern.MatchString(s.Name):
		return fmt.Errorf("name %q: use lowercase letters, digits, '.', '_' or '-' (max 63)", s.Name)
	case !hostPattern.MatchString(s.Host):
		return fmt.Errorf("host %q is not a valid hostname or IP address", s.Host)
	case s.Port < 1 || s.Port > 65535:
		return fmt.Errorf("port %d must be between 1 and 65535", s.Port)
	case !adminSSHPattern.MatchString(s.AdminSSH):
		return fmt.Errorf("admin_ssh %q must look like user@host or an ~/.ssh/config alias", s.AdminSSH)
	}
	return nil
}

// Validate checks the whole configuration and reports every problem at once.
func (c *Config) Validate() error {
	var problems []string
	add := func(format string, args ...any) { problems = append(problems, fmt.Sprintf(format, args...)) }

	if c.Version != 1 {
		add("version must be 1 (got %d)", c.Version)
	}
	seen := map[string]bool{}
	for i, s := range c.Servers {
		if err := s.Validate(); err != nil {
			add("servers[%d]: %v", i, err)
		}
		if seen[s.Name] {
			add("servers[%d]: duplicate name %q", i, s.Name)
		}
		seen[s.Name] = true
	}

	r := c.Rules
	if r.AlertWhen.MinSeverity < 0 || r.AlertWhen.MinSeverity > 10 {
		add("rules.alert_when.min_severity must be between 0 and 10")
	}
	if r.AlertWhen.MinEPSS < 0 || r.AlertWhen.MinEPSS > 1 {
		add("rules.alert_when.min_epss must be between 0 and 1")
	}
	if r.EarlyWarning.MinSeverity < 0 || r.EarlyWarning.MinSeverity > 10 {
		add("rules.early_warning.min_severity must be between 0 and 10")
	}
	if r.Unfixed != UnfixedUrgentOnly && r.Unfixed != UnfixedAll {
		add("rules.unfixed must be %q or %q", UnfixedUrgentOnly, UnfixedAll)
	}
	for _, p := range r.Ignore.Packages {
		if !packagePattern.MatchString(p) {
			add("rules.ignore.packages: %q is not a package name", p)
		}
	}
	for _, id := range r.Ignore.CVEs {
		if !cvePattern.MatchString(id) {
			add("rules.ignore.cves: %q is not a CVE ID like CVE-2024-6387", id)
		}
	}
	for name, d := range map[string]Duration{"urgent": r.Remind.Urgent, "high": r.Remind.High, "normal": r.Remind.Normal} {
		if time.Duration(d) < time.Minute {
			add("rules.remind.%s must be at least 1m", name)
		}
	}

	if !slices.Contains(TerminalApps, c.Terminal.App) {
		add("terminal.app %q is not one of: %s", c.Terminal.App, strings.Join(TerminalApps, ", "))
	}
	if c.Terminal.App == "custom" && !strings.Contains(c.Terminal.Command, "{script}") {
		add(`terminal.command must contain "{script}" when terminal.app is "custom"`)
	}
	if c.Notifications.MaxButtons < 2 || c.Notifications.MaxButtons > 10 {
		add("notifications.max_buttons must be between 2 and 10")
	}

	if len(problems) > 0 {
		slices.Sort(problems)
		return apperr.New(apperr.ConfigInvalid, "config.yaml: "+strings.Join(problems, "; "))
	}
	return nil
}

// Duration is a time.Duration that also reads and writes whole days ("7d").
type Duration time.Duration

// MarshalYAML writes durations like "4h" or "7d".
func (d Duration) MarshalYAML() (any, error) { return FormatDuration(time.Duration(d)), nil }

// UnmarshalYAML reads durations like "90m", "4h" or "7d".
func (d *Duration) UnmarshalYAML(n *yaml.Node) error {
	v, err := ParseDuration(n.Value)
	if err != nil {
		return err
	}
	*d = Duration(v)
	return nil
}

// ParseDuration is time.ParseDuration plus a "d" (days) suffix.
func ParseDuration(s string) (time.Duration, error) {
	if days, ok := strings.CutSuffix(s, "d"); ok {
		n, err := strconv.Atoi(days)
		if err != nil || n < 0 {
			return 0, fmt.Errorf("invalid duration %q", s)
		}
		return time.Duration(n) * 24 * time.Hour, nil
	}
	return time.ParseDuration(s)
}

// FormatDuration prints whole days, hours or minutes compactly.
func FormatDuration(d time.Duration) string {
	switch {
	case d > 0 && d%(24*time.Hour) == 0:
		return fmt.Sprintf("%dd", d/(24*time.Hour))
	case d > 0 && d%time.Hour == 0:
		return fmt.Sprintf("%dh", d/time.Hour)
	case d > 0 && d%time.Minute == 0:
		return fmt.Sprintf("%dm", d/time.Minute)
	default:
		return d.String()
	}
}
