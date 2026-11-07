package cli

import (
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/kugesh-rajasekaran/make-it-safer/internal/apperr"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/config"
)

func (a *app) configCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "config",
		Short: "Change settings: alert scores, reminders, terminal and notifications",
		Long: `Shows every setting in one list: ↑/↓ to move, Enter to change the highlighted
one, q to quit. Each change is saved right away.

For scripts and agents: mis config get [key] and mis config set <key> <value>.
Servers are changed with mis server, the passphrase with mis passphrase change.`,
		Args: cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error { return a.runConfig() },
	}
	cmd.AddCommand(&cobra.Command{
		Use: "get [key]", Short: "Print every setting, or one", Args: cobra.MaximumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error { return a.runConfigGet(args) },
	}, &cobra.Command{
		Use: "set <key> <value>", Short: "Change one setting", Args: cobra.ExactArgs(2),
		Example: "  mis config set rules.remind.high 10m\n  mis config set rules.ignore.packages linux-firmware,tzdata",
		RunE:    func(_ *cobra.Command, args []string) error { return a.runConfigSet(args[0], args[1]) },
	})
	return cmd
}

type settingValue struct {
	Key   string `json:"key"`
	Value string `json:"value"`
	Label string `json:"label,omitempty"`
}

func (a *app) runConfig() error {
	paths, cfg, err := a.setup()
	if err != nil {
		return err
	}
	if a.json || !a.interactive() {
		all := settingValues(cfg)
		return a.emit(all, func(w io.Writer) {
			printSettings(w, all)
			_, _ = fmt.Fprintln(w, "\nChange one with: mis config set <key> <value>")
		})
	}
	changes, err := a.configScreen(paths, cfg)
	if err != nil {
		return err
	}
	switch changes {
	case 0:
		a.say("No changes.\n")
	case 1:
		a.say("✓ 1 change saved.\n")
	default:
		a.say("✓ %d changes saved.\n", changes)
	}
	if changes > 0 {
		a.say("The background service picks this up within 15 minutes. New alert scores apply at its next check; to apply them now: mis check\n")
	}
	return nil
}

func (a *app) runConfigGet(args []string) error {
	_, cfg, err := a.setup()
	if err != nil {
		return err
	}
	if len(args) == 1 {
		s, err := lookupSetting(args[0])
		if err != nil {
			return err
		}
		v := settingValue{Key: s.Key, Value: s.Value(cfg)}
		return a.emit(v, func(w io.Writer) { _, _ = fmt.Fprintln(w, v.Value) })
	}
	all := settingValues(cfg)
	return a.emit(all, func(w io.Writer) { printSettings(w, all) })
}

func (a *app) runConfigSet(key, value string) error {
	paths, cfg, err := a.setup()
	if err != nil {
		return err
	}
	s, err := lookupSetting(key)
	if err != nil {
		return err
	}
	if err := s.Set(cfg, value); err != nil {
		return err
	}
	if err := cfg.Save(paths.Config); err != nil {
		return err
	}
	v := settingValue{Key: s.Key, Value: s.Value(cfg)}
	return a.emit(v, func(w io.Writer) { _, _ = fmt.Fprintf(w, "✓ %s = %s\n", v.Key, v.Value) })
}

func lookupSetting(key string) (config.Setting, error) {
	s, ok := config.Lookup(key)
	if !ok {
		return s, apperr.New(apperr.ConfigUnknownSetting, fmt.Sprintf("there's no setting %q; see them all with: mis config get", key))
	}
	return s, nil
}

func settingValues(cfg *config.Config) []settingValue {
	var all []settingValue
	for _, s := range config.Settings() {
		all = append(all, settingValue{Key: s.Key, Value: s.Value(cfg), Label: s.Label})
	}
	return all
}

func printSettings(w io.Writer, all []settingValue) {
	width := 0
	for _, v := range all {
		width = max(width, len(v.Key))
	}
	for _, v := range all {
		value := v.Value
		if value == "" {
			value = `""`
		}
		_, _ = fmt.Fprintf(w, "%-*s  %s\n", width, v.Key, value)
	}
}

// interactive reports whether mis talks to a person in a terminal.
func (a *app) interactive() bool {
	errFile, ok := a.stderr.(*os.File)
	return ok && a.stdin != nil && term.IsTerminal(int(a.stdin.Fd())) && term.IsTerminal(int(errFile.Fd()))
}
