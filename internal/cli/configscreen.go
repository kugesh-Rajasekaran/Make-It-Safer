package cli

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"unicode/utf8"

	"golang.org/x/term"

	"github.com/kugesh-rajasekaran/make-it-safer/internal/apperr"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/config"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/keyring"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/vault"
)

// The mis config screen: every setting in one list, screenRows at a time.
// ↑/↓ move, Enter changes the highlighted setting, q quits. Each change is
// saved right away and you come back to the same place in the list.

const screenRows = 10

type screenRow struct {
	group, label string
	setting      *config.Setting // nil: auto-unlock, which isn't in config.yaml
}

type screen struct {
	rows     []screenRow
	cur, top int
}

func newScreen(withAutoUnlock bool) *screen {
	var rows []screenRow
	group := ""
	for _, s := range config.Settings() {
		if s.Hidden {
			continue
		}
		if s.Group != "" {
			group = s.Group
		}
		rows = append(rows, screenRow{group: group, label: s.Label, setting: &s})
	}
	if withAutoUnlock {
		rows = append(rows, screenRow{group: "Unlock", label: "Unlock automatically at login"})
	}
	return &screen{rows: rows}
}

// move moves the highlight and scrolls it into view.
func (s *screen) move(by int) {
	s.cur = min(max(s.cur+by, 0), len(s.rows)-1)
	if s.cur < s.top {
		s.top = s.cur
	}
	if s.cur >= s.top+screenRows {
		s.top = s.cur - screenRows + 1
	}
}

// render draws the list; value gives each row's value in words.
func (s *screen) render(value func(screenRow) string, status string) string {
	var b strings.Builder
	b.WriteString(bold("Make-It-Safer settings") + "      " + dim("↑/↓ move · Enter change · q quit") + "\r\n\r\n")
	end := min(s.top+screenRows, len(s.rows))
	b.WriteString(more("↑", s.top))
	for i := s.top; i < end; i++ {
		r := s.rows[i]
		group := ""
		if i == s.top || s.rows[i-1].group != r.group {
			group = r.group
		}
		mark, val := "  ", value(r)
		if i == s.cur {
			mark, val = cyan("› "), cyan(bold(val))
		}
		b.WriteString(mark + dim(pad(group, 15)) + pad(r.label, 48) + val + "\r\n")
	}
	b.WriteString(more("↓", len(s.rows)-end))
	b.WriteString("\r\n" + status + "\r\n")
	return b.String()
}

func more(arrow string, n int) string {
	if n <= 0 {
		return "\r\n"
	}
	return strings.Repeat(" ", 17) + dim(fmt.Sprintf("%s %d more", arrow, n)) + "\r\n"
}

// configScreen runs the screen until you quit and returns how many changes
// were saved.
func (a *app) configScreen(paths config.Paths, cfg *config.Config) (int, error) {
	s := newScreen(keyring.Available())
	value := func(r screenRow) string {
		if r.setting == nil {
			return onOff(vault.AutoUnlockEnabled(paths.AutoKey))
		}
		return r.setting.Show(cfg)
	}
	status, changes := "", 0
	for {
		a.say("%s", clearScreen+s.render(value, status))
		k, err := a.readKey()
		if err != nil {
			return changes, err
		}
		switch k {
		case keyUp:
			s.move(-1)
			status = ""
		case keyDown:
			s.move(1)
			status = ""
		case keyQuit, keyEsc:
			return changes, nil
		case keyEnter:
			msg, changed, err := a.change(paths, cfg, s, value)
			if err != nil {
				return changes, err
			}
			if changed {
				changes++
			}
			status = msg
		}
	}
}

// change edits the highlighted row. It returns the status line and whether
// something was saved; an error means the input closed.
func (a *app) change(paths config.Paths, cfg *config.Config, s *screen, value func(screenRow) string) (string, bool, error) {
	row := s.rows[s.cur]
	if row.setting == nil {
		return a.changeAutoUnlock(paths)
	}
	set, next := *row.setting, *cfg
	switch set.Kind {
	case config.KindToggle:
		flipped := "yes"
		if set.Value(cfg) == "yes" {
			flipped = "no"
		}
		if err := set.Set(&next, flipped); err != nil {
			return failed(err), false, nil
		}
	case config.KindChoice:
		picked, ok, err := a.pick(s, value, set, set.Value(cfg))
		if err != nil || !ok || (picked == set.Value(cfg) && picked != "custom") {
			return dim("Not changed."), false, err
		}
		if err := a.askUntilValid(&next, func(c *config.Config) (bool, error) { return a.applyChoice(c, set, picked) }); err != nil {
			return "", false, err
		}
	default:
		changed := true
		err := a.askUntilValid(&next, func(c *config.Config) (bool, error) {
			answer, err := a.ask(set.Question, set.Value(c))
			if err != nil || answer == set.Value(c) {
				changed = false
				return true, err
			}
			return false, set.Set(c, answer)
		})
		if err != nil || !changed {
			return dim("Not changed."), false, err
		}
	}
	if err := next.Save(paths.Config); err != nil {
		return failed(err), false, nil
	}
	wasChecked := cfg.ThisComputer
	*cfg = next
	if err := forgetIfNoLongerChecked(paths, wasChecked, cfg); err != nil {
		return failed(err), true, nil
	}
	return green("✓ Saved: ") + set.Label + " → " + set.Show(cfg), true, nil
}

// askUntilValid runs try on a copy of c until it works, showing each
// problem. try returns done=true to stop without a change.
func (a *app) askUntilValid(c *config.Config, try func(*config.Config) (done bool, err error)) error {
	a.say(showCursor)
	for {
		trial := *c
		done, err := try(&trial)
		switch {
		case apperr.Is(err, apperr.CLIInputAborted):
			return err
		case done:
			return nil
		case err != nil:
			a.say("%s\r\n", red("✗ "+apperr.MessageOf(err)))
		default:
			*c = trial
			return nil
		}
	}
}

// applyChoice sets a picked choice; "custom" terminals also need their command.
func (a *app) applyChoice(c *config.Config, set config.Setting, picked string) (bool, error) {
	if picked == "custom" {
		command, _ := config.Lookup("terminal.command")
		answer, err := a.ask(command.Question, command.Value(c))
		if err != nil {
			return true, err
		}
		if err := command.Set(c, answer); err != nil {
			return false, err
		}
	}
	return false, set.Set(c, picked)
}

// pick shows the choices under the list: ↑/↓ to pick, Enter, Esc to cancel.
func (a *app) pick(s *screen, value func(screenRow) string, set config.Setting, current string) (string, bool, error) {
	i := 0
	for j, c := range set.Choices {
		if c.Value == current {
			i = j
		}
	}
	for {
		var b strings.Builder
		b.WriteString(set.Label + ":\r\n")
		for j, c := range set.Choices {
			mark, label := "  ", c.Label
			if j == i {
				mark, label = cyan("› "), cyan(bold(label))
			}
			if c.Value == current {
				label += dim("  (now)")
			}
			b.WriteString("  " + mark + label + "\r\n")
		}
		b.WriteString(dim("↑/↓ pick · Enter save · Esc cancel") + "\r\n")
		a.say("%s", clearScreen+s.render(value, "")+b.String())
		k, err := a.readKey()
		if err != nil {
			return "", false, err
		}
		switch k {
		case keyUp:
			i = max(i-1, 0)
		case keyDown:
			i = min(i+1, len(set.Choices)-1)
		case keyEnter:
			return set.Choices[i].Value, true, nil
		case keyEsc, keyQuit:
			return "", false, nil
		}
	}
}

func (a *app) changeAutoUnlock(paths config.Paths) (string, bool, error) {
	if vault.AutoUnlockEnabled(paths.AutoKey) {
		if err := autoUnlockOff(paths); err != nil {
			return failed(err), false, nil
		}
		return green("✓ Saved: ") + "auto-unlock off; after a restart, run mis unlock", true, nil
	}
	a.say(showCursor + "Turning on auto-unlock needs your passphrase once.\r\n")
	if _, err := a.autoUnlockOn(paths); err != nil {
		if apperr.Is(err, apperr.CLIInputAborted) {
			return dim("Not changed."), false, nil
		}
		return failed(err), false, nil
	}
	return green("✓ Saved: ") + "auto-unlock on; it unlocks itself when you log in", true, nil
}

type key int

const (
	keyNone key = iota
	keyUp
	keyDown
	keyEnter
	keyEsc
	keyQuit
)

// readKey reads one key press in raw mode, through the same buffer as
// line prompts so no typed input is lost between the two.
func (a *app) readKey() (key, error) {
	fd := int(a.stdin.Fd())
	old, err := term.MakeRaw(fd)
	if err != nil {
		return keyNone, apperr.Wrap(apperr.CLIInputAborted, err, "cannot read keys from the terminal")
	}
	a.say(hideCursor)
	defer func() {
		_ = term.Restore(fd, old)
		a.say(showCursor)
	}()
	if a.in == nil {
		a.in = bufio.NewReader(a.stdin)
	}
	return readKey(a.in)
}

func readKey(r *bufio.Reader) (key, error) {
	b, err := r.ReadByte()
	if err != nil {
		return keyNone, apperr.New(apperr.CLIInputAborted, "input ended")
	}
	switch b {
	case '\r', '\n':
		return keyEnter, nil
	case 'q', 'Q', 3, 4: // Ctrl-C and Ctrl-D quit too: raw mode delivers them as bytes
		return keyQuit, nil
	case 'k':
		return keyUp, nil
	case 'j':
		return keyDown, nil
	case 0x1b:
		if r.Buffered() == 0 {
			return keyEsc, nil // a lone Esc; arrows arrive as one burst
		}
		if b2, _ := r.ReadByte(); b2 != '[' && b2 != 'O' {
			return keyEsc, nil
		}
		switch b3, _ := r.ReadByte(); b3 {
		case 'A':
			return keyUp, nil
		case 'B':
			return keyDown, nil
		}
	}
	return keyNone, nil
}

// Terminal styling. NO_COLOR (https://no-color.org) turns colors off.
const (
	clearScreen = "\x1b[H\x1b[2J"
	hideCursor  = "\x1b[?25l"
	showCursor  = "\x1b[?25h"
)

var noColor = os.Getenv("NO_COLOR") != ""

func style(code, s string) string {
	if noColor {
		return s
	}
	return "\x1b[" + code + "m" + s + "\x1b[0m"
}

func bold(s string) string  { return style("1", s) }
func dim(s string) string   { return style("2", s) }
func red(s string) string   { return style("31", s) }
func green(s string) string { return style("32", s) }
func cyan(s string) string  { return style("36", s) }

func failed(err error) string { return red("✗ " + apperr.MessageOf(err)) }

func onOff(on bool) string {
	if on {
		return "on"
	}
	return "off"
}

// pad pads s with spaces to n characters (not bytes).
func pad(s string, n int) string {
	if c := utf8.RuneCountInString(s); c < n {
		return s + strings.Repeat(" ", n-c)
	}
	return s + " "
}
