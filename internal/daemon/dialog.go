package daemon

import (
	"cmp"
	"maps"
	"slices"
	"strings"

	"github.com/kugesh-rajasekaran/make-it-safer/internal/apperr"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/explain"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/findings"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/inventory"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/notify"
)

// openDialog opens notification key's dialog. When the desktop can't show
// one (the macOS helper app isn't connected, zenity isn't installed),
// fallback runs instead: the terminal, as before.
func (d *Daemon) openDialog(key string, fallback func() error) error {
	err := d.showDialog(key, false)
	if err == nil {
		return nil
	}
	d.log.Info("dialog", "status", "not shown", "id", key, "error", err)
	return fallback()
}

// showDialog shows key's dialog; refresh updates it after one of its
// buttons.
func (d *Daemon) showDialog(key string, refresh bool) error {
	dl, ok := d.notifier.(notify.Dialoger)
	if !ok {
		return apperr.New(apperr.NotifyUnavailable, "this desktop can't show dialogs")
	}
	dg, err := d.dialog(key)
	if err != nil {
		return err
	}
	dg.Refresh = refresh
	return dl.ShowDialog(*dg)
}

// dialog is what notification key's dialog shows: the facts of its worst
// finding, the fix, and a row per server with its button (✓ once used).
func (d *Daemon) dialog(key string) (*notify.Dialog, error) {
	st, err := findings.Load(d.paths)
	if err != nil {
		return nil, err
	}
	group := openGroup(st, key)
	if len(group) == 0 {
		return nil, apperr.New(apperr.FixNothingToDo, "nothing open for "+key)
	}
	w := cmp.Or(explain.Worst(group), group[0])
	dg := &notify.Dialog{ID: key, Title: explain.Clean(title(w)), Verdict: explain.Verdict(w), Level: w.Priority.String(), Facts: explain.Facts(w)}
	button := "Update"
	switch {
	case isApple(w):
		update, described := apple(group)
		worst := cmp.Or(described, w) // in Apple's own words when it described one
		dg.Title, dg.Fix, button = explain.Clean(update), "Install it in System Settings › Software Update.", "Open Software Update"
		dg.Facts = append([]explain.Fact{{Label: "Worst of them", Value: worst.CVE}}, explain.Facts(worst)...)
	case w.Kind == findings.KindEarlyWarning:
		dg.Fix, button = "Not confirmed by your distro yet. Make-It-Safer tells you once it is, with the fix.", ""
	case w.Kind == findings.KindReboot:
		dg.Facts, button = []explain.Fact{{Label: "Why", Value: explain.Capitalize(explain.Clean(w.Summary))}}, "Restart"
	}

	d.mu.Lock()
	opened := maps.Clone(d.clicked[key]) // fix() writes the inner map; a nil map reads as empty
	d.mu.Unlock()
	var notes []string // e.g. Ubuntu Pro, restart afterwards
	for _, server := range servers(group) {
		r := notify.Row{Name: serverLabel(server), Detail: change(group, server), Opened: opened[server]}
		if inv, err := inventory.Load(d.paths, server); err == nil && button != "" {
			if _, cmd, err := fixFor(inv, st, server, key); err == nil && !cmd.Empty() {
				r.Command, notes = cmd.Sudo, append(notes, cmd.Notes...)
			}
			if inv.IsMac() || r.Command != "" {
				r.Button = &notify.Button{ID: "fix:" + server, Title: button}
			}
		}
		dg.Rows = append(dg.Rows, r)
	}
	if dg.Fix == "" {
		dg.Fix = button + " opens your terminal with this typed in (over SSH for a server). Nothing runs until you press Enter."
		if !slices.ContainsFunc(dg.Rows, func(r notify.Row) bool { return r.Button != nil }) {
			dg.Fix = "No fix from your distro yet. Make-It-Safer tells you when there is one."
		}
	}
	slices.Sort(notes)
	dg.Fix = strings.Join(append([]string{dg.Fix}, slices.Compact(notes)...), "\n")
	if !slices.ContainsFunc(dg.Rows, func(r notify.Row) bool { return r.Command != dg.Rows[0].Command }) {
		dg.Command = dg.Rows[0].Command // the same everywhere: shown once, under the fix
		for i := range dg.Rows {
			dg.Rows[i].Command = ""
		}
	}
	return dg, nil
}

// openGroup is the open findings of group key.
func openGroup(st *findings.Store, key string) []*findings.Finding {
	return slices.DeleteFunc(slices.Clone(st.Findings), func(f *findings.Finding) bool { return !f.Open() || groupKey(f) != key })
}

// servers lists the servers of fs, sorted.
func servers(fs []*findings.Finding) []string {
	var out []string
	for _, f := range fs {
		out = append(out, f.Server)
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// change says what the fix changes on server, e.g. "openssl
// 3.0.13-0ubuntu3.4 → 3.0.13-0ubuntu3.5"; for a restart, what runs now; for
// a heads-up, what may be affected.
func change(group []*findings.Finding, server string) string {
	var parts []string
	for _, f := range group {
		if f.Server != server {
			continue
		}
		name := f.Source
		if isApple(f) {
			name = map[string]string{"macos": "macOS", "safari": "Safari"}[f.Source]
		}
		part := name + " " + f.Installed + " → " + cmp.Or(f.Fixed, "no fix yet")
		switch f.Kind {
		case findings.KindReboot:
			part = "running kernel " + f.Installed
		case findings.KindEarlyWarning:
			part = "may be affected: " + name + " " + f.Installed
		}
		parts = append(parts, explain.Clean(part))
	}
	slices.Sort(parts)
	return strings.Join(slices.Compact(parts), ", ")
}
