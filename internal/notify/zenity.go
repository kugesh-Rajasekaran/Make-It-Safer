package notify

import (
	"strings"
)

// On Linux a Dialog opens with zenity (GNOME's dialog tool, also on most
// KDE desktops). Its text goes in with --no-markup, so feed text shows as it
// is, and each button is labelled with its server.

// zenityArgs are zenity's arguments for d.
func zenityArgs(d Dialog) []string {
	args := []string{"--info", "--no-markup", "--title=Make-It-Safer", "--width=520", "--ok-label=Close", "--text=" + dialogText(d)}
	for _, r := range d.Rows {
		if r.Button != nil {
			args = append(args, "--extra-button="+zenityLabel(r))
		}
	}
	return args
}

// zenityLabel is a row's button, e.g. "Update ovh-web-1 ✓". A single "_"
// would mark a keyboard shortcut and not show, so it is doubled.
func zenityLabel(r Row) string {
	label := r.Button.Title + " " + strings.ReplaceAll(r.Name, "_", "__")
	if r.Opened {
		label += " ✓"
	}
	return label
}

// zenityAction is the ID of the button zenity printed it was closed with;
// "" for Close or a closed window.
func zenityAction(d Dialog, out string) string {
	out = strings.TrimSuffix(out, "\n")
	for _, r := range d.Rows {
		if r.Button != nil && zenityLabel(r) == out {
			return r.Button.ID
		}
	}
	return ""
}

// dialogText is d as plain text.
func dialogText(d Dialog) string {
	lines := []string{d.Title, "Verdict: " + d.Verdict}
	if len(d.Facts) > 0 {
		lines = append(lines, "", "What it is")
		for _, f := range d.Facts {
			sep := ": "
			if strings.HasSuffix(f.Label, "?") {
				sep = " "
			}
			lines = append(lines, f.Label+sep+f.Value)
		}
	}
	if d.Fix != "" || d.Command != "" {
		lines = append(lines, "", "The fix", d.Fix)
		if d.Command != "" {
			lines = append(lines, d.Command)
		}
	}
	if len(d.Rows) > 0 {
		lines = append(lines, "", "What it affects")
		for _, r := range d.Rows {
			line := r.Name
			if r.Detail != "" {
				line += " · " + r.Detail
			}
			lines = append(lines, line)
			if r.Command != "" {
				lines = append(lines, "    "+r.Command)
			}
		}
	}
	return strings.Join(lines, "\n")
}
