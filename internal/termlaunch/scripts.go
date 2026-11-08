// Package termlaunch opens your terminal with an SSH session where the fix
// is already typed in, or with a Make-It-Safer command (unlock, pick, …).
//
// Everything put into scripts is either our own text or validated values,
// always shell-quoted; banner lines are also stripped of control characters.
package termlaunch

import (
	"encoding/base64"
	"fmt"
	"strings"
	"unicode"

	"github.com/kugesh-rajasekaran/make-it-safer/internal/config"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/findings"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/fixcmd"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/sshx"
)

const maxBannerFindings = 8

// Banner describes what the fix is for, shown above the prompt.
func Banner(server string, fs []*findings.Finding, cmd *fixcmd.Command) []string {
	lines := []string{"Make-It-Safer · " + server}
	for i, f := range fs {
		if i == maxBannerFindings {
			lines = append(lines, fmt.Sprintf("  …and %d more", len(fs)-i))
			break
		}
		switch f.Kind {
		case findings.KindReboot:
			lines = append(lines, "  restart needed: a newer kernel is installed than the one running")
		case findings.KindEndOfLife:
			lines = append(lines, "  "+f.Installed+": security support ended")
		default:
			fixed := "no fix yet"
			if f.HasFix() {
				fixed = "fixed in " + f.Fixed
			}
			line := fmt.Sprintf("  %s  %s  installed %s → %s", f.CVE, f.Source, f.Installed, fixed)
			if f.KEV {
				line += "  (actively exploited)"
			}
			lines = append(lines, line)
		}
	}
	for _, n := range cmd.Notes {
		lines = append(lines, "  ⚠ "+n)
	}
	return lines
}

// RemoteScript is the bash script run on the server. It prints the banner
// and puts the command on the prompt line: Enter runs it, you can edit it
// first, or Ctrl-C skips to a normal shell. Nothing runs without Enter.
func RemoteScript(banner []string, cmd *fixcmd.Command) string {
	var b strings.Builder
	b.WriteString("printf '\\n'\n")
	for _, line := range banner {
		fmt.Fprintf(&b, "printf '%%s\\n' %s\n", quote(printable(line)))
	}
	if cmd.Empty() {
		b.WriteString("printf '%s\\n' 'Nothing to run automatically; here is a normal shell.'\n")
	} else {
		fmt.Fprintf(&b, "if [ \"$(id -u)\" -eq 0 ]; then c=%s; else c=%s; fi\n", quote(cmd.Root), quote(cmd.Sudo))
		b.WriteString("printf '%s\\n\\n' 'Enter = run · edit it first · Ctrl-C = skip to a normal shell'\n")
		// The script survives Ctrl-C and always ends in a normal shell. The
		// line is read, and the command run, in subshells where Ctrl-C works
		// as usual: a trapped Ctrl-C would not stop read -e.
		b.WriteString("trap : INT\n")
		b.WriteString("c=$(trap - INT; read -r -e -i \"$c\" -p \"$(id -un)@$(hostname -s):~\\$ \" c && printf '%s' \"$c\") || c=\n")
		b.WriteString("if [ -n \"$c\" ]; then (trap - INT; eval \"$c\"); fi\n")
	}
	b.WriteString("exec \"${SHELL:-/bin/bash}\" -l\n")
	return b.String()
}

// RemoteCommand wraps a script for `ssh -t host COMMAND`. The script
// travels base64-encoded, so no quoting can break on the way.
func RemoteCommand(script string) string {
	return `bash -c "$(printf %s ` + base64.StdEncoding.EncodeToString([]byte(script)) + ` | base64 -d)"`
}

// FixLauncher is the local script your terminal runs: it deletes itself and
// logs in with your own ssh client and admin login.
func FixLauncher(s config.Server, remoteCommand string) string {
	args := sshx.AdminArgs(s, remoteCommand)
	q := make([]string, len(args))
	for i, a := range args {
		q[i] = quote(a)
	}
	return "#!/bin/sh\n# Make-It-Safer: SSH session to " + quote(printable(s.Name)) + " with the fix typed in. This file deletes itself.\n" +
		"rm -f -- \"$0\"\nexec ssh " + strings.Join(q, " ") + "\n"
}

// LocalLauncher is a local script that runs a mis command, then waits for
// Enter so you can read the result.
func LocalLauncher(mis string, args ...string) string {
	q := []string{quote(mis)}
	for _, a := range args {
		q = append(q, quote(a))
	}
	return "#!/bin/sh\n# Make-It-Safer. This file deletes itself.\nrm -f -- \"$0\"\n" + strings.Join(q, " ") +
		"\nprintf '\\n%s' 'Press Enter to close this window.'\nread -r _\n"
}

func quote(s string) string { return fixcmd.Quote(s) }

// printable drops control characters (escape codes) from banner text.
func printable(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, s)
}

// LocalFixLauncher runs a fix script on this computer, without SSH (a Linux
// desktop that checks itself). It deletes itself.
func LocalFixLauncher(script string) string {
	return "#!/bin/sh\n# Make-It-Safer: the fix for this computer, typed in. This file deletes itself.\n" +
		"rm -f -- \"$0\"\nexec " + RemoteCommand(script) + "\n"
}
