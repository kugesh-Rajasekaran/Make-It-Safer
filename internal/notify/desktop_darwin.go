package notify

import (
	"context"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/kugesh-rajasekaran/make-it-safer/internal/config"
)

// HelperApp is where the install script (or `make install`) puts the macOS helper app.
func HelperApp() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, "Applications", "Make-It-Safer Notifier.app")
}

// helperHint says how to get the helper app back. Most people installed with
// the script; `make install` needs a source checkout and the Go tools.
const helperHint = "run the install script again, or `make install` if you built from source"

// Desktop returns the macOS notifier: the helper app, launched in the
// background. Without the app, notifications only go to the log.
func Desktop(ctx context.Context, paths config.Paths, log *slog.Logger) Notifier {
	app := HelperApp()
	if _, err := os.Stat(app); err != nil {
		log.Warn("notifier", "status", "helper app missing", "path", app, "fix", helperHint)
		return &missing{Log: NewLog(log), reason: "macOS helper app not installed (" + helperHint + ")"}
	}
	sock := filepath.Join(paths.Home, "notify.sock")
	launch := func() error {
		return exec.Command("open", "-g", "-j", "-a", app, "--args", sock).Run() //nolint:gosec // our own helper app and socket path
	}
	h, err := NewHelper(ctx, sock, launch, log)
	if err != nil {
		log.Warn("notifier", "status", "error", "error", err)
		return &missing{Log: NewLog(log), reason: "macOS notifications unavailable: " + err.Error()}
	}
	return h
}

// missing logs notifications and explains why they don't appear.
type missing struct {
	*Log
	reason string
}

func (m *missing) Describe() string { return m.reason }
