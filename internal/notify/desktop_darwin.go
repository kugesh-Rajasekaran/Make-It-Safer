package notify

import (
	"context"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/kugesh-rajasekaran/make-it-safer/internal/config"
)

// HelperApp is where `make install` puts the macOS helper app.
func HelperApp() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, "Applications", "Make-It-Safer Notifier.app")
}

// Desktop returns the macOS notifier: the helper app, launched in the
// background. Without the app, notifications only go to the log.
func Desktop(ctx context.Context, paths config.Paths, log *slog.Logger) Notifier {
	app := HelperApp()
	if _, err := os.Stat(app); err != nil {
		log.Warn("notifier", "status", "helper app missing", "path", app, "fix", "run: make install")
		return &missing{Log: NewLog(log), reason: "macOS helper app not installed (run: make install)"}
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
