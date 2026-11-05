package notify

import (
	"context"
	"log/slog"

	"github.com/kugesh-rajasekaran/make-it-safer/internal/config"
)

// Desktop returns the notifier for this computer: the macOS helper app, or
// D-Bus on Linux. Until those exist (milestone M5) it logs only.
func Desktop(_ context.Context, _ config.Paths, log *slog.Logger) Notifier {
	return NewLog(log)
}
