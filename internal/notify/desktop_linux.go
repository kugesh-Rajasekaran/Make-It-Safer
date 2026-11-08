package notify

import (
	"context"
	"log/slog"

	"github.com/kugesh-rajasekaran/make-it-safer/internal/config"
)

// Desktop returns the Linux notifier: freedesktop notifications over the
// D-Bus session bus. Without a desktop session, notifications only go to
// the log.
func Desktop(ctx context.Context, _ config.Paths, log *slog.Logger) Notifier {
	d, err := NewDBus(ctx, log)
	if err != nil {
		log.Warn("notifier", "status", "no desktop notifications", "error", err)
		return &missing{Log: NewLog(log), reason: "no desktop notifications (no D-Bus session; is the service running in your desktop session?)"}
	}
	return d
}

// missing logs notifications and explains why they don't appear.
type missing struct {
	*Log
	reason string
}

func (m *missing) Describe() string { return m.reason }
