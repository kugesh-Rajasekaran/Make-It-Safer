package notify

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/kugesh-rajasekaran/make-it-safer/internal/config"
)

// Without the helper app, status and doctor explain how to get it back. That
// has to work for someone who installed with the script: no checkout, no Go.
func TestDesktopWithoutHelperAppSaysHowToInstall(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	n := Desktop(context.Background(), config.PathsAt(t.TempDir()), slog.New(slog.NewTextHandler(io.Discard, nil)))
	got := n.Describe()
	for _, want := range []string{"not installed", "install script"} {
		if !strings.Contains(got, want) {
			t.Errorf("Describe() = %q, want it to contain %q", got, want)
		}
	}
}
