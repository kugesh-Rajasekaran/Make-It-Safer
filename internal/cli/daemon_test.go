package cli

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/kugesh-rajasekaran/make-it-safer/internal/apperr"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/config"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/notify"
)

// A second `mis daemon` must refuse before it creates the notifier: on macOS
// that rebinds the helper's socket, cutting the running service off from it.
func TestSecondDaemonRefusesBeforeTakingTheNotifier(t *testing.T) {
	dir, err := os.MkdirTemp("", "mis") // short path: Unix socket paths are limited
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	t.Setenv(config.EnvHome, filepath.Join(dir, "h"))
	paths, err := config.DefaultPaths()
	if err != nil {
		t.Fatal(err)
	}
	if err := paths.Ensure(); err != nil {
		t.Fatal(err)
	}
	running, err := net.Listen("unix", paths.Socket) // a daemon that answers
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = running.Close() }()

	var out bytes.Buffer
	a := newApp([]string{"daemon", "--json"}, nil, &out, &out)
	a.desktop = func(context.Context, config.Paths, *slog.Logger) notify.Notifier {
		t.Error("the second daemon created a notifier")
		return notify.NewLog(slog.New(slog.NewTextHandler(io.Discard, nil)))
	}
	if code := a.execute([]string{"daemon", "--json"}); code != 1 {
		t.Fatalf("exit code %d", code)
	}
	if e := decode(t, out.String()); e.Error == nil || e.Error.Code != apperr.DaemonAlreadyRunning {
		t.Fatalf("envelope = %s", out.String())
	}
}
