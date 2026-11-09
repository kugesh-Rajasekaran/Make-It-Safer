package cli

import (
	"testing"
	"time"

	"github.com/kugesh-rajasekaran/make-it-safer/internal/config"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/inventory"
)

// mis doctor judges a server by when its package list was read, not by when
// it was last matched.
func TestPackageListTimes(t *testing.T) {
	paths := config.PathsAt(t.TempDir())
	if err := paths.Ensure(); err != nil {
		t.Fatal(err)
	}
	readAt := time.Date(2026, 11, 5, 9, 0, 0, 0, time.UTC)
	inv := &inventory.Inventory{CollectedAt: readAt, OSID: "ubuntu", OSVersion: "24.04", Kernel: "6.8.0-49-generic"}
	if err := inventory.Save(paths, "web", inv); err != nil {
		t.Fatal(err)
	}
	servers := []config.Server{{Name: "web"}, {Name: "db"}} // db has no package list yet
	got := packageListTimes(paths, servers)
	if len(got) != 1 || !got["web"].Equal(readAt) {
		t.Fatalf("packageListTimes = %v, want only web at %v", got, readAt)
	}
}
