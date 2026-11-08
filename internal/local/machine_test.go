//go:build localmachine

// Reads the real computer running the test. Run by hand:
// go test -tags localmachine -v ./internal/local/

package local

import (
	"context"
	"testing"
	"time"
)

func TestCollectThisComputer(t *testing.T) {
	inv, err := Collect(context.Background(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%s %s, kernel %s, %s, %d packages", inv.OSID, inv.OSVersion, inv.Kernel, inv.Arch, len(inv.Packages))
	if inv.Mac != nil {
		t.Logf("Safari %s, %d Apple updates, %d outdated Homebrew packages", inv.Mac.Safari, len(inv.Mac.Updates), len(inv.Mac.Homebrew))
		for _, u := range inv.Mac.Updates {
			t.Logf("  update: %s (%s) restart=%v", u.Title, u.Version, u.Restart)
		}
	}
}
