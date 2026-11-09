package feeds

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestPruneDir(t *testing.T) {
	now := time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC)
	dir := t.TempDir()
	write := func(name string, age time.Duration) {
		t.Helper()
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(p, now.Add(-age), now.Add(-age)); err != nil {
			t.Fatal(err)
		}
	}
	day := 24 * time.Hour
	write("CVE-2026-0001.json", 40*day)
	write(".CVE-2026-0002.json.tmp-123", 31*day) // a leftover of an interrupted write
	write("CVE-2026-0003.json", 29*day)
	write("CVE-2026-0004.json", 0)
	if err := os.Mkdir(filepath.Join(dir, "sub"), 0o700); err != nil {
		t.Fatal(err)
	}

	removed, err := PruneDir(dir, 30*day, now)
	if err != nil || removed != 2 {
		t.Fatalf("PruneDir() = %d, %v; want 2 removed", removed, err)
	}
	var left []string
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		left = append(left, e.Name())
	}
	if len(left) != 3 || left[0] != "CVE-2026-0003.json" || left[1] != "CVE-2026-0004.json" || left[2] != "sub" {
		t.Fatalf("left behind: %v", left)
	}
	if n, err := PruneDir(filepath.Join(dir, "missing"), 30*day, now); n != 0 || err != nil {
		t.Fatalf("missing dir: %d, %v", n, err)
	}
}
