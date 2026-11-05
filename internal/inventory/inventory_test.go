package inventory

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kugesh-rajasekaran/make-it-safer/internal/apperr"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/config"
)

var now = time.Date(2026, 11, 5, 8, 0, 0, 0, time.UTC)

func TestParseRealOutput(t *testing.T) {
	cases := map[string]struct{ osID, version string }{
		"ubuntu-24.04.txt": {"ubuntu", "24.04"},
		"debian-12.txt":    {"debian", "12"},
	}
	for file, want := range cases {
		t.Run(file, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join("testdata", file))
			if err != nil {
				t.Fatal(err)
			}
			inv, err := Parse(data, now)
			if err != nil {
				t.Fatal(err)
			}
			if inv.OSID != want.osID || inv.OSVersion != want.version || !inv.Supported() {
				t.Fatalf("OS = %s %s", inv.OSID, inv.OSVersion)
			}
			if len(inv.Packages) < 50 || inv.Kernel == "" || inv.Arch != "amd64" {
				t.Fatalf("unexpected inventory: %d packages, kernel %q, arch %q", len(inv.Packages), inv.Kernel, inv.Arch)
			}
			for _, p := range inv.Packages {
				if strings.HasSuffix(p.Name, ":amd64") {
					t.Fatalf("native arch suffix not stripped: %s", p.Name)
				}
			}
			libc := inv.Binaries("glibc")
			if len(libc) == 0 || libc[0].Source != "glibc" {
				t.Fatalf("Binaries(glibc) = %+v", libc)
			}
			if len(inv.Sources()) >= len(inv.Packages) {
				t.Fatal("Sources() should group binary packages by source")
			}
		})
	}
}

const minimal = "mis-collect 1\nos-id=ubuntu\nos-version=24.04\nkernel=6.8.0-49-generic\narch=amd64\nreboot-required=yes\ngroups=mis\n" +
	"pkg\tii \tlibssl3t64:amd64\t3.0.13-0ubuntu3.16\topenssl\t3.0.13-0ubuntu3.16\n" +
	"pkg\tii \tlibc6:i386\t2.39-0ubuntu8.9\tglibc\t2.39-0ubuntu8.9\n" +
	"pkg\trc \told-package\t1.0\told-package\t1.0\n"

func TestParseMinimal(t *testing.T) {
	inv, err := Parse([]byte(minimal), now)
	if err != nil {
		t.Fatal(err)
	}
	if !inv.RebootRequired || len(inv.Groups) != 1 || inv.Groups[0] != "mis" {
		t.Fatalf("flags not parsed: %+v", inv)
	}
	if len(inv.Packages) != 2 {
		t.Fatalf("removed packages must be skipped, got %+v", inv.Packages)
	}
	if inv.Packages[0].Name != "libssl3t64" || inv.Packages[1].Name != "libc6:i386" {
		t.Fatalf("names = %q, %q (native arch stripped, foreign arch kept)", inv.Packages[0].Name, inv.Packages[1].Name)
	}
}

func TestParseRejects(t *testing.T) {
	replace := func(old, new string) string { return strings.Replace(minimal, old, new, 1) }
	cases := map[string]struct {
		input string
		code  string
	}{
		"not collector output":  {"uid=999(mis) gid=999(mis)\n", apperr.InventoryInvalid},
		"empty":                 {"", apperr.InventoryInvalid},
		"no packages":           {"mis-collect 1\nos-id=ubuntu\nos-version=24.04\nkernel=6.8\n", apperr.InventoryInvalid},
		"unknown field":         {replace("arch=amd64", "shell=bash"), apperr.InventoryInvalid},
		"duplicate field":       {replace("arch=amd64", "os-id=debian"), apperr.InventoryInvalid},
		"escape in kernel":      {replace("kernel=6.8.0-49-generic", "kernel=6.8\x1b[2J"), apperr.InventoryInvalid},
		"command in version":    {replace("3.0.13-0ubuntu3.16\topenssl", "1.0;rm -rf /\topenssl"), apperr.InventoryInvalid},
		"space in package name": {replace("libssl3t64:amd64", "lib ssl"), apperr.InventoryInvalid},
		"too few columns":       {replace("\topenssl\t3.0.13-0ubuntu3.16", ""), apperr.InventoryInvalid},
		"bad status":            {replace("pkg\tii ", "pkg\tzz "), apperr.InventoryInvalid},
		"bad group":             {replace("groups=mis", "groups=mis Sudo!"), apperr.InventoryInvalid},
		"too large":             {minimal + strings.Repeat("x", MaxBytes), apperr.InventoryTooLarge},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse([]byte(tc.input), now); !apperr.Is(err, tc.code) {
				t.Fatalf("Parse() = %v, want %s", err, tc.code)
			}
		})
	}
}

func TestSaveLoadRemove(t *testing.T) {
	paths := config.PathsAt(t.TempDir())
	if err := paths.Ensure(); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(paths, "web-1"); !apperr.Is(err, apperr.InventoryNotFound) {
		t.Fatalf("Load() before Save = %v", err)
	}
	inv, err := Parse([]byte(minimal), now)
	if err != nil {
		t.Fatal(err)
	}
	if err := Save(paths, "web-1", inv); err != nil {
		t.Fatal(err)
	}
	got, err := Load(paths, "web-1")
	if err != nil || len(got.Packages) != 2 || !got.CollectedAt.Equal(now) {
		t.Fatalf("Load() = %+v, %v", got, err)
	}
	if err := Remove(paths, "web-1"); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(paths, "web-1"); !apperr.Is(err, apperr.InventoryNotFound) {
		t.Fatal("inventory still there after Remove")
	}
}

// FuzzParse checks that hostile output never crashes the parser and that
// whatever it accepts matches the field patterns.
func FuzzParse(f *testing.F) {
	f.Add([]byte(minimal))
	for _, file := range []string{"ubuntu-24.04.txt", "debian-12.txt"} {
		if data, err := os.ReadFile(filepath.Join("testdata", file)); err == nil {
			f.Add(data)
		}
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		inv, err := Parse(data, now)
		if err != nil {
			return
		}
		if !osIDPattern.MatchString(inv.OSID) || !kernelPattern.MatchString(inv.Kernel) {
			t.Fatalf("accepted invalid fields: %+v", inv)
		}
		for _, p := range inv.Packages {
			if !binaryPattern.MatchString(p.Name) || !versionPattern.MatchString(p.Version) ||
				!sourcePattern.MatchString(p.Source) || !versionPattern.MatchString(p.SourceVersion) {
				t.Fatalf("accepted invalid package: %+v", p)
			}
		}
	})
}
