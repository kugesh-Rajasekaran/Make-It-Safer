package local

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/kugesh-rajasekaran/make-it-safer/internal/inventory"
)

func TestParseSoftwareUpdate(t *testing.T) {
	out := []byte(`Software Update Tool

Finding available software
Software Update found the following new or updated software:
* Label: Safari27.2SequoiaAuto-27.2
	Title: Safari, Version: 27.2, Size: 238722KiB, Recommended: YES,
* Label: macOS Sequoia 15.8.2-24H232
	Title: macOS Sequoia 15.8.2, Version: 15.8.2, Size: 2269625KiB, Recommended: YES, Action: restart,
* Label: Evil; rm -rf ~
	Title: Evil, Version: 1.0, Size: 1KiB,
* Label: Broken
	Title: Broken, Version: latest, Size: 1KiB,
`)
	want := []inventory.AppleUpdate{
		{Label: "Safari27.2SequoiaAuto-27.2", Title: "Safari", Version: "27.2"},
		{Label: "macOS Sequoia 15.8.2-24H232", Title: "macOS Sequoia 15.8.2", Version: "15.8.2", Restart: true},
	}
	if got := ParseSoftwareUpdate(out); !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v\nwant %+v", got, want)
	}
	if got := ParseSoftwareUpdate([]byte("Software Update Tool\n\nFinding available software\nNo new software available.\n")); len(got) != 0 {
		t.Fatalf("no updates: got %+v", got)
	}
}

func TestParseBrewOutdated(t *testing.T) {
	out := []byte(`{"formulae":[{"name":"aom","installed_versions":["3.11.0"],"current_version":"3.15.3","pinned":false},
		{"name":"bad name","installed_versions":["1"],"current_version":"2"}],
		"casks":[{"name":"bruno","installed_versions":["1.23.1"],"current_version":"4.3.0"}]}`)
	got, err := ParseBrewOutdated(out)
	want := []inventory.BrewPackage{{Name: "aom", Installed: "3.11.0", Current: "3.15.3"}, {Name: "bruno", Installed: "1.23.1", Current: "4.3.0"}}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v, %v", got, err)
	}
	if _, err := ParseBrewOutdated([]byte("Error: something")); err == nil {
		t.Fatal("garbage should fail, not look like 'nothing outdated'")
	}
}

func TestParseLinuxIgnoresGroupNames(t *testing.T) {
	const body = "mis-collect 1\nos-id=ubuntu\nos-version=24.04\nkernel=6.8.0-49-generic\narch=amd64\nreboot-required=no\n%spkg\tii \tbash\t5.2.21-2\tbash\t5.2.21-2\n"
	now := time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC)
	for name, groups := range map[string]string{
		"plain":            "groups=kugesh adm sudo\n",
		"directory domain": "groups=domain users@corp.example.com sudo\n",
		"upper case":       "groups=Staff Domain-Admins\n",
		"long name":        "groups=" + strings.Repeat("a", 42) + "\n",
		"no groups line":   "",
	} {
		t.Run(name, func(t *testing.T) {
			inv, err := parseLinux([]byte(fmt.Sprintf(body, groups)), now)
			if err != nil || inv.OSID != "ubuntu" || len(inv.Packages) != 1 {
				t.Fatalf("parseLinux() = %+v, %v", inv, err)
			}
		})
	}
	// Everything else is still checked strictly.
	for name, bad := range map[string]string{
		"duplicate field": "os-id=debian\n",
		"stray line":      "not a field\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parseLinux([]byte(fmt.Sprintf(body, bad)), now); err == nil {
				t.Fatal("parseLinux accepted bad output")
			}
		})
	}
}

// A child that keeps the output pipes open must not hold run past its timeout.
func TestRunTimeoutHoldsWhenAChildKeepsThePipeOpen(t *testing.T) {
	old := waitDelay
	waitDelay = 300 * time.Millisecond
	defer func() { waitDelay = old }()

	start := time.Now()
	_, err := run(context.Background(), 300*time.Millisecond, nil, "", "/bin/sh", "-c", "sleep 5 & sleep 5")
	if err == nil {
		t.Fatal("run succeeded although the command was killed")
	}
	if d := time.Since(start); d > 3*time.Second {
		t.Fatalf("run took %v with a 300ms timeout", d)
	}
}
