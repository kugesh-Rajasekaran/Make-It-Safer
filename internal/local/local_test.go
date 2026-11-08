package local

import (
	"reflect"
	"testing"

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
