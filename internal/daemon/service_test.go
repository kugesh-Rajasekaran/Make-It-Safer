package daemon

import (
	"html"
	"strings"
	"testing"
)

func TestServiceFiles(t *testing.T) {
	v := serviceValues{Label: launchLabel, Binary: "/Users/me/My Tools/mis", Log: "/Users/me/Library/Logs/MakeItSafer/daemon.log", Home: "/tmp/a&b"}
	plist, err := renderLaunchAgent(v)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"<string>/Users/me/My Tools/mis</string>", "<string>daemon</string>", "<key>RunAtLoad</key>", "/tmp/a&amp;b"} {
		if !strings.Contains(plist, want) {
			t.Errorf("plist lacks %q:\n%s", want, plist)
		}
	}
	if html.UnescapeString(plist) == plist {
		t.Error("plist values should be XML-escaped")
	}
	unit, err := renderSystemdUnit(serviceValues{Binary: "/home/me/go/bin/mis"})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`ExecStart="/home/me/go/bin/mis" daemon`, "WantedBy=graphical-session.target", "Restart=on-failure"} {
		if !strings.Contains(unit, want) {
			t.Errorf("unit lacks %q:\n%s", want, unit)
		}
	}
	if strings.Contains(unit, "MIS_HOME") {
		t.Error("MIS_HOME should only be set when it was set")
	}
}
