package config

import (
	"strings"
	"testing"
)

func TestThisComputer(t *testing.T) {
	c := Default()
	c.Servers = []Server{{Name: "web", Host: "10.0.0.1", Port: 22, AdminSSH: "root@10.0.0.1"}}

	if got := c.Checked(); len(got) != 1 {
		t.Fatalf("off: %+v", got)
	}
	if _, ok := c.Server(LocalName()); ok {
		t.Fatal("this computer found while this_computer is off")
	}

	c.ThisComputer = true
	got := c.Checked()
	if len(got) != 2 || got[1].Name != LocalName() || !got[1].Local || got[0].Local {
		t.Fatalf("on: %+v", got)
	}
	if s, ok := c.Server(LocalName()); !ok || !s.Local {
		t.Fatalf("Server(%q) = %+v, %v", LocalName(), s, ok)
	}
	if len(c.Servers) != 1 {
		t.Fatal("Checked must not change the servers list")
	}

	setting, ok := Lookup("this_computer")
	if !ok || setting.Kind != KindToggle || !strings.HasPrefix(setting.Label, "Also check this ") {
		t.Fatalf("setting: %+v", setting)
	}
}

func TestServerNamesForThisComputerAreReserved(t *testing.T) {
	for _, name := range []string{"this-mac", "this-computer"} {
		s := Server{Name: name, Host: "10.0.0.1", Port: 22, AdminSSH: "root@10.0.0.1"}
		if err := s.Validate(); err == nil || !strings.Contains(err.Error(), "kept for this computer") {
			t.Errorf("%s: got %v", name, err)
		}
	}
}
