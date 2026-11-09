package kev

import (
	"strings"
	"testing"
)

func TestDescription(t *testing.T) {
	data := `{"catalogVersion": "1", "vulnerabilities": [
	  {"cveID": "CVE-2024-3400", "vulnerabilityName": "Command Injection", "shortDescription": "  Allows an\n unauthenticated attacker  to run code.  "},
	  {"cveID": "CVE-2024-0001", "shortDescription": "` + strings.Repeat("x", 400) + `"}]}`
	cat, err := parse([]byte(data))
	if err != nil {
		t.Fatal(err)
	}
	if got := cat.Description("CVE-2024-3400"); got != "Allows an unauthenticated attacker to run code." {
		t.Errorf("description = %q", got)
	}
	if got := []rune(cat.Description("CVE-2024-0001")); len(got) != 300 || got[299] != '…' {
		t.Errorf("long description: %d runes", len(got))
	}
	if cat.Description("CVE-2099-0001") != "" || (*Catalog)(nil).Description("CVE-2024-3400") != "" {
		t.Error("an unlisted CVE or no catalog has no description")
	}
}
