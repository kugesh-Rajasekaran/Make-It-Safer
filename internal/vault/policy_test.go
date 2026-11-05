package vault

import (
	"strings"
	"testing"

	"github.com/kugesh-rajasekaran/make-it-safer/internal/apperr"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/secret"
)

func TestCheckPassphrase(t *testing.T) {
	cases := []struct {
		name, passphrase, code, reason string
	}{
		{"too short", "short phrase", apperr.VaultPassphraseTooShort, "at least 15"},
		{"too long", strings.Repeat("ab cd ", 200), apperr.VaultPassphraseTooLong, "at most 1024"},
		{"not text", "\xff\xfe valid-looking tail", apperr.VaultPassphraseInvalid, "UTF-8"},
		{"repeated character", strings.Repeat("a", 20), apperr.VaultPassphraseTooWeak, "repeated"},
		{"common password", "passwordpassword", apperr.VaultPassphraseTooWeak, ""},
		{"keyboard pattern", "qwertyuiopasdfghjkl", apperr.VaultPassphraseTooWeak, ""},
		{"common passwords", "iloveyou123456password", apperr.VaultPassphraseTooWeak, "common passwords"},
		{"sequence", "abcdefghijklmnopqrst", apperr.VaultPassphraseTooWeak, ""},
		{"tool name", "makeitsafer-makeitsafer", apperr.VaultPassphraseTooWeak, "tool's name"},
		{"server name", "ovh-web-1-ovh-web-1", apperr.VaultPassphraseTooWeak, "server name"},
		{"strong words", "glacier rhubarb tandem quiver lantern 77", "", ""},
		{"spaces and unicode", "café über straße fjörd brûlée", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := CheckPassphrase(secret.Bytes(tc.passphrase), []string{"ovh-web-1"})
			if tc.code == "" {
				if err != nil {
					t.Fatalf("rejected a good passphrase: %v", err)
				}
				return
			}
			if !apperr.Is(err, tc.code) {
				t.Fatalf("got %v, want %s", err, tc.code)
			}
			if !strings.Contains(err.Error(), tc.reason) {
				t.Fatalf("reason %q does not mention %q", err.Error(), tc.reason)
			}
		})
	}
}

func TestLengthCountsCharactersAfterNFC(t *testing.T) {
	// 14 × "e" + combining acute accent is 28 code points but 14 characters.
	decomposed := strings.Repeat("é", 14)
	err := CheckPassphrase(secret.Bytes(decomposed), nil)
	if !apperr.Is(err, apperr.VaultPassphraseTooShort) || !strings.Contains(err.Error(), "has 14") {
		t.Fatalf("got %v, want too short with 14 characters", err)
	}
}

func TestGeneratePassphrase(t *testing.T) {
	seen := map[string]bool{}
	for range 5 {
		p, err := GeneratePassphrase()
		if err != nil {
			t.Fatal(err)
		}
		words := strings.Split(string(p), "-")
		if len(words) != generatedWords {
			t.Fatalf("got %d words", len(words))
		}
		if err := CheckPassphrase(p, nil); err != nil {
			t.Fatalf("generated passphrase rejected: %v", err)
		}
		if seen[string(p)] {
			t.Fatal("generated the same passphrase twice")
		}
		seen[string(p)] = true
	}
}
