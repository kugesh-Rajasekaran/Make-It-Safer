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
		{"empty", "", apperr.VaultPassphraseTooShort, "has 0"},
		{"too short", "1234567", apperr.VaultPassphraseTooShort, "at least 8"},
		{"too long", strings.Repeat("ab cd ", 200), apperr.VaultPassphraseTooLong, "at most 1024"},
		{"not text", "\xff\xfe valid-looking tail", apperr.VaultPassphraseInvalid, "UTF-8"},
		{"exactly 8", "abcd1234", "", ""},
		{"repeated characters are allowed", strings.Repeat("a", 8), "", ""},
		{"common words are allowed", "password", "", ""},
		{"keyboard patterns are allowed", "qwertyui", "", ""},
		{"exactly 1024", strings.Repeat("a", 1024), "", ""},
		{"words", "glacier rhubarb tandem quiver lantern 77", "", ""},
		{"spaces and unicode", "café über straße fjörd brûlée", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := CheckPassphrase(secret.Bytes(tc.passphrase))
			if tc.code == "" {
				if err != nil {
					t.Fatalf("rejected a valid passphrase: %v", err)
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
	// 7 × "e" + combining acute accent is 14 code points but 7 characters.
	decomposed := strings.Repeat("é", 7)
	err := CheckPassphrase(secret.Bytes(decomposed))
	if !apperr.Is(err, apperr.VaultPassphraseTooShort) || !strings.Contains(err.Error(), "has 7") {
		t.Fatalf("got %v, want too short with 7 characters", err)
	}
}

func TestGeneratePassphrase(t *testing.T) {
	seen := map[string]bool{}
	for range 2000 { // enough to hit the hyphenated list words (4 of 7776) every run
		p, err := GeneratePassphrase()
		if err != nil {
			t.Fatal(err)
		}
		words := strings.Split(string(p), "-")
		if len(words) != generatedWords {
			t.Fatalf("got %d words", len(words))
		}
		if err := CheckPassphrase(p); err != nil {
			t.Fatalf("generated passphrase rejected: %v", err)
		}
		if seen[string(p)] {
			t.Fatal("generated the same passphrase twice")
		}
		seen[string(p)] = true
	}
}
