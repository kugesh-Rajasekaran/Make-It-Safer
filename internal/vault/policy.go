// Package vault holds the passphrase policy, the encrypted key file and the
// unlocked key (kept in locked memory). See docs/design.md §4.2 and §5.2.
package vault

import (
	"fmt"
	"math"
	"strings"
	"unicode/utf8"

	"github.com/sethvargo/go-diceware/diceware"
	"github.com/trustelem/zxcvbn"
	"github.com/trustelem/zxcvbn/match"
	"golang.org/x/text/unicode/norm"

	"github.com/kugesh-rajasekaran/make-it-safer/internal/apperr"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/secret"
)

const (
	// MinLength is NIST SP 800-63B-4's minimum for single-factor passwords.
	MinLength = 15
	// MaxLength is generous; NIST asks for at least 64.
	MaxLength = 1024
	// minGuessesLog10 is stricter than NIST on purpose: a copied key.enc can
	// be attacked offline without any rate limit. 10^14 guesses ≈ 47 bits.
	minGuessesLog10 = 14
	// strengthWindow caps the text the strength estimator looks at; it gets
	// slow on very long input and 100 characters is plenty to judge.
	strengthWindow = 100
	// generatedWords from the EFF long wordlist give ≈ 77 bits.
	generatedWords = 6
)

// contextWords are what an attacker would try first for this tool.
var contextWords = []string{"make-it-safer", "makeitsafer", "make it safer", "mis", "safer", "passphrase"}

// CheckPassphrase applies the passphrase policy (docs/design.md §5.2): the
// NIST SP 800-63B-4 rules plus a strength floor. It returns nil, or an
// error whose message says why the passphrase was rejected. extraWords are
// context words such as your username, hostname and server names.
//
// The strength estimator needs a Go string, which can't be wiped. This
// check only runs when a passphrase is created or changed, never at unlock.
func CheckPassphrase(p secret.Bytes, extraWords []string) error {
	if !utf8.Valid(p) {
		return apperr.New(apperr.VaultPassphraseInvalid, "the passphrase must be valid text (UTF-8)")
	}
	normalized := secret.Bytes(norm.NFC.Bytes(p))
	defer wipeIfCopy(normalized, p)

	n := utf8.RuneCount(normalized)
	if n < MinLength {
		return apperr.New(apperr.VaultPassphraseTooShort, fmt.Sprintf("use at least %d characters (this one has %d)", MinLength, n))
	}
	if n > MaxLength {
		return apperr.New(apperr.VaultPassphraseTooLong, fmt.Sprintf("use at most %d characters (this one has %d)", MaxLength, n))
	}

	inputs := append(append([]string{}, contextWords...), extraWords...)
	for i := range inputs {
		inputs[i] = strings.ToLower(inputs[i])
	}
	result := zxcvbn.PasswordStrength(firstRunes(normalized, strengthWindow), inputs)
	if result.Guesses <= 0 || math.Log10(result.Guesses) < minGuessesLog10 {
		return apperr.New(apperr.VaultPassphraseTooWeak, "too easy to guess: "+weakness(result.Sequence))
	}
	return nil
}

// GeneratePassphrase returns six random words from the EFF long wordlist,
// joined with hyphens (≈ 77 bits).
func GeneratePassphrase() (secret.Bytes, error) {
	for range 10 { // a weak draw is astronomically unlikely; retry anyway
		words, err := diceware.Generate(generatedWords)
		if err != nil {
			return nil, apperr.Wrap(apperr.VaultKeyCreateFailed, err, "cannot generate a passphrase")
		}
		p := secret.Bytes(strings.Join(words, "-"))
		if CheckPassphrase(p, nil) == nil {
			return p, nil
		}
		p.Wipe()
	}
	return nil, apperr.New(apperr.VaultKeyCreateFailed, "cannot generate a strong passphrase")
}

// weakness explains in plain words why zxcvbn found a passphrase guessable.
func weakness(seq []*match.Match) string {
	for _, m := range seq {
		if m.Pattern == "dictionary" && m.DictionaryName == "user_inputs" {
			return "it contains the tool's name, your username, your computer's name or a server name"
		}
	}
	if len(seq) == 1 && seq[0].Pattern == "dictionary" && seq[0].DictionaryName == "passwords" {
		return "it appears in lists of common or breached passwords"
	}
	for _, m := range seq {
		switch m.Pattern {
		case "repeat":
			return "repeated characters or words are easy to guess"
		case "sequence":
			return "sequences like 'abcd' or '1234' are easy to guess"
		case "spatial":
			return "keyboard patterns like 'qwerty' are easy to guess"
		case "date":
			return "dates are easy to guess"
		}
	}
	for _, m := range seq {
		if m.Pattern == "dictionary" && m.DictionaryName == "passwords" {
			return "parts of it appear in lists of common passwords"
		}
	}
	return "it is made of common words; use four or more random words, or the generated passphrase"
}

// firstRunes returns at most n runes of b as a string.
func firstRunes(b []byte, n int) string {
	end := 0
	for i := 0; i < n && end < len(b); i++ {
		_, size := utf8.DecodeRune(b[end:])
		end += size
	}
	return string(b[:end])
}

// wipeIfCopy wipes normalized unless it shares memory with the original
// (norm returns its input unchanged when it's already NFC).
func wipeIfCopy(normalized, original []byte) {
	if len(normalized) > 0 && len(original) > 0 && &normalized[0] == &original[0] {
		return
	}
	clear(normalized)
}
