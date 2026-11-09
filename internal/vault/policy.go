// Package vault holds the passphrase policy, the encrypted key file and the
// unlocked key (kept in locked memory). See docs/design.md §4.2 and §5.2.
package vault

import (
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/sethvargo/go-diceware/diceware"
	"golang.org/x/text/unicode/norm"

	"github.com/kugesh-rajasekaran/make-it-safer/internal/apperr"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/secret"
)

const (
	// MinLength is the shortest passphrase accepted (docs/adr/0001).
	MinLength = 8
	// MaxLength is generous; NIST asks for at least 64.
	MaxLength = 1024
	// generatedWords from the EFF long wordlist give ≈ 77 bits.
	generatedWords = 6
)

// CheckPassphrase applies the passphrase policy (docs/design.md §5.2): valid
// UTF-8 and 8 to 1024 characters after NFC normalization. It returns nil, or
// an error whose message says why the passphrase was rejected.
func CheckPassphrase(p secret.Bytes) error {
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
	return nil
}

// GeneratePassphrase returns six random words from the EFF long wordlist,
// joined with hyphens (≈ 77 bits). The four list words that contain a hyphen
// themselves ("t-shirt") are skipped, so it always reads as six words.
func GeneratePassphrase() (secret.Bytes, error) {
	words := make([]string, 0, generatedWords)
	for len(words) < generatedWords {
		w, err := diceware.Generate(1)
		if err != nil {
			return nil, apperr.Wrap(apperr.VaultKeyCreateFailed, err, "cannot generate a passphrase")
		}
		if !strings.Contains(w[0], "-") {
			words = append(words, w[0])
		}
	}
	return secret.Bytes(strings.Join(words, "-")), nil
}

// wipeIfCopy wipes normalized unless it shares memory with the original
// (norm returns its input unchanged when it's already NFC).
func wipeIfCopy(normalized, original []byte) {
	if len(normalized) > 0 && len(original) > 0 && &normalized[0] == &original[0] {
		return
	}
	clear(normalized)
}
