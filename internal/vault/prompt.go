package vault

import (
	"fmt"
	"io"
	"os"
	"unicode/utf8"

	"golang.org/x/term"

	"github.com/kugesh-rajasekaran/make-it-safer/internal/apperr"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/secret"
)

// maxInputBytes bounds what ReadPassphrase accepts: MaxLength characters of
// up to 4 bytes each. The buffer is allocated once, so typing never leaves
// stray copies behind in memory.
const maxInputBytes = MaxLength * 4

// ReadPassphrase reads a passphrase typed in the terminal, without echo.
// It refuses anything that isn't a terminal: passphrases never come from
// pipes, files, flags or environment variables.
func ReadPassphrase(tty *os.File, w io.Writer, prompt string) (secret.Bytes, error) {
	if tty == nil || !term.IsTerminal(int(tty.Fd())) {
		return nil, apperr.New(apperr.VaultTTYRequired, "the passphrase can only be typed in a terminal")
	}
	fd := int(tty.Fd())
	state, err := term.MakeRaw(fd)
	if err != nil {
		return nil, apperr.Wrap(apperr.VaultTTYRequired, err, "cannot read from the terminal")
	}
	defer func() { _ = term.Restore(fd, state) }()

	_, _ = fmt.Fprint(w, prompt)
	p, err := readLine(tty)
	_, _ = fmt.Fprint(w, "\r\n")
	return p, err
}

// readLine reads one line in raw mode. It handles Backspace (a whole
// character at a time), Ctrl-U (clear), Ctrl-C/Ctrl-D (abort) and Enter.
func readLine(r io.Reader) (secret.Bytes, error) {
	buf := make(secret.Bytes, 0, maxInputBytes)
	one := make([]byte, 1)
	overflow := false
	for {
		n, err := r.Read(one)
		if n == 0 || err != nil {
			buf.Wipe()
			return nil, apperr.New(apperr.CLIInputAborted, "input ended before Enter")
		}
		switch c := one[0]; c {
		case '\r', '\n':
			one[0] = 0
			if overflow {
				buf.Wipe()
				return nil, apperr.New(apperr.VaultPassphraseTooLong, fmt.Sprintf("use at most %d characters", MaxLength))
			}
			return buf, nil
		case 3, 4: // Ctrl-C, Ctrl-D
			buf.Wipe()
			return nil, apperr.New(apperr.CLIInputAborted, "cancelled")
		case 21: // Ctrl-U: start over, also after too much input
			buf.Wipe()
			buf = buf[:0]
			overflow = false
		case 127, 8: // Backspace / Delete
			if len(buf) > 0 {
				_, size := utf8.DecodeLastRune(buf)
				clear(buf[len(buf)-size:])
				buf = buf[:len(buf)-size]
			}
		default:
			if len(buf) < cap(buf) {
				buf = append(buf, c) // never grows past cap: no reallocation, no copies
			} else {
				overflow = true
			}
		}
	}
}
