package vault

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/kugesh-rajasekaran/make-it-safer/internal/apperr"
)

func TestReadLine(t *testing.T) {
	cases := []struct {
		name, input, want, code string
	}{
		{"enter", "secret words\r", "secret words", ""},
		{"newline", "secret words\n", "secret words", ""},
		{"backspace", "secrex\x7ft\r", "secret", ""},
		{"backspace removes a whole character", "café\x7fe\r", "cafe", ""},
		{"ctrl-u clears the line", "wrong\x15right\r", "right", ""},
		{"ctrl-c cancels", "abc\x03", "", apperr.CLIInputAborted},
		{"ctrl-d cancels", "abc\x04", "", apperr.CLIInputAborted},
		{"input ends", "abc", "", apperr.CLIInputAborted},
		{"too long", strings.Repeat("a", maxInputBytes+5) + "\r", "", apperr.VaultPassphraseTooLong},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := readLine(strings.NewReader(tc.input))
			if tc.code != "" {
				if !apperr.Is(err, tc.code) {
					t.Fatalf("readLine() = %v, want %s", err, tc.code)
				}
				return
			}
			if err != nil || string(got) != tc.want {
				t.Fatalf("readLine() = %q, %v; want %q", got, err, tc.want)
			}
		})
	}
}

func TestReadPassphraseRequiresTerminal(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	if _, err := ReadPassphrase(r, os.Stderr, "Passphrase: "); !apperr.Is(err, apperr.VaultTTYRequired) {
		t.Fatalf("ReadPassphrase(pipe) = %v, want %s", err, apperr.VaultTTYRequired)
	}
	if _, err := ReadPassphrase(nil, os.Stderr, "Passphrase: "); !apperr.Is(err, apperr.VaultTTYRequired) {
		t.Fatalf("ReadPassphrase(nil) = %v, want %s", err, apperr.VaultTTYRequired)
	}
}

func TestLimiter(t *testing.T) {
	now := time.Unix(0, 0)
	l := &Limiter{Now: func() time.Time { return now }}
	if l.Wait() != 0 {
		t.Fatal("fresh limiter should allow an attempt")
	}
	for i, want := range []time.Duration{time.Second, 2 * time.Second, 4 * time.Second} {
		l.Failure()
		if got := l.Wait(); got != want {
			t.Fatalf("after %d failures wait %v, want %v", i+1, got, want)
		}
	}
	for range 20 {
		l.Failure()
	}
	if got := l.Wait(); got != maxUnlockDelay {
		t.Fatalf("wait %v, want the %v cap", got, maxUnlockDelay)
	}
	now = now.Add(maxUnlockDelay)
	if l.Wait() != 0 {
		t.Fatal("limiter should allow an attempt after the delay")
	}
	l.Success()
	l.Failure()
	if got := l.Wait(); got != time.Second {
		t.Fatalf("after reset wait %v, want 1s", got)
	}
}
