package secret

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"testing"
)

const value = "correct horse battery staple"

func TestBytesNeverRevealsContent(t *testing.T) {
	s := Bytes(value)

	var logs bytes.Buffer
	slog.New(slog.NewTextHandler(&logs, nil)).Info("unlock", "passphrase", s)
	jsonOut, err := json.Marshal(struct{ P Bytes }{s})
	if err != nil {
		t.Fatal(err)
	}
	text, err := s.MarshalText()
	if err != nil {
		t.Fatal(err)
	}

	outputs := map[string]string{
		"%v":   fmt.Sprintf("%v", s),
		"%s":   fmt.Sprintf("%s", s),
		"%x":   fmt.Sprintf("%x", s),
		"%q":   fmt.Sprintf("%q", s),
		"%+v":  fmt.Sprintf("%+v", struct{ P Bytes }{s}),
		"%#v":  fmt.Sprintf("%#v", s),
		"slog": logs.String(),
		"json": string(jsonOut),
		"text": string(text),
	}
	for name, out := range outputs {
		if strings.Contains(out, "horse") || strings.Contains(out, "686f727365") {
			t.Errorf("%s leaked the secret: %q", name, out)
		}
		if !strings.Contains(out, redacted) {
			t.Errorf("%s = %q, want it to contain %q", name, out, redacted)
		}
	}
}

func TestWipe(t *testing.T) {
	s := Bytes(value)
	s.Wipe()
	for i, b := range s {
		if b != 0 {
			t.Fatalf("byte %d not wiped", i)
		}
	}
}
