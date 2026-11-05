// Package secret provides a byte slice type for secret material (passphrases,
// key bytes) that never prints, logs or marshals its content, and can be
// wiped after use.
package secret

import (
	"fmt"
	"io"
	"log/slog"
)

const redacted = "[redacted]"

// Bytes holds secret material. Formatting it with fmt, logging it with slog
// or marshalling it to JSON always yields "[redacted]".
type Bytes []byte

// Wipe overwrites the content with zeros.
func (b Bytes) Wipe() { clear(b) }

func (Bytes) String() string   { return redacted }
func (Bytes) GoString() string { return redacted }

// Format implements fmt.Formatter so every verb (%v, %s, %x, %q, …) is redacted.
func (Bytes) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, redacted) }

// LogValue implements slog.LogValuer.
func (Bytes) LogValue() slog.Value { return slog.StringValue(redacted) }

// MarshalJSON keeps secrets out of JSON output.
func (Bytes) MarshalJSON() ([]byte, error) { return []byte(`"` + redacted + `"`), nil }

// MarshalText keeps secrets out of text encodings (YAML, TOML, …).
func (Bytes) MarshalText() ([]byte, error) { return []byte(redacted), nil }
