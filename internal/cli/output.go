package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"unicode"
)

type errorBody struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// emit prints a command's result: the {"ok": true, "data": …} envelope with
// --json, otherwise the text that human writes.
func (a *app) emit(data any, human func(w io.Writer)) error {
	if a.json {
		return a.writeJSON(struct {
			OK   bool `json:"ok"`
			Data any  `json:"data"`
		}{true, data})
	}
	human(a.stdout)
	return nil
}

// printError prints a failed command: the {"ok": false, "error": …}
// envelope on stdout with --json, otherwise one line on stderr.
func (a *app) printError(err error) {
	e := asAppError(err)
	if a.json {
		_ = a.writeJSON(struct {
			OK    bool      `json:"ok"`
			Error errorBody `json:"error"`
		}{false, errorBody{Code: e.Code, Message: e.Error()}})
		return
	}
	_, _ = fmt.Fprintf(a.stderr, "mis: %s [%s]\n", e.Error(), e.Code)
}

func (a *app) writeJSON(v any) error {
	enc := json.NewEncoder(a.stdout)
	enc.SetEscapeHTML(false)
	return enc.Encode(v)
}

// clean makes text from outside sources (feeds, servers) safe to print in a
// terminal by dropping control characters, so it can't inject escape codes.
func clean(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '\n' || r == '\t' {
			return r
		}
		if unicode.IsControl(r) || r == unicode.ReplacementChar {
			return -1
		}
		return r
	}, s)
}
