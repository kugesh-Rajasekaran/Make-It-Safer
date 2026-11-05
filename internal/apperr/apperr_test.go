package apperr

import (
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

func TestErrorFormattingAndUnwrap(t *testing.T) {
	cause := errors.New("connection refused")
	err := Wrap(ConfigUnreadable, cause, "cannot read config")

	if got, want := err.Error(), "cannot read config: connection refused"; got != want {
		t.Fatalf("Error() = %q, want %q", got, want)
	}
	if !errors.Is(err, cause) {
		t.Fatal("wrapped cause is not reachable with errors.Is")
	}
	if got := New(ConfigInvalid, "bad").Error(); got != "bad" {
		t.Fatalf("Error() without cause = %q", got)
	}
}

func TestCodeOf(t *testing.T) {
	wrapped := fmt.Errorf("loading: %w", New(ConfigInvalid, "bad port"))
	if got := CodeOf(wrapped); got != ConfigInvalid {
		t.Fatalf("CodeOf(wrapped) = %q", got)
	}
	if got := CodeOf(errors.New("plain")); got != CLIUnexpected {
		t.Fatalf("CodeOf(plain) = %q", got)
	}
	if !Is(wrapped, ConfigInvalid) || Is(wrapped, ConfigUnreadable) {
		t.Fatal("Is() does not match codes correctly")
	}
}

// TestCodesAreAreaPrefixedAndUnique parses the registry so a new code can't
// be generic (NOT_FOUND) or a duplicate.
func TestCodesAreAreaPrefixedAndUnique(t *testing.T) {
	areas := []string{
		"CLI", "CONFIG", "VAULT", "SERVER", "SETUP", "INVENTORY", "FEEDS", "OSV",
		"KEV", "EPSS", "EOL", "CVE", "FINDINGS", "DAEMON", "SERVICE", "NOTIFY",
		"FIX", "TERMINAL", "MATCH", "DOCTOR",
	}
	pattern := regexp.MustCompile(`^(` + strings.Join(areas, "|") + `)(_[A-Z0-9]+)+$`)

	file, err := parser.ParseFile(token.NewFileSet(), "codes.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]string{}
	for _, decl := range file.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.CONST {
			continue
		}
		for _, spec := range gen.Specs {
			vs := spec.(*ast.ValueSpec)
			for i, name := range vs.Names {
				lit, ok := vs.Values[i].(*ast.BasicLit)
				if !ok {
					t.Fatalf("%s is not a string literal", name.Name)
				}
				code, err := strconv.Unquote(lit.Value)
				if err != nil {
					t.Fatal(err)
				}
				if !pattern.MatchString(code) {
					t.Errorf("%s = %q: codes must be UPPER_SNAKE and start with a known area", name.Name, code)
				}
				if other, dup := seen[code]; dup {
					t.Errorf("%s and %s share code %q", other, name.Name, code)
				}
				seen[code] = name.Name
			}
		}
	}
	if len(seen) == 0 {
		t.Fatal("no codes found")
	}
}
