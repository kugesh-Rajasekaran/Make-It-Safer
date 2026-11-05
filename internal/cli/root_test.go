package cli

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/kugesh-rajasekaran/make-it-safer/internal/apperr"
)

type envelope struct {
	OK    bool            `json:"ok"`
	Data  json.RawMessage `json:"data"`
	Error *errorBody      `json:"error"`
}

func runCLI(t *testing.T, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code = run(args, nil, &out, &errOut)
	return code, out.String(), errOut.String()
}

func decode(t *testing.T, s string) envelope {
	t.Helper()
	var e envelope
	if err := json.Unmarshal([]byte(s), &e); err != nil {
		t.Fatalf("output is not a JSON envelope: %v\n%s", err, s)
	}
	return e
}

func TestVersionJSON(t *testing.T) {
	code, out, _ := runCLI(t, "version", "--json")
	if code != 0 {
		t.Fatalf("exit code %d", code)
	}
	e := decode(t, out)
	var info versionInfo
	if err := json.Unmarshal(e.Data, &info); err != nil {
		t.Fatal(err)
	}
	if !e.OK || info.Version == "" || info.OS == "" {
		t.Fatalf("unexpected envelope: %s", out)
	}
}

func TestVersionHuman(t *testing.T) {
	code, out, _ := runCLI(t, "version")
	if code != 0 || !strings.HasPrefix(out, "mis ") {
		t.Fatalf("exit %d, output %q", code, out)
	}
}

func TestErrorsHaveCodes(t *testing.T) {
	code, out, _ := runCLI(t, "no-such-command", "--json")
	e := decode(t, out)
	if code != 1 || e.OK || e.Error == nil || e.Error.Code != "CLI_USAGE_INVALID" {
		t.Fatalf("exit %d, envelope %s", code, out)
	}

	code, _, errOut := runCLI(t, "version", "--bogus")
	if code != 1 || !strings.Contains(errOut, "[CLI_USAGE_INVALID]") {
		t.Fatalf("exit %d, stderr %q", code, errOut)
	}
}

func TestCleanDropsControlCharacters(t *testing.T) {
	in := "safe\x1b]52;c;evil\x07 text\r\nnext\tline\u0085"
	if got, want := clean(in), "safe]52;c;evil text\nnext\tline"; got != want {
		t.Fatalf("clean() = %q, want %q", got, want)
	}
}

func TestInitRequiresTerminal(t *testing.T) {
	t.Setenv("MIS_HOME", t.TempDir()+"/mis")
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	var out, errOut bytes.Buffer
	code := run([]string{"init", "--json"}, r, &out, &errOut)
	e := decode(t, out.String())
	if code != 1 || e.Error == nil || e.Error.Code != "VAULT_TTY_REQUIRED" {
		t.Fatalf("exit %d, envelope %s", code, out.String())
	}
}

func TestCommandsNeedInit(t *testing.T) {
	t.Setenv("MIS_HOME", t.TempDir()+"/mis")
	code, out, _ := runCLI(t, "passphrase", "change", "--json")
	e := decode(t, out)
	if code != 1 || e.Error == nil || e.Error.Code != "CONFIG_NOT_INITIALIZED" {
		t.Fatalf("exit %d, envelope %s", code, out)
	}
}

func TestFailedResultsAreOneEnvelope(t *testing.T) {
	var out bytes.Buffer
	a := newApp([]string{"--json"}, nil, &out, &out)
	err := a.emitFailed([]string{"check"}, func(io.Writer) {}, apperr.New(apperr.SetupVerifyFailed, "some checks failed"))
	a.printError(err)
	e := decode(t, out.String()) // fails on two JSON documents
	if e.OK || e.Error == nil || e.Error.Code != apperr.SetupVerifyFailed || string(e.Data) != `["check"]` {
		t.Fatalf("envelope = %s", out.String())
	}
}
