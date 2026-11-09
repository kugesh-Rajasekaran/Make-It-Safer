package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/kugesh-rajasekaran/make-it-safer/internal/config"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/secret"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/vault"
)

// A key without a config.yaml (the file was deleted) used to loop: init said
// "already set up" while every other command said "run: mis init".
func TestInitRestoresMissingConfig(t *testing.T) {
	paths := config.PathsAt(filepath.Join(t.TempDir(), "mis"))
	t.Setenv(config.EnvHome, paths.Home)
	if err := paths.Ensure(); err != nil {
		t.Fatal(err)
	}
	if _, err := vault.Create(paths.KeyFile, paths.PublicKey, secret.Bytes("correct horse battery"),
		vault.Params{Time: 1, MemoryKiB: 8 << 10, Threads: 1}); err != nil {
		t.Fatal(err)
	}
	key, err := os.ReadFile(paths.KeyFile)
	if err != nil {
		t.Fatal(err)
	}

	code, out, errOut := runCLI(t, "init", "--json")
	if e := decode(t, out); code != 0 || !e.OK {
		t.Fatalf("exit %d: %s %s", code, out, errOut)
	}
	if after, _ := os.ReadFile(paths.KeyFile); !bytes.Equal(after, key) {
		t.Error("the key file changed")
	}
	if _, err := config.Load(paths.Config); err != nil {
		t.Fatalf("config.yaml was not re-created: %v", err)
	}
	if code, out, _ := runCLI(t, "config", "get", "--json"); code != 0 {
		t.Errorf("other commands still fail: exit %d: %s", code, out)
	}

	// Now it really is set up.
	code, out, _ = runCLI(t, "init", "--json")
	if e := decode(t, out); code != 1 || e.Error == nil || e.Error.Code != "VAULT_KEY_EXISTS" {
		t.Fatalf("exit %d: %s", code, out)
	}
}
