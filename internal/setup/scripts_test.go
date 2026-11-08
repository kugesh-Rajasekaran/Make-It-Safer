package setup

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"os/exec"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/kugesh-rajasekaran/make-it-safer/internal/apperr"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/config"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/sshx"
	"github.com/kugesh-rajasekaran/make-it-safer/server"
)

func testKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	k, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestScript(t *testing.T) {
	pub := testKey(t)
	script, err := Script(pub)
	if err != nil {
		t.Fatal(err)
	}
	wantKey := `KEY_LINE='restrict,command="/usr/local/lib/mis/collect" ` + strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub))) + ` make-it-safer'`
	if !strings.Contains(script, wantKey) {
		t.Fatalf("script does not install the key as expected:\n%s", wantKey)
	}
	if strings.Contains(script, "{{") {
		t.Fatal("unrendered template field left in the script")
	}
	b64 := strings.TrimSuffix(strings.TrimPrefix(lineWith(script, "COLLECTOR_B64="), "COLLECTOR_B64='"), "'")
	collector, err := base64.StdEncoding.DecodeString(b64)
	if err != nil || string(collector) != server.Collector {
		t.Fatalf("embedded collector does not decode to collect.sh: %v", err)
	}
}

func TestScriptRejectsOtherKeys(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := ssh.NewSignerFromKey(priv)
	// A key type the setup script doesn't support (RSA) must be refused.
	rsaLike := fakeKey{typ: "ssh-rsa", inner: signer.PublicKey()}
	if _, err := Script(rsaLike); !apperr.Is(err, apperr.SetupInvalidKey) {
		t.Fatalf("Script(rsa) = %v", err)
	}
}

func TestRemoteCommandCarriesScriptIntact(t *testing.T) {
	script := "#!/bin/sh\necho 'quotes \" and $dollars stay intact'\n"
	cmd := RemoteCommand(script)
	if strings.Contains(cmd, "\n") || strings.Contains(cmd, "$dollars") {
		t.Fatalf("script is not encoded: %s", cmd)
	}
	out, err := exec.Command("sh", "-c", strings.Replace(cmd, "exec sudo sh", "exec cat", 1)).Output()
	if err != nil {
		t.Fatal(err)
	}
	// As root the wrapper execs sh (running the script); as a normal user it
	// would exec sudo, replaced by cat here so the test needs no sudo.
	if !strings.Contains(string(out), "quotes \" and $dollars stay intact") {
		t.Fatalf("round trip changed the script: %q", out)
	}
}

func TestAdminArgs(t *testing.T) {
	cases := []struct {
		server config.Server
		want   string
	}{
		{config.Server{AdminSSH: "ubuntu@203.0.113.10", Port: 22}, "-t -- ubuntu@203.0.113.10 CMD"},
		{config.Server{AdminSSH: "ubuntu@203.0.113.10", Port: 2222}, "-t -p 2222 -- ubuntu@203.0.113.10 CMD"},
		{config.Server{AdminSSH: "ovh1", Port: 2222}, "-t -- ovh1 CMD"},
	}
	for _, tc := range cases {
		if got := strings.Join(sshx.AdminArgs(tc.server, "CMD"), " "); got != tc.want {
			t.Errorf("AdminArgs(%+v) = %q, want %q", tc.server, got, tc.want)
		}
	}
}

func TestScriptsPassShellcheck(t *testing.T) {
	if _, err := exec.LookPath("shellcheck"); err != nil {
		t.Skip("shellcheck not installed")
	}
	script, err := Script(testKey(t))
	if err != nil {
		t.Fatal(err)
	}
	for name, content := range map[string]string{"setup": script, "teardown": TeardownScript(), "collect": server.Collector} {
		cmd := exec.Command("shellcheck", "-s", "sh", "-")
		cmd.Stdin = strings.NewReader(content)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Errorf("shellcheck %s:\n%s", name, out)
		}
	}
}

func lineWith(s, prefix string) string {
	for _, line := range strings.Split(s, "\n") {
		if strings.HasPrefix(line, prefix) {
			return line
		}
	}
	return ""
}

type fakeKey struct {
	typ   string
	inner ssh.PublicKey
}

func (k fakeKey) Type() string                                 { return k.typ }
func (k fakeKey) Marshal() []byte                              { return k.inner.Marshal() }
func (k fakeKey) Verify(data []byte, sig *ssh.Signature) error { return k.inner.Verify(data, sig) }
