package vault

import (
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/kugesh-rajasekaran/make-it-safer/internal/apperr"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/secret"
)

// testParams keep Argon2id fast in tests; real keys use DefaultParams.
var testParams = Params{Time: 1, MemoryKiB: 8 << 10, Threads: 1}

const testPassphrase = "glacier rhubarb tandem quiver lantern 77"

func createKey(t *testing.T) (dir string, pub ssh.PublicKey) {
	t.Helper()
	dir = t.TempDir()
	pub, err := Create(filepath.Join(dir, "key.enc"), filepath.Join(dir, "key.pub"), secret.Bytes(testPassphrase), testParams)
	if err != nil {
		t.Fatal(err)
	}
	return dir, pub
}

func TestCreateAndUnlock(t *testing.T) {
	dir, pub := createKey(t)
	keyPath := filepath.Join(dir, "key.enc")

	for _, name := range []string{"key.enc", "key.pub"} {
		info, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("%s has mode %o, want 600", name, info.Mode().Perm())
		}
	}
	raw, _ := os.ReadFile(keyPath)
	if strings.Contains(string(raw), "PRIVATE KEY") {
		t.Fatal("key.enc contains an unencrypted private key")
	}

	key, err := Unlock(keyPath, secret.Bytes(testPassphrase))
	if err != nil {
		t.Fatal(err)
	}
	defer key.Destroy()
	if string(key.PublicKey().Marshal()) != string(pub.Marshal()) {
		t.Fatal("unlocked key has a different public key")
	}

	// The signer must produce signatures the public key accepts.
	data := []byte("challenge")
	sig, err := key.Signer().Sign(rand.Reader, data)
	if err != nil {
		t.Fatal(err)
	}
	if err := pub.Verify(data, sig); err != nil {
		t.Fatalf("signature does not verify: %v", err)
	}

	stored, err := PublicKeyFromFile(keyPath)
	if err != nil || string(stored.Marshal()) != string(pub.Marshal()) {
		t.Fatalf("PublicKeyFromFile = %v, %v", stored, err)
	}
}

func TestSignerFailsAfterDestroy(t *testing.T) {
	dir, _ := createKey(t)
	key, err := Unlock(filepath.Join(dir, "key.enc"), secret.Bytes(testPassphrase))
	if err != nil {
		t.Fatal(err)
	}
	signer := key.Signer()
	key.Destroy()
	key.Destroy() // twice is fine
	if key.Alive() {
		t.Fatal("key still alive after Destroy")
	}
	if _, err := signer.Sign(rand.Reader, []byte("x")); !apperr.Is(err, apperr.VaultLocked) {
		t.Fatalf("Sign after Destroy = %v, want %s", err, apperr.VaultLocked)
	}
}

func TestUnlockRejects(t *testing.T) {
	cases := map[string]struct {
		mutate func(f map[string]any)
		raw    string
		code   string
	}{
		"wrong passphrase": {code: apperr.VaultUnlockFailed},
		"tampered params": {code: apperr.VaultUnlockFailed, mutate: func(f map[string]any) {
			f["header"].(map[string]any)["params"].(map[string]any)["time"] = 2
		}},
		"swapped public key": {code: apperr.VaultUnlockFailed, mutate: func(f map[string]any) {
			f["header"].(map[string]any)["public_key"] = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl evil\n"
		}},
		"weakened cost": {code: apperr.VaultKeyFileInvalid, mutate: func(f map[string]any) {
			f["header"].(map[string]any)["params"].(map[string]any)["memory_kib"] = 64
		}},
		"unknown field":  {code: apperr.VaultKeyFileInvalid, mutate: func(f map[string]any) { f["extra"] = true }},
		"truncated file": {code: apperr.VaultKeyFileInvalid, raw: `{"header": {`},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			dir, _ := createKey(t)
			keyPath := filepath.Join(dir, "key.enc")
			if tc.mutate != nil || tc.raw != "" {
				data := []byte(tc.raw)
				if tc.mutate != nil {
					raw, _ := os.ReadFile(keyPath)
					var f map[string]any
					if err := json.Unmarshal(raw, &f); err != nil {
						t.Fatal(err)
					}
					tc.mutate(f)
					data, _ = json.Marshal(f)
				}
				if err := os.WriteFile(keyPath, data, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			passphrase := testPassphrase
			if name == "wrong passphrase" {
				passphrase = "glacier rhubarb tandem quiver lantern 78"
			}
			key, err := Unlock(keyPath, secret.Bytes(passphrase))
			if key != nil {
				key.Destroy()
			}
			if !apperr.Is(err, tc.code) {
				t.Fatalf("Unlock() = %v, want %s", err, tc.code)
			}
		})
	}
}

func TestUnlockRefusesReadableKeyFile(t *testing.T) {
	dir, _ := createKey(t)
	keyPath := filepath.Join(dir, "key.enc")
	if err := os.Chmod(keyPath, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Unlock(keyPath, secret.Bytes(testPassphrase)); !apperr.Is(err, apperr.ConfigPermissionsTooOpen) {
		t.Fatalf("Unlock() = %v, want %s", err, apperr.ConfigPermissionsTooOpen)
	}
}

func TestCreateRefusesToOverwrite(t *testing.T) {
	dir, _ := createKey(t)
	_, err := Create(filepath.Join(dir, "key.enc"), filepath.Join(dir, "key.pub"), secret.Bytes(testPassphrase), testParams)
	if !apperr.Is(err, apperr.VaultKeyExists) {
		t.Fatalf("Create() over an existing key = %v", err)
	}
}

func TestChangePassphrase(t *testing.T) {
	dir, pub := createKey(t)
	keyPath := filepath.Join(dir, "key.enc")
	next := "orbit velvet canyon pepper meadow 42"

	if err := ChangePassphrase(keyPath, secret.Bytes("not the passphrase at all"), secret.Bytes(next), testParams); !apperr.Is(err, apperr.VaultUnlockFailed) {
		t.Fatalf("change with wrong current passphrase = %v", err)
	}
	if err := ChangePassphrase(keyPath, secret.Bytes(testPassphrase), secret.Bytes(next), testParams); err != nil {
		t.Fatal(err)
	}
	if _, err := Unlock(keyPath, secret.Bytes(testPassphrase)); !apperr.Is(err, apperr.VaultUnlockFailed) {
		t.Fatalf("old passphrase still works: %v", err)
	}
	key, err := Unlock(keyPath, secret.Bytes(next))
	if err != nil {
		t.Fatal(err)
	}
	defer key.Destroy()
	if string(key.PublicKey().Marshal()) != string(pub.Marshal()) {
		t.Fatal("changing the passphrase changed the key")
	}
}

func TestDefaultParamsAreRFC9106Options(t *testing.T) {
	p := DefaultParams()
	if p != ParamsStrong && p != ParamsLowMemory {
		t.Fatalf("DefaultParams() = %+v", p)
	}
}
