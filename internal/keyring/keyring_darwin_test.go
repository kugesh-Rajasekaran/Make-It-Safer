//go:build darwin && keychain

// Uses your real login Keychain, with a throwaway item that it removes.
// Run by hand: go test -tags keychain ./internal/keyring/

package keyring

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/kugesh-rajasekaran/make-it-safer/internal/apperr"
)

func TestKeychainRoundTrip(t *testing.T) {
	item := Item{Service: "Make-It-Safer test", Account: rand.Text()}
	t.Cleanup(func() { _ = item.Delete() })

	if _, err := item.Get(); !apperr.Is(err, apperr.KeyringItemMissing) {
		t.Fatalf("Get before Set = %v, want KEYRING_ITEM_MISSING", err)
	}
	for _, secret := range [][]byte{bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32)} { // second Set replaces
		if err := item.Set(secret); err != nil {
			t.Fatal(err)
		}
		got, err := item.Get()
		if err != nil || !bytes.Equal(got, secret) {
			t.Fatalf("Get = %x, %v; want %x", got, err, secret)
		}
	}
	if err := item.Delete(); err != nil {
		t.Fatal(err)
	}
	if err := item.Delete(); err != nil {
		t.Fatalf("second Delete = %v, want nil", err)
	}
	if _, err := item.Get(); !apperr.Is(err, apperr.KeyringItemMissing) {
		t.Fatalf("Get after Delete = %v, want KEYRING_ITEM_MISSING", err)
	}
}
