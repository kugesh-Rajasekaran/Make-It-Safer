// Package keyring keeps a small secret in the operating system's secret
// store: the login Keychain on macOS. Make-It-Safer keeps one item there per
// install, the unlock key for auto-unlock (docs/design.md §4.2, ADR 0002).
package keyring

import "github.com/kugesh-rajasekaran/make-it-safer/internal/apperr"

// Item names one secret in the store.
type Item struct {
	Service string // shown as the item's name in Keychain Access
	Account string
}

// AutoUnlock is the item that holds the auto-unlock key of the install in
// home (Make-It-Safer's folder), so separate installs never share one.
func AutoUnlock(home string) Item {
	return Item{Service: "Make-It-Safer auto-unlock", Account: home}
}

// Require returns KEYRING_UNAVAILABLE on computers without a supported
// secret store, and nil otherwise.
func Require() error {
	if Available() {
		return nil
	}
	return apperr.New(apperr.KeyringUnavailable, "auto-unlock needs the macOS Keychain; it isn't available on this computer yet")
}
