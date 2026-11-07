//go:build !darwin

package keyring

// Available reports whether this computer has a supported secret store.
// Linux (Secret Service: GNOME Keyring, KWallet) is planned.
func Available() bool { return false }

// Set is not available on this platform.
func (Item) Set([]byte) error { return Require() }

// Get is not available on this platform.
func (Item) Get() ([]byte, error) { return nil, Require() }

// Delete has nothing to remove on this platform.
func (Item) Delete() error { return nil }
