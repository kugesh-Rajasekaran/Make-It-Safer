# ADR 0002 · Auto-unlock with the macOS Keychain

**Status:** accepted, 2026-11-07 (macOS); Linux planned

## Context

After every restart the background service started locked until you typed your passphrase (`mis unlock`). While locked it still matches new vulnerabilities against saved package lists, but it can't refresh them. You asked for it to start working with no typing after a restart.

## Decision

- **Optional auto-unlock.** `mis init` asks (default yes); `mis auto-unlock on|off` changes it later.
- **Two ways to open the key.** `key.enc` stays as it is (passphrase + Argon2id). `key.auto` holds the same key encrypted with XChaCha20-Poly1305 under a random 256-bit **unlock key**. Its authenticated header carries the public key, which must match `key.enc`.
- **The unlock key lives only in the login Keychain:** a generic password named "Make-It-Safer auto-unlock", whose account is Make-It-Safer's folder. macOS unlocks the login Keychain when you log in. The passphrase is still never stored.
- **Every read, write and delete is pinned to the login keychain, opened by its path** (`kSecUseKeychain`, `kSecMatchSearchList`). Without that, `SecItemAdd` writes to the *default* keychain, and any program running as you can switch the default, with no prompt, to a keychain whose password it knows. That would quietly capture the unlock key. Found in the security review. Pinning needs the deprecated `SecKeychainOpen`: the data-protection keychain would avoid it, but needs an Apple-issued signing identity.
- **The daemon unlocks itself at start.** If that fails (item missing, access denied), it stays locked and shows the usual notice. `mis lock` still wins until `mis unlock` or the next start, including over an unlock that was still in progress.
- **The Security framework is called through cgo**, with no third-party library. The `security` command-line tool was rejected for two reasons: it would put the secret in a command line, and items it saves trust that tool, so any program could read them through it.
- **Ad-hoc builds and Keychain trust.** macOS trusts only the exact build that saved an item, and `mis` is ad-hoc signed, so every update is a new build. On your Mac, "Always Allow" didn't stop the prompt for the same rebuilt binary. So after each successful read the item is saved again, which makes the running build its owner: one prompt per update, then silence.

## Consequences

- **No typing after a restart**, only your Mac login. After `make install`, one Keychain prompt.
- **Exposure while logged in:** a separate program running as you can't read the item silently (macOS asks), but it can use the unlocked daemon, as it could anyway while unlocked. A program that gets code *into* `mis` itself could read the item silently. `mis` isn't built with the hardened runtime yet, which would block `DYLD_INSERT_LIBRARIES`; that's a follow-up. In every case the key only opens the read-only `mis` user (package lists).
- **A stolen, powered-off Mac:** the login Keychain is encrypted with your login password (plus FileVault), and `key.auto` alone is useless.
- **cgo on macOS.** The Linux build has no cgo and returns `KEYRING_UNAVAILABLE`. Linux support means a Secret Service (GNOME Keyring, KWallet) store behind the same `vault.SecretStore` interface.
- **A stable Developer ID signature** (public release) would make "Always Allow" last; the re-save then becomes a no-op.
