# ADR 0001 · Passphrase: at least 8 characters, nothing else

**Status:** accepted, 2026-11-07

## Context

M1 shipped the NIST SP 800-63B-4 rules plus extras: at least 15 characters, a blocklist of common and breached passwords and context words, and a zxcvbn strength floor of 10¹⁴ guesses. On the first real onboarding the user found this too hard. They rejected an 8-character passphrase, then a longer one with repeated words.

## Decision

- A passphrase needs **at least 8 characters** (Unicode code points after NFC) and at most 1024.
- No blocklist, no context words, no strength estimate.
- The generated 6-word passphrase (≈ 77 bits) is still offered when you press Enter.
- The `zxcvbn` dependency and the `VAULT_PASSPHRASE_TOO_WEAK` code are removed.

## Consequences

- **Looser than NIST** on two SHALLs: the 15-character minimum and the blocklist (design §5.2).
- **Residual risk:** if `key.enc` is copied off your computer, a common or short passphrase (e.g. `password`) can be guessed offline quickly, even at Argon2id's ~1 s and 2 GiB per guess.
- **Impact if guessed:** read-only access as the `mis` user, which can only list installed packages. Your admin login is never stored, so it isn't exposed.
- Onboarding gets simpler and has one less third-party dependency (plus 7 indirect ones).
