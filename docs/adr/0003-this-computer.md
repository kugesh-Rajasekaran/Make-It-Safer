# ADR 0003 · Check the computer mis runs on, using Apple's security notes on a Mac

**Status:** accepted, 2026-11-08

## Context

`mis` only checked servers over SSH. You wanted the computer it runs on checked too, during onboarding, with "all vulnerabilities, like the VPS".

- **Linux desktops (Ubuntu, Debian)** have the same package database and OSV data as servers, so full parity is possible.
- **A Mac has no such database.** Apple and Homebrew publish none, and OSV doesn't cover them. Apple does publish a security note per release that lists the CVEs it fixes, but only as web pages.

## Decision

- **Optional.** `this_computer` in config.yaml: `mis init` asks (default yes), and `mis config` changes it. It's checked like a server, without SSH, a `mis` user or the key.
- **Linux:** the server collector runs locally and the rest is unchanged.
- **Mac, Apple updates:** for each macOS and Safari update `softwareupdate --list` offers, every CVE in Apple's notes for releases newer than the installed version, up to the offered one. Each CVE gets KEV, EPSS and CVSS like a server's, and one notification covers each update.
- **Mac, other parts:**
  - end of life from endoflife.date
  - outdated Homebrew packages as one Normal finding
  - the button opens System Settings › Software Update
- **Apple's pages are read as HTML.** `support.apple.com` is added to the network allowlist. The parsers are strict and tested against saved pages, and pages are cached (the index for 6 h, notes for 7 days) with ETags. With no data, the check fails and keeps the last findings rather than resolving them.

## Consequences

- **Your Mac gets real CVE-level findings.** The first check on a Mac 15.7.7 found 567: 59 urgent, 2 of them actively exploited.
- **Apple can change its page layout.** Parsing then finds no releases and the check reports an error (tests catch it too); it never invents or drops findings silently.
- **Not covered on a Mac:**
  - CVEs Apple hasn't fixed yet (it doesn't publish them)
  - App Store and third-party apps
  - CVE detail for Homebrew packages
- **One more outbound host:** `support.apple.com`, only when this computer is a Mac.
