# Make-It-Safer: Implementation Plan

## TL;DR

> **What we build:** `mis`, a Go command-line tool and background service for your Mac (then Linux). It finds which of your Ubuntu/Debian servers are affected by new vulnerabilities, notifies you, and opens SSH with the fix command already typed in.
> **Milestones:** 8 (M0–M7), done in order. **First usable version:** after M5.
> **Effort:** Large overall; each milestone is S, M or L.
> **Critical path:** M0 → M1 → M2 → M3 → M4 → M5 → M6 → M7

How it works: [`design.md`](design.md) · Rules for working in this repo: [`CLAUDE.md`](../CLAUDE.md) · Terms: [`CONTEXT.md`](../CONTEXT.md)

---

## 1. Context

### What you asked for
- One simple CLI that keeps vulnerability data up to date. When something new appears, it checks all your servers and tells you which are vulnerable.
- Credentials are given at setup and never stored. After a restart it asks again.
- Strictly read-only on servers. Configs stay local, with no cloud sync.
- One desktop notification per vulnerability, with a button per server: click → Terminal → SSH → update command typed in.

### Decisions
| Topic | Decision |
|---|---|
| Servers (v1) | Ubuntu, Debian |
| Your computer | Mac first, then Linux |
| Audience | Just you: install from source |
| Unlock | One passphrase per restart; the key is stored only encrypted |
| Data | OSV (confirmed), CVE List early warning (severity ≥ 9 or exploited), KEV, EPSS, end-of-life |
| Testing | Claude runs unit, lint and Docker tests; you run real-server and desktop checks |

The full list is in design §2.

---

## 2. Objectives

### Core objective
For every server you own, always know which vulnerabilities affect it, and be one click and one Enter away from fixing each one. The tool itself must never be able to change a server or leak a credential.

### Must have
- Read-only `mis` user with a forced command; pinned host keys.
- One passphrase per restart (NIST SP 800-63B-4 plus offline extras). The key is stored only encrypted; secrets live only in locked memory.
- Confirmed findings from distro data via OSV, prioritised with KEV, EPSS, CVSS and end-of-life, with reminders.
- One notification per CVE with a button per server that doesn't close it. Each button opens Terminal (configurable) → SSH with your admin login → fix command typed in.
- Early warning for severity ≥ 9 or exploited CVEs.
- `--json` on every command.

### Must NOT have
- No writes to servers by `mis`; no sudo for the `mis` user.
- No stored passphrase or admin credentials. No secrets in logs, flags, env vars or temp files.
- No automatic fixing: every fix waits for your Enter.
- No cloud sync, accounts or telemetry. No network access beyond the allowlist (design §4.9).
- No local vulnerability database.
- Not in v1: AlmaLinux/Rocky, Docker images, other alert channels, public release.

### Definition of done (verifiable)
- `make check` green in CI on Linux and macOS.
- `make test-integration` green on Ubuntu 22.04, 24.04, Debian 12 and 13.
- Every fuzz target runs for 10 minutes without a crash.
- A log-scan test proves no passphrase or key bytes appear in logs or state files.
- Your acceptance checklist (§6) passes on your Mac, a Linux desktop and your real servers.

---

## 3. How we work

**For each milestone:**
1. Create a branch from `main` (names in §7).
2. Each task is code + tests, committed as one commit. The commit message is the task's `type(scope)` and title.
3. `make check` runs before every commit (pre-commit hook).
4. At the end, Claude runs the integration tests, you do the **You check** steps, and Claude opens a PR. You review and merge.

**Who verifies what:**

| | Claude (cloud session) | You |
|---|---|---|
| Unit, fuzz and lint | ✅ | |
| Throwaway Ubuntu/Debian servers in Docker | ✅ | |
| Your real servers | | ✅ |
| Mac: notifications, Terminal, LaunchAgent, Swift helper | CI compile check only | ✅ |
| Linux desktop | tests against a fake notification server | ✅ |

🔒 marks a security-critical task. It needs tests for failure and attack cases, not just the happy path.

---

## 4. Milestones

| # | Milestone | Size | After it, you can… | Status |
|---|---|---|---|---|
| M0 | Foundations | S | run `mis version` on Mac and Linux | ✅ Done |
| M1 | Passphrase and key | M | create your passphrase and encrypted key | ✅ Done |
| M2 | Read-only server access | M | set up a server and prove it's read-only | ✅ Done |
| M3 | Vulnerability checks | L | run `mis check` and see what's vulnerable where | ✅ Done |
| M4 | Background service | M | reboot, unlock once, and checks run by themselves | ✅ Done |
| M5 | Notifications and fix flow (Mac first) | L | click a server button and get SSH with the fix typed in | ✅ Built · S2/S3 on your Mac and Linux desktop |
| M6 | Early warning | S | get heads-ups for critical CVEs within ~15 min | ✅ Done |
| M7 | Setup wizard and polish | M | set everything up with `mis init` alone | ✅ Built · your fresh-setup check pending |

### M0 · Foundations (S)
Goal: an empty but solid project.

| ID | Task | Done when |
|---|---|---|
| T-001 | `chore(git)` create `main` from the current branch; you make it the default branch on GitHub | `main` is the default branch |
| T-002 | `chore` Go module, `cmd/mis` (cobra, `mis version`), Makefile, golangci-lint config, pre-commit hook, `.gitignore`, short README | `make check` passes; `mis version --json` prints `{"ok":true,…}` |
| T-003 | `feat(config)` OS paths, `config.yaml` schema/defaults/validation, 0700/0600 enforcement, atomic writes 🔒 | Looser permissions refused (`CONFIG_PERMISSIONS_TOO_OPEN`); config round-trips |
| T-004 | `feat(cli)` JSON output envelope, error-code registry, `slog` with a redacting secret type 🔒 | Envelope shape tested; secrets log as `[redacted]` |
| T-005 | `chore(ci)` GitHub Actions: Linux `make check` on every push; macOS build on pull requests only (macOS minutes cost more on private repos) | Both jobs green |

**You check:** nothing; CI covers it.

### M1 · Passphrase and key (M)
Goal: design §4.2 and §5.2.

| ID | Task | Done when |
|---|---|---|
| T-101 | `feat(vault)` passphrase policy: NIST rules (≥ 15 code points after NFC, ≤ 1024, no composition rules), blocklist + context words, strength floor ≥ 10¹⁴ guesses, 6-word generator 🔒 | Accept/reject table tests with reasons; strength-estimator dependency justified; wordlist and blocklist licences noted |
| T-102 | `feat(vault)` key file: Ed25519, Argon2id (RFC 9106 parameters chosen by RAM), XChaCha20-Poly1305, authenticated header 🔒 | Round-trip works; wrong passphrase and tampered or truncated files rejected |
| T-103 | `feat(vault)` secure memory (memguard), core dumps off, anti-debug, unlock rate limit 🔒 | Key buffer wiped on lock; delay grows after failed attempts |
| T-104 | `feat(cli)` `mis init` (passphrase + key step) and `mis passphrase change`, TTY-only input | Piped input refused with `VAULT_TTY_REQUIRED` |

**You check (Mac):** run `mis init`. A weak passphrase is rejected with a reason and a strong one is accepted. Then `mis passphrase change` works.

### M2 · Read-only server access (M)
Goal: design §4.1.

| ID | Task | Done when |
|---|---|---|
| T-201 | `feat(inventory)` `server/collect.sh` + strict parser with size limits and validation 🔒 | Golden tests for Ubuntu and Debian output; 10-minute fuzz run clean |
| T-202 | `feat(setup)` setup/teardown templates: `mis` user, root-owned home, `restrict,command=` key, sshd drop-in, `sshd -t`, reload, rollback; `mis server setup-script` 🔒 | Golden tests; shellcheck clean |
| T-203 | `feat(sshx)` SSH client: pinned host keys, timeouts, collector call, output cap 🔒 | A changed host key fails with `SERVER_HOSTKEY_MISMATCH` |
| T-204 | `feat(cli)` `mis server add/list/remove`: fingerprint check (auto-compared with your `known_hosts`), setup through your own `ssh` | Docker: add → setup → remove works |
| T-205 | `feat(setup)` `mis server verify`: other commands, PTY, forwarding and password all refused; no privileged groups; prints OS and package count 🔒 | Docker: every refusal proven |
| T-206 | `test(integration)` Docker matrix: Ubuntu 22.04/24.04, Debian 12/13, full flow | `make test-integration` green |

**You check:** add one real server. `mis server verify` passes, and your own admin login still works.

### M3 · Vulnerability checks (L)
Goal: design §4.4. Starts with spike S1.

| ID | Task | Done when |
|---|---|---|
| S1 | `spike` query live OSV for Ubuntu (including Pro) and Debian by source package; record responses in `testdata/` | Results written into design §4.4 |
| T-301 | `feat(osv)` querybatch (chunks of 1000), details cache, ecosystem mapping, change detection (HEAD/ETag) | Tests on recorded responses; retry with backoff |
| T-302 | `feat(feeds)` KEV, EPSS and endoflife.date clients | Fixture tests |
| T-303 | `feat(findings)` finding model, state machine, JSON storage, diff against the last check | Transition table tests; illegal transitions rejected |
| T-304 | `feat(findings)` rules, priorities, reboot-required and end-of-life findings | Rule table tests |
| T-305 | `feat(cli)` `mis check`, `mis findings`, `mis show`, `mis ack` (they ask for the passphrase themselves until M4) | `--json` output tested |
| T-306 | `test(integration)` container with an old package → finding with the fixed version → upgrade → resolved | Green in Docker |

**You check:** run `mis check` on your servers. Every update that `apt list --upgradable` shows from a `-security` source appears in `mis findings`.

### M4 · Background service (M)
Goal: design §4.3.

| ID | Task | Done when |
|---|---|---|
| T-401 | `feat(daemon)` daemon + socket: 0600, same-user check, LOCKED/UNLOCKED, `mis unlock/lock/status`; the CLI uses the daemon when it's running 🔒 | Connection from another user refused; key gone after lock |
| T-402 | `feat(daemon)` scheduler: intervals from design §4.4, catch-up after sleep, backoff | Fake-clock tests |
| T-403 | `feat(daemon)` reminders by priority, stale-data warning; log-only notifier until M5 | Fake-clock tests |
| T-404 | `feat(service)` `mis service install/uninstall/status/logs`: LaunchAgent (macOS), systemd user unit (Linux) | Generated files golden-tested |

**You check (Mac):** run `mis service install` and reboot. `mis status` says LOCKED; after `mis unlock`, checks run by themselves.

### M5 · Notifications and fix flow, Mac first (L)
Goal: design §4.6 and §4.7. Starts with spike S2 on your Mac.

| ID | Task | Done when |
|---|---|---|
| S2 | `spike` (your Mac) tiny test helper: Alerts style, how many buttons show, click → close → re-post, ad-hoc signing permission prompt | Results written into design §4.6 |
| T-501 | `feat(fixcmd)` apt fix commands: validated names, kernel meta-packages + reboot hint, Ubuntu Pro note, no `sudo` for root 🔒 | Hostile package names rejected; golden commands |
| T-502 | `feat(termlaunch)` launcher + prefill (`read -e -i`); Terminal (default), iTerm2, Ghostty; Linux default chain, kitty, alacritty, wezterm, custom; `mis fix` 🔒 | Docker: the SSH session shows the prefilled command |
| T-503 | `feat(notify)` macOS helper app (Swift): per-CVE notification, server buttons + All servers…, events → daemon, re-post with ✓, Alerts-style check | CI compiles it; you check below |
| T-504 | `feat(notify)` daemon notifications: progress, ✅ resolved, lock notice, baseline summary; `mis pick`, `mis notify test` | Fake-notifier tests |
| S3 | `spike` (your Linux desktop) from the systemd user service: open a terminal and show a resident notification | Results written into design §4.6 and §7 |
| T-505 | `feat(notify)` Linux D-Bus notifier: actions, `resident`, `replaces_id`, 3-button limit, re-post fallback | Tests against a fake notification server |
| T-506 | `test(e2e)` fix → re-check → ✅ resolved | Green in Docker |

Built and tested here: T-501, T-502, T-504, T-505, T-506 (Docker: prefill, Enter, edit, Ctrl-C, upgrade from a local apt repository, ✅ resolved). CI compiles T-503. Still yours: S2 and S3, the checks below.

**You check:**
1. On your Mac, run `mis notify test`.
2. Then, on a real finding: click a server button → Terminal → SSH → command typed in → Enter → ✅.
3. Later, repeat on your Linux desktop.

### M6 · Early warning (S)
Goal: design §4.5.

| ID | Task | Done when |
|---|---|---|
| T-601 | `feat(cvelist)` poll the CVE List every 15 min, fetch new records, keep severity ≥ 9 or KEV | Recorded-feed tests |
| T-602 | `feat(match)` vendor/product → installed source package matcher + alias table | Regression tests, including known false matches (Drupal "File Force Download" ≠ `file`) |
| T-603 | `feat(findings)` early-warning lifecycle (unconfirmed → confirmed or not affected) + 🟡 notification | Replayed-feed tests |

Built: the delta log is read by byte range (64 KB per run normally). Watched CVEs are re-read when CISA updates them. Early warnings expire after 30 days without distro data. Checked against two days of real CVEs and a typical server's packages; see design §4.5.

**You check:** the first real heads-up arrives (expect about 1–2 a week) and later turns into "confirmed" or "not affected".

### M7 · Setup wizard and polish (M)

| ID | Task | Done when |
|---|---|---|
| T-701 | `feat(cli)` full `mis init` wizard: passphrase → notification test → terminal → rules → servers → service → first check | End-to-end test with a fake terminal |
| T-702 | `feat(cli)` `mis doctor`: permissions, synced folders, notifier, terminal, network allowlist, daemon, servers, feed age | A test per check |
| T-703 | `chore` `make install` / `make uninstall`: `mis`, ad-hoc-signed helper (Mac), service | Works on your Mac and on Linux |
| T-704 | `docs` `docs/user-guide.md`: install, daily use, fixing, unlocking, removing a server, troubleshooting | You can follow it alone |
| T-705 | `test` final review: threat model walk-through (design §5.1), full matrix, fuzz, log scan for secrets 🔒 | All green; anything found is fixed |

Built and tested here:
- **T-701:** the whole wizard runs end-to-end through a pseudo-terminal against a fake background service. The passphrase is never echoed, and the service is unlocked without asking twice.
- **T-702:** a test per check.
- **T-703:** works on Linux; the macOS part is yours.
- **T-705:** every fuzz target ran for 30 s, and the Docker integration suite passes on Ubuntu (Debian runs in CI). The log scan is a test now. The threat-model walkthrough found one gap: a host-key mismatch during a background refresh was only logged. It now raises an urgent notification.

**You check:** a fresh setup on your Mac using only the user guide.

---

## 5. Spikes (verify early)

| Spike | When | Question | Who |
|---|---|---|---|
| S1 | Start of M3 | How does OSV answer for Ubuntu (including Pro) and Debian source packages? | Claude |
| S2 | Start of M5 | macOS: how many buttons show in Alerts style, does re-posting work, is ad-hoc signing enough? | You run it on your Mac; Claude writes the test app |
| S3 | Before T-505 | Linux: can the systemd user service open a terminal and keep a notification on screen? | You, on your Linux desktop |

The M2 Docker matrix also proves the sshd drop-in works on each distro.

---

## 6. Acceptance checklist (you)

- [ ] `mis server verify` passes on every server, and your admin login still works.
- [ ] After a reboot: one "locked" notification, one passphrase, and checks resume.
- [ ] Every apt security update shows up in `mis findings`.
- [ ] One notification per CVE, with a button per affected server; clicking a button doesn't close it.
- [ ] Button → Terminal → SSH → fix command typed in → Enter → ✅ resolved notification within an hour.
- [ ] Weak passphrases are rejected with a reason.
- [ ] `mis doctor` is all green.

---

## 7. Commit strategy

- **Branches:** one per milestone: `chore/m0-foundations`, `feat/m1-vault`, `feat/m2-server-access`, `feat/m3-checks`, `feat/m4-daemon`, `feat/m5-notify`, `feat/m6-early-warning`, `feat/m7-wizard`.
- **Commits:** one per task, using the task's `type(scope)` and title, e.g. `feat(vault): encrypt key with Argon2id and XChaCha20-Poly1305`.
- **PRs:** one per milestone. You review and merge.
- **Docs:** design or plan changes go in the same PR as the code that needs them.

---

## 8. Success criteria

- You never have to wonder whether a server is exposed: `mis status` and the notifications tell you.
- New vulnerabilities reach you soon after distro data appears (Debian: hours; Ubuntu: about 1–2 days). Critical ones arrive as early warnings within 15–30 minutes.
- Fixing takes one click and one Enter, and is confirmed with ✅.
- No credential is ever stored in readable form, and `mis` cannot change a server.
