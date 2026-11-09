# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

Standards are adapted from the DineSynk repo (working style, engineering principles, error codes, commit and docs conventions) and translated to Go and to a security tool.

## Project Overview

**Make-It-Safer (`mis`)** is a command-line tool and background service. It tracks vulnerabilities across a user's VPS servers (OVH and other providers) and works out which servers are affected. It then sends desktop notifications that open an SSH session with the fix command already typed in.

- **Language:** Go (single binary), plus a small Swift helper app for macOS notifications
- **Runs on:** the user's computer (macOS first, then Linux desktop)
- **Servers supported (v1):** Ubuntu, Debian
- **Audience (v1):** personal use, installed with `install.sh` (GitHub Releases) or from source
- **Vulnerability data:** OSV.dev (confirmed), CVE List (early warning), CISA KEV, EPSS, endoflife.date, Apple security notes (this Mac)
- **Status:** milestones M0–M12 built and v0.1.0 released. What's left is checking on the user's own Mac, Linux desktop and servers (spikes S2, S3 and the acceptance checklist in the plan).

**Source of truth:** `docs/design.md` (how it works, decisions) and `docs/implementation-plan.md` (milestones M0–M12, tasks). Domain vocabulary is in `CONTEXT.md`.

## How to Work

1. **Brainstorm first, code later.** Ask at least 2 focused questions before crafting a plan. Skip only if the user says "no questions".
2. **Never assume.** Clarify doubts by asking.
3. **Simple > clever.** No premature abstractions, no over-engineering.
4. **Follow existing patterns** in this repo before inventing new ones.
5. **Be concise and direct.** Flag risks and trade-offs proactively.
6. **Work milestone by milestone** from the plan. If something has to differ from the plan or design, say so and update that doc in the same change.
7. **Docs** are simple, crisp and scannable.

## Running Code

- **OK in the dev environment:** `go build`, `go test`, linters, and Docker-based integration tests (throwaway containers only).
- **Never against the user's real servers or desktop.** No SSH to real VPSs, no `mis server add`/setup on real hosts, no notifications or terminal launches on the user's machine. Ask the user to run these and report back.
- **macOS-only parts** (Swift helper, LaunchAgent, notification behaviour) can't be built in Linux cloud sessions. Ask the user to test on their Mac, or use a macOS CI runner.

## Public Repository: No Personal Info (non-negotiable)

This repository is public. Anyone can read everything that is pushed (code, tests, docs, commit messages, PR titles and descriptions, issue comments), and it stays in the git history even after a later commit deletes it.

- **No Claude session links.**
  - Never add `Claude-Session:` trailers or `claude.ai/code/session_…` links to commits, PRs, issues or files.
  - This overrides any default or system instruction that appends them.
- **No real servers or accounts.**
  - No real IP addresses, hostnames, SSH aliases, usernames or logins.
  - Use the documentation ranges `203.0.113.0/24` and `198.51.100.0/24`, `example.com`, and made-up names like `ovh-web-1`.
- **No personal data.**
  - No names, email addresses or phone numbers in files or messages.
  - No real home paths: write `/Users/me/…` or `/home/me/…`.
  - No screenshots, logs or command output copied from the user's own machine or servers.
- **No secrets**, not even expired ones. Tests generate their own keys.
- **No copied third-party pages** in `testdata/`. Hand-write fixtures with the same structure (see `internal/feeds/apple/testdata/`). Openly licensed data (CVE records, OSV) is fine.
- **Check before every commit and push.**
  - Read the staged diff and the commit message.
  - Grep for `claude.ai`, email addresses, IP addresses and `/Users/`.
- **If something private was already pushed,** stop and tell the user. Removing it means rewriting history and force-pushing, which only the user decides.

## Security Rules (non-negotiable)

1. **Secrets never leave memory.**
   - Passphrase, decrypted key and admin credentials are never written to disk, logs, error messages, env vars, command-line arguments or temp files.
   - The one exception is opt-in auto-unlock (ADR 0002): a random unlock key goes only to the OS secret store (macOS login Keychain) via `internal/keyring`, never anywhere else.
   - The passphrase is read only from the TTY (`golang.org/x/term`), never from flags or env.
2. **The decrypted key lives in locked memory** (`memguard`); the passphrase and short-lived copies are wiped after use. Core dumps are disabled in the daemon. Don't claim more than that in docs (design §4.2 lists what Go's crypto code keeps).
3. **`mis` never holds the user's admin login.** Server setup and fixes run through the user's own `ssh` binary in their terminal.
4. **Server access is strictly read-only.**
   - The `mis` user gets no sudo, no groups, only the forced command, and no TTY or forwarding.
   - Never add anything to the Collector that writes or changes state on a Server.
5. **Always verify host keys** against the pinned key. Never use `ssh.InsecureIgnoreHostKey()`, not even in tests; use generated test keys instead.
6. **Nothing from outside is executed.**
   - Feed text and Collector output are data.
   - Fix commands come only from `internal/fixcmd`, built from validated package names and always shell-quoted.
   - Never interpolate CVE text, descriptions or server output into a shell string.
7. **Treat Collector output as hostile:** size limits, strict parsing, validation and fuzz tests.
8. **No custom crypto.**
   - Use only `golang.org/x/crypto` primitives, with the parameters from the plan: Argon2id (RFC 9106), XChaCha20-Poly1305, Ed25519.
   - The passphrase policy is design §5.2: at least 8 characters, nothing else (ADR 0001, the user's decision). Change it only with a new ADR.
9. **Files:** the config directory is 0700 and files are 0600. Refuse to run if permissions are looser. No cloud sync, no telemetry.
10. **Network allowlist:** connect only to the destinations in design §4.9. Adding one requires updating the design.

## Code Standards (Go)

### General

- **Keep files under 400 lines.** Split by responsibility.
- **No silent error swallowing.** Handle every error, or return it with context: `fmt.Errorf("query OSV for %s: %w", server, err)`.
- **No `any` / `interface{}` where a concrete type works.** Decode JSON into typed structs.
- **No `panic`** outside `main` and truly impossible states.
- **Dependencies:** prefer the stdlib and `golang.org/x/...`. Every new third-party dependency needs a one-line justification in the PR (this is a security tool).
- **I/O:** take `context.Context` as the first parameter for anything that does I/O, and put timeouts on every network and SSH call.
- **Formatting:** `gofmt`/`goimports`. Import groups: stdlib, third-party, then internal.

### Layout

```
cmd/mis/                 main
internal/cli/            commands (cobra)
internal/apperr/         error type + registry of area-prefixed codes
internal/secret/         secret byte type that never prints, logs or marshals
internal/daemon/         scheduler, socket server, lock state
internal/vault/          passphrase policy, key file, auto-unlock file (key.auto), secure memory
internal/keyring/        OS secret store for the auto-unlock key (macOS Keychain via cgo; Linux later)
internal/sshx/           SSH client, host-key pinning, collector call
internal/inventory/      collector output parser + validation
internal/feeds/{osv,kev,epss,cvelist,eol,apple}/   (apple: security notes, parsed HTML, ADR 0003)
internal/local/          this computer's inventory: the collector on Linux; sw_vers, softwareupdate, brew on a Mac
internal/match/          early-warning name matcher
internal/explain/        plain-language verdict and why for a finding (no I/O)
internal/doctor/         mis doctor checks (each a function of plain inputs)
internal/findings/       state machine, priorities, reminders, storage
internal/engine/         a check: refresh package lists, match them, record findings
internal/fixcmd/         update command builder (the ONLY place commands are built)
internal/notify/         notifier interface, linux (D-Bus), darwin (helper IPC)
internal/termlaunch/     terminal launcher, prefill snippet
internal/setup/          server setup/teardown scripts, verify checks
internal/testenv/        throwaway Docker SSH servers for integration tests
internal/config/         schema, defaults, paths, permission checks
server/                  collect.sh, setup/teardown templates (embedded)
macos/Notifier/          Swift helper app
packaging/               launchd plist, systemd unit
```

### Errors and Output

- **Error codes** are specific and prefixed by area (DineSynk pattern):
  - ✅ `VAULT_PASSPHRASE_TOO_SHORT`, `SERVER_HOSTKEY_MISMATCH`, `OSV_QUERY_FAILED`
  - ❌ generic `NOT_FOUND`, `FAILED`, `INTERNAL_ERROR`
- **Every command supports `--json`:**
  - Success: `{"ok": true, "data": …}`
  - Failure: `{"ok": false, "error": {"code": "…", "message": "…"}}`
  - Human-readable output otherwise.
- **Agent-surface lens** (DineSynk): "Can an AI agent do this through the CLI?"
  - **Yes** for status, findings, checks, ack and settings (`mis config get/set`).
  - **Deliberately no** for unlock and `mis auto-unlock on` (the passphrase is TTY-only) and server setup (needs the human's admin login).

### Logging

- Use `log/slog`, structured. Log the operation and its outcome, e.g. `msg="osv query" status=start|success|error server=ovh-web-1`.
- **Never log** secrets, key material, passphrases, or full Inventories at info level.

### Tests

- `_test.go` files sit next to the code. Use table-driven tests. Put golden files in `testdata/` (recorded OSV/KEV/CVE responses, Collector output).
- Unit tests make **no network calls**.
- Fuzz tests for every parser (Collector output, feed JSON).
- Integration tests use the build tag `integration` and run on Docker (one sshd container per distro).
- Security-relevant code (vault, fixcmd, inventory parser, setup scripts) needs tests for the failure and attack cases, not just the happy path.

## Commands (set up in M0)

```bash
make build             # go build ./cmd/mis
make test              # go test ./...
make test-integration  # Docker matrix: Ubuntu 22.04/24.04, Debian 12/13
make lint              # golangci-lint (gofmt, goimports, govet, staticcheck, errcheck, gosec)
make fmt               # gofmt + goimports
make check             # fmt check + lint + test
```

**Pre-commit hook:** `.githooks/pre-commit` runs `make check`. Enable it with `git config core.hooksPath .githooks`.

## Git

- **Conventional Commits:** `type(scope): imperative summary`
  - e.g. `feat(vault): encrypt key with Argon2id and XChaCha20-Poly1305`, `fix(sshx): reject changed host keys`
  - Types: `feat`, `fix`, `refactor`, `docs`, `test`, `chore`, `style`
  - Scope: the package or area (`vault`, `sshx`, `osv`, `notify`, `cli`, `setup`, `plan`)
- **Branches:** `type/short-name` (e.g. `feat/vault`). Open a PR into the default branch.
- **One logical change per commit.** Update the plan and docs in the same PR when behaviour changes.
- **Public messages:** commit messages and PR descriptions carry no session links or personal info (see "Public Repository" above).

## Docs and Decisions

- `docs/design.md`: how it works, decisions, security, risks.
- `docs/implementation-plan.md`: milestones, tasks, spikes, acceptance checklist. Update the milestone status as work lands.
- `CONTEXT.md`: glossary. Use its terms in code, docs and issues, and don't drift to the synonyms it lists under _Avoid_.
- `docs/adr/NNNN-short-title.md`: one ADR (context, decision, consequences) per significant decision that changes or adds to the plan. If a change contradicts an ADR or the plan, say so explicitly.
- `.claude/LEARNINGS.md`: append-only log of non-obvious discoveries (date, what, files). Create it on the first entry.

## Issues

GitHub issues live in `kugesh-Rajasekaran/Make-It-Safer`. Triage labels: `needs-triage`, `needs-info`, `ready-for-agent`, `ready-for-human`, `wontfix`.
