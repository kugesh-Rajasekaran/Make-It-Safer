# Learnings

Append-only log of non-obvious discoveries. Newest last.

## 2026-11-05 · Go 1.26 can't sign from locked memory

- **What:** `crypto/ed25519` caches the key in a weak-pointer cache (`fips140cache`), which panics with "getWeakHandle on invalid pointer" when the key lives in memguard memory. Sign with a short-lived heap copy and wipe it.
- **Files:** `internal/vault/key.go`, design §4.2

## 2026-11-05 · golangci-lint needs v2.15+ for Go 1.26

- **What:** Older versions fail to load Go 1.26 packages. CI pins `v2.15.0`.
- **Files:** `.github/workflows/ci.yml`

## 2026-11-05 · Docker tests in the cloud sandbox

- **What:** Debian mirrors don't resolve in the sandbox, and Docker Hub rate-limits. Run `MIS_TEST_IMAGES=ubuntu:22.04,ubuntu:24.04`; images build with `--network host`; `mirror.gcr.io/library/ubuntu` works when Docker Hub returns 429. CI runs the full matrix.
- **Files:** `internal/testenv/testenv.go`

## 2026-11-05 · bash `read -e` ignores a trapped Ctrl-C

- **What:** With `trap : INT`, bash (outside POSIX mode) keeps `read -e` going after Ctrl-C, so a prefilled command stayed on the line and the next Enter ran it. Read the line, and run the command, in subshells with `trap - INT`. The script itself keeps the trap, so it always ends in a normal shell. Keys typed within milliseconds of Ctrl-C can be swallowed, but the prefilled command is cleared and never runs.
- **Files:** `internal/termlaunch/scripts.go`, `internal/termlaunch/integration_test.go`

## 2026-11-05 · Any program on the D-Bus session bus can send ActionInvoked

- **What:** Notification click signals are only trusted when their sender is the current owner of `org.freedesktop.Notifications`. The owner changes when the notification server restarts, so it's looked up after each `Notify`.
- **Files:** `internal/notify/dbus_linux.go`

## 2026-11-05 · apt still asks before upgrading

- **What:** `apt-get install --only-upgrade` asks "Do you want to continue? [Y/n]". We keep that confirmation (no `-y`): you see what changes before it happens.
- **Files:** `internal/fixcmd/fixcmd.go`, `internal/engine/integration_test.go`
