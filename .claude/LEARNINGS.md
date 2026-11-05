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

## 2026-11-05 · The CVE List delta log is big, newest first, and range-readable

- **What:** `cves/deltaLog.json` is ~37 MB (2.2 MB gzipped) for 30 days, newest change set first, a set every ~11 min (p10 6 min, p90 30 min), ~600 new CVEs a day. `delta.json` only holds the latest set, so polling it misses sets. raw.githubusercontent.com answers `Range` requests with 206 (and `cache-control: max-age=300`). Go's transport doesn't ask for gzip when a `Range` header is set, so ranges are plain bytes.
- **Files:** `internal/feeds/feeds.go` (`GetStart`), `internal/feeds/cvelist/delta.go`

## 2026-11-05 · CISA writes KEV status into CVE records

- **What:** CISA's ADP container adds `{"other": {"type": "kev", "content": {"dateAdded": …}}}` to the record's metrics, so a KEV listing shows up as a CVE List update; no separate KEV polling of watched CVEs is needed.
- **Files:** `internal/feeds/cvelist/cvelist.go` (`kevListed`)

## 2026-11-05 · Exact product names need a vendor check

- **What:** On real data, exact name matching alone matched "Git for Windows" (vendor `git-for-windows`, product `git`) and Tanium's "Patch" module to Debian's `git` and `patch`. Bare names now only count with a known vendor, no vendor, or a vendor that names the product; other operating systems are skipped.
- **Files:** `internal/match/match.go`, `internal/match/testdata/`
