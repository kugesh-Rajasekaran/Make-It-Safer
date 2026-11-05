# Make-It-Safer: Design

How Make-It-Safer works and why. The step-by-step build plan is in [`implementation-plan.md`](implementation-plan.md).

Make-It-Safer is a command-line tool (`mis`) for people who run a few VPS servers across providers such as OVH. It watches for new vulnerabilities, works out which of your servers are affected, and alerts you with a desktop notification. From that notification you can open an SSH session with the fix command already typed in, waiting for you to press Enter.

---

## 1. Principles

1. **Simple:** one program, one passphrase, a few small files. No vulnerability database to maintain.
2. **Credentials are never stored in readable form:** the passphrase is never saved, and the login key is saved only encrypted.
3. **Read-only on servers:** the checker can *only* read package lists. It cannot change anything.
4. **Local:** no accounts, no cloud sync of configs, no telemetry. The internet is used only for vulnerability data and SSH.
5. **The distro decides "vulnerable":** we trust Debian and Ubuntu data, not upstream version numbers.
6. **Nothing from outside is executed:** feed text and server output are data, never commands.

---

## 2. Decisions

| Topic | Decision |
|---|---|
| Form | `mis` command-line tool, plus a background service started at login (macOS LaunchAgent, Linux systemd user service) |
| Language | Go (single binary). Small Swift helper app for macOS notifications. |
| Your computer | macOS first, then Linux desktop |
| Servers (v1) | Ubuntu and Debian. AlmaLinux/Rocky later. |
| Audience (v1) | Personal use: installed from source. No public release, no Apple notarization. |
| Confirmed vulnerabilities | OSV.dev API: the server's distro release, package names and versions in; matching vulnerabilities out |
| Early warning (unconfirmed) | Official CVE List, polled every 15 min. Only **severity ≥ 9** or actively exploited, by default. |
| Prioritisation | CISA KEV (actively exploited), EPSS (exploit probability), CVSS, OS end-of-life |
| Server access | Dedicated read-only `mis` user with a forced command. No shell, no tunnels, no sudo. |
| Login secret | One Ed25519 key, saved encrypted with your passphrase. Unlocked once per restart and held in memory only. |
| Passphrase rules | NIST SP 800-63B-4 (Aug 2025), plus extra checks because the key file could be attacked offline (§5.2) |
| Alerts | Desktop notifications only. One per CVE, one button per affected server, buttons don't close it. |
| Fix flow | Button → configured terminal (default: system Terminal) → SSH with *your* admin login → update command already typed, waiting for Enter |
| Testing | Claude: unit, lint and Docker tests with recorded data. You: real servers and your Mac/Linux desktop. |

---

## 3. Architecture

```
 YOUR COMPUTER (macOS first, then Linux)                         INTERNET (read-only data)
┌───────────────────────────────────────────────────────┐    ┌──────────────────────────────┐
│  mis (CLI)  ── unix socket (owner-only) ──┐           │    │ OSV.dev       distro vulns    │
│                                           ▼           │    │ CVE List      new CVEs        │
│  mis daemon (runs at login)                           │◄──►│ CISA KEV      exploited       │
│   ├─ Vault ........ key in memory only (locked/unlocked)   │ EPSS          exploit chance  │
│   ├─ Scheduler .... feeds, checks, reminders          │    │ endoflife.date OS support     │
│   ├─ Engine ....... findings, rules, priorities       │    └──────────────────────────────┘
│   ├─ Notifier ..... macOS helper app / Linux D-Bus    │
│   └─ Fix launcher . opens Terminal + SSH + prefill    │
│                                                       │
│  config dir   (local only, owner-only permissions)    │
│   config.yaml · key.enc · known_hosts · state/*.json  │
└──────────────┬──────────────────────────┬─────────────┘
               │ SSH as `mis` (read-only) │ SSH as YOU (admin), only when you click
               ▼                          ▼
        ┌─────────────────────────────────────────┐
        │  Ubuntu / Debian server (OVH, others…)   │
        │  user `mis` → can ONLY run               │
        │  /usr/local/lib/mis/collect (prints      │
        │  OS, kernel, installed packages)         │
        └─────────────────────────────────────────┘
```

---

## 4. Components

### 4.1 Server side: strictly read-only access

**What onboarding installs on each server** (shown to you first, then run with *your* admin login):

| Item | Detail |
|---|---|
| User `mis` | System user. No password (`*`), key login only. Shell `/bin/sh` (sshd needs a shell to run the forced command). |
| Groups | None. Verified to be **not** in `sudo`, `adm`, `docker`, `lxd`, `libvirt` or `disk`. |
| Home `/var/lib/mis` | Owned by **root** (0755), so `mis` can't write files or add its own keys |
| `~/.ssh/authorized_keys` | Root-owned, 0644: `restrict,command="/usr/local/lib/mis/collect" ssh-ed25519 AAAA… make-it-safer` |
| SSH drop-in `/etc/ssh/sshd_config.d/50-mis.conf` | See below. Fallback for systems without `sshd_config.d`: append to `sshd_config`. |
| Collector `/usr/local/lib/mis/collect` | Root-owned (0755). Reads only. Ignores any input from the client. |

```
Match User mis
    ForceCommand /usr/local/lib/mis/collect
    AuthenticationMethods publickey
    DisableForwarding yes
    PermitTTY no
    PermitUserRC no
```

**Safe apply:** validate with `sshd -t` → reload sshd → keep your admin session open → test as `mis` → only then finish. If any step fails, nothing is changed and the reason is shown.

**How setup runs:** `mis` calls your normal `ssh` program (`ssh -t you@server "sudo bash -c …"`). That `ssh` program handles your admin password or key, and `sudo` asks on your terminal. If your admin login is `root`, no `sudo` is used. `mis` **never sees your admin credentials**.

**Collector output** (plain text, versioned, no server-side dependencies):
```
mis-collect 1
os-id=ubuntu
os-version=24.04
kernel=6.8.0-49-generic
arch=amd64
reboot-required=no
groups=mis
pkg	libssl3t64:amd64	3.0.13-0ubuntu3.16	openssl	3.0.13-0ubuntu3.16
pkg	openssh-server	1:9.6p1-3ubuntu13.5	openssh	1:9.6p1-3ubuntu13.5
…
```
Commands used: `sed` on `/etc/os-release`, `uname -r`, `dpkg --print-architecture`, `test -e /var/run/reboot-required`, `id -Gn`, `dpkg-query -W -f=…`. None of them need root.

**`mis server verify`** proves the restrictions from your computer. Each of these must be *refused* for `mis` (otherwise verify reports an error):
- running any other command: asking for `id; touch /tmp/mis-was-here` returns collector output, and the file is never created
- opening a terminal (PTY)
- port forwarding (`-L`/`-R`)
- password login

It also checks that the `groups=` line shows no privileged group, and prints the OS, kernel and package count.

**Host key pinning:** at `mis server add` we show the server's SSH fingerprint.
- If your `~/.ssh/known_hosts` already trusts that server, the fingerprints are compared automatically.
- Otherwise you compare it with your provider's console.

The key is then pinned. A mismatch later blocks the connection and triggers an urgent "possible interception" alert.

**Removal:** `mis server remove` prints a teardown script (deletes the user, collector and drop-in).

### 4.2 Vault: passphrase and key

| Step | What happens |
|---|---|
| Setup | Generate an Ed25519 key. Encrypt it with your passphrase. Save `key.enc`. Install the public key on each server. |
| Restart | Daemon starts **locked** → notification "Make-It-Safer is locked, click to unlock" |
| Unlock | Click → Terminal → `mis unlock` → type passphrase → key decrypted **into locked memory** → passphrase wiped |
| Lock | Reboot, crash, logout or `mis lock` → key gone |

**Key file format (`key.enc`):**
- Argon2id key derivation, using RFC 9106 recommended parameters:
  - **2 GiB, t=1, p=4** on machines with ≥ 8 GB RAM
  - **64 MiB, t=3, p=4** otherwise
- Random 16-byte salt.
- XChaCha20-Poly1305 encryption with a random 24-byte nonce. The header (format version, KDF parameters, salt) is authenticated.
- Parameters are stored in the header so they can be raised later (`mis passphrase change`).

**Memory hygiene:**
- Secrets in `memguard` locked buffers (no swap), wiped after use.
- Core dumps disabled (`RLIMIT_CORE=0`).
- Linux: `PR_SET_DUMPABLE=0` blocks same-user debuggers. macOS: `PT_DENY_ATTACH`.
- Unlock attempts are rate-limited, with exponential delay.
- Signing uses a short-lived copy of the key, wiped right after: Go's Ed25519 code can't sign from memory outside the Go heap.
- Passphrases are typed in raw terminal mode into one pre-sized buffer, so typing leaves no stray copies.

**Passphrase rules:** see §5.2.

### 4.3 Daemon and service lifecycle

- **Install:** `mis service install` creates:
  - macOS: `~/Library/LaunchAgents/com.makeitsafer.daemon.plist` (`RunAtLoad`, `KeepAlive`)
  - Linux: `~/.config/systemd/user/mis.service` (`WantedBy=graphical-session.target`, so it starts with your desktop and can show notifications)
- It runs as **your user inside your desktop session**, which is needed for notifications and opening terminals.
- **CLI ↔ daemon:**
  - Unix socket, mode 0600. The peer is checked with `SO_PEERCRED`/`getpeereid` (same user only).
  - Commands: unlock, lock, status, check, ack, fix, …
  - When the daemon isn't running, commands that need the key ask for the passphrase themselves.
- **States:**
  - `LOCKED`: feeds and matching keep running against the **saved package lists**. No SSH.
  - `UNLOCKED`: also refreshes package lists over SSH.
- **Sleep/wake:** on wake, jobs that are overdue run immediately.

### 4.4 Vulnerability engine

**Sources and schedule:**

| Job | Source | Default interval | Needs unlock? |
|---|---|---|---|
| Feed change check | OSV `modified_id.csv` for Debian and Ubuntu (HEAD + ETag, a few bytes), plus the CISA KEV catalog (ETag) | 30 min | No |
| Match | OSV `POST /v1/querybatch` (one request per server, ≤ 1000 packages) | When a feed changed, and every 6 h regardless | No (uses saved package lists) |
| Vulnerability details | OSV `GET /v1/vulns/{id}`, cached by `modified` time | On new or changed IDs | No |
| Exploited list | CISA KEV JSON (GitHub mirror as fallback, saved copy when offline) | With the feed check | No |
| Exploit probability | EPSS API, only for findings that can alert | With each match | No |
| OS end-of-life | endoflife.date | With each match | No |
| Early warning | CVE List `deltaLog.json` | 15 min | No |
| Package lists | SSH → collector | Every 12 h, on unlock, and after a fix click | **Yes** |

**Ecosystem mapping:**

| Server | OSV ecosystem |
|---|---|
| Ubuntu 24.04 | `Ubuntu:24.04:LTS`, plus `Ubuntu:Pro:…` when the release is in extended support |
| Debian 12 | `Debian:12` |

Query by **source package name and version** (e.g. `openssh`), because that is how distros file vulnerabilities.
- Only the per-CVE distro records (`UBUNTU-CVE-…`, `DEBIAN-CVE-…`) are used; advisories (USN, DSA, DLA) repeat the same CVEs.
- A fix found only in the `Ubuntu:Pro:…` ecosystem, or marked "Available with Ubuntu Pro", is flagged as needing Ubuntu Pro.
- Records are cached without their long lists of affected versions (OSV already did the matching), keyed by their `modified` time.
- Spike S1 was done offline against real records from OSV's public data bucket, because the OSV API isn't reachable from the build sandbox. Your first `mis check` is the live confirmation.

**Findings:** one finding is (server, vulnerability, source package).
```
new ──► notified ──► (snoozed / accepted) ──► resolved ✅
 ▲                                                │
 └──────────── reopened (e.g. package downgraded) ┘
```
- **Resolved** = after a package-list refresh, OSV no longer reports it. You get a ✅ notification.
- Reboot-required (running kernel older than the newest installed one) and OS end-of-life are special findings.

**Priorities (defaults, configurable):**

| Level | Rule | Reminder |
|---|---|---|
| 🔴 Urgent | Actively exploited (KEV), or severity ≥ 9 with a fix available, or OS end-of-life | Every 4 h |
| 🟠 High | Severity ≥ 7, or EPSS ≥ 10%, or a patched kernel waiting for reboot > 3 days | Daily |
| 🟡 Normal | Other vulnerabilities with a fix available | Weekly summary |
| ⚪ Silent | No fix yet and not urgent; listed in `mis findings` only | none |

Severity is the highest CVSS base score in the CVE record (from the CNA or CISA). When there is none, the distro's own rating (Ubuntu priority, Debian urgency) stands in. Scores and EPSS are only fetched for findings that can alert (those with a fix, unless `unfixed: all`).

**Rules config (`config.yaml`):**
```yaml
rules:
  alert_when:
    actively_exploited: true     # CISA KEV
    min_severity: 7.0            # CVSS
    min_epss: 0.10
  early_warning:
    enabled: true
    min_severity: 9.0
  unfixed: urgent_only           # alert without a fix only if urgent
  ignore:
    packages: [linux-firmware]
    cves: []
  remind: { urgent: 4h, high: 24h, normal: 7d }
```

**First check after adding a server:** one *summary* notification per server ("ovh-web-1: 14 open vulnerabilities, 2 urgent"), not 14 separate ones. Alerts per CVE start from then on.

### 4.5 Early warning (unconfirmed)

1. Every 15 min, read new entries from the CVE List delta log.
2. Keep only CVEs with severity ≥ 9 (from the CNA or ADP score) or listed in KEV.
3. Match the CVE's vendor/product against installed source packages:
   - exact name match plus a vendor sanity check
   - plus a curated alias table (e.g. `OpenSSH → openssh`, `GNU C Library → glibc`, `Apache HTTP Server → apache2`, `Linux kernel → linux*`)
4. Notify 🟡 *"Heads-up (unconfirmed)"*. It has no fix command, because none is known yet. Clicking it opens `mis show CVE-…` in Terminal.
5. When distro data arrives, it is replaced by 🔴 *confirmed* or ✅ *"not affected"*.

### 4.6 Notifications

**One notification per CVE, one button per affected server, plus "All servers…".**
```
┌ Make-It-Safer ───────────────────────────────────────┐
│ 🔴 CVE-2026-XXXXX · openssh · actively exploited      │
│ 3 servers affected · fix available                    │
│ [ovh-web-1]  [ovh-db-1]  [All servers…]               │
└───────────────────────────────────────────────────────┘
```

| | macOS | Linux |
|---|---|---|
| Mechanism | Helper app `Make-It-Safer Notifier.app` (Swift, UserNotifications), talking to the daemon over the socket | D-Bus `org.freedesktop.Notifications` (no extra program) |
| Stays on screen | User must pick **Alerts** style. Onboarding checks and guides you. | `urgency=critical` + `resident=true` hint (GNOME, KDE) |
| Button click keeps it open | macOS closes it on click → daemon **re-posts it at once** with `✓` on that server | `resident` hint keeps it; we update it via `replaces_id` |
| Button limit | Alerts show actions under an "Options" menu (exact maximum verified in spike S2) | GNOME shows max 3 → 2 servers + "All servers…" |
| Clicks come from | The helper, over `notify.sock` (0600, same-user check) | Only the current owner of `org.freedesktop.Notifications`; signals from other programs on the bus are ignored |
| Clicking the body | Opens the "All servers…" picker | Same (`default` action) |

- **"All servers…"** opens a terminal picker (`mis pick CVE-…`) that stays open. Choose a server and its SSH window opens.
- **As fixes land:** "2 of 3 fixed" … then ✅ "fixed on all servers" replaces the notification.
- **Lock notice:** "Make-It-Safer is locked, click to unlock" → opens Terminal with `mis unlock`.
- **Buttons:** `notifications.max_buttons` (default 3) counts the server buttons plus "All servers…".
- **Without the background service:** `mis fix <server> [CVE]` and `mis pick <CVE>` open the same SSH sessions from the command line.

### 4.7 Fix flow: click → terminal → SSH → prefilled command

1. **Click a server button** → the daemon checks that the server and CVE exist in its own state (it ignores anything else).
2. **Write a launcher script** in a private temp dir (0700, auto-deleted). It contains no secrets.
3. **Open the terminal** (config `terminal:`):
   - **default** = macOS `open -a Terminal x.command`, or Linux `$TERMINAL` → `x-terminal-emulator` → `gnome-terminal`/`kgx`/`konsole`/`xfce4-terminal` → `xterm`
   - Also: `iterm2`, `ghostty`, `kitty`, `alacritty`, `wezterm`, or a custom `"cmd {script}"`
4. **SSH as you:** `ssh -t <admin_ssh>` (e.g. `ubuntu@51.x.x.x` or your `~/.ssh/config` alias). Your own keys and password prompts apply, and `mis` stores only this login name.
5. **On the server, before the prompt**, a short bash snippet shows the banner and runs `read -e -i "<command>"`, so the command is already typed in. Nothing runs without Enter:
```
⚠ Make-It-Safer · ovh-web-1
  CVE-2026-XXXXX  openssh  actively exploited  CVSS 9.8
  installed 1:9.6p1-3ubuntu13.5 → fixed in 1:9.6p1-3ubuntu13.8
  Enter = run · edit first · Ctrl-C = skip to normal shell

ubuntu@ovh-web-1:~$ sudo apt-get update && sudo apt-get install --only-upgrade openssh-server openssh-client▌
```
   - **Enter** runs it. apt still asks `[Y/n]`, so you see what changes first.
   - **Ctrl-C** at the prompt, or while the command runs, leaves you in a normal shell. The line is read, and the command run, in subshells with normal Ctrl-C, because bash's `read -e` ignores a trapped Ctrl-C.
   - The snippet travels base64-encoded (`bash -c "$(printf %s … | base64 -d)"`), so no quoting breaks on the way.
6. **After you run it**, the daemon refreshes that server's package list every 10 min, for up to 1 h → ✅ resolved.

**Fix command builder:**

| Case | Command |
|---|---|
| Debian/Ubuntu package | `sudo apt-get update && sudo apt-get install --only-upgrade <installed binaries of the source package>` |
| Kernel | Upgrade the installed kernel meta-packages (e.g. `linux-image-generic` on Ubuntu, `linux-image-amd64` on Debian). The banner adds: "then run `sudo reboot`" (never auto-run). |
| Restart needed (a newer kernel is installed) | `sudo reboot`, typed in like any other fix |
| Fix only via Ubuntu Pro | The same apt command; the banner adds that it needs Ubuntu Pro (`sudo pro attach`). Once attached, apt installs the fix. |
| Admin login is `root` | Same commands without `sudo` |

Package names must match `^[a-z0-9][a-z0-9+.-]{0,127}(:[a-z0-9-]{1,32})?$` and are shell-quoted. **No feed text ever enters the command.** Banner text is printed as data, with control characters removed.

### 4.8 CLI

```
mis init                         first-time setup wizard
mis server add|list|remove       manage servers
mis server verify [name]         prove read-only restrictions
mis server setup-script <name>   print setup script to run yourself
mis unlock | mis lock            give / wipe the key (memory only)
mis status                       locked?, last checks, open findings per server
mis findings [--server X]        what is vulnerable where
mis show CVE-…                   details, servers, fix commands
mis check [server]               run checks now
mis fix <server> [CVE…]          same as clicking a button
mis pick CVE-…                   server picker (used by "All servers…")
mis ack CVE-… [--server X] [--until DATE] [--reason TEXT]
mis passphrase change            re-encrypt key with a new passphrase
mis notify test                  send a test notification with buttons
mis service install|uninstall|status|logs
mis doctor                       permissions, notifier, terminal, network, servers
```

### 4.9 Files and network

Files live in `~/.config/mis` (Linux) or `~/Library/Application Support/MakeItSafer` (macOS). The directory is 0700, files are 0600, and the daemon refuses to start if they're more open.

| File | Content | Secret? |
|---|---|---|
| `config.yaml` | Servers, rules, terminal, notification options | No |
| `key.enc` | Encrypted private key | Encrypted |
| `key.pub` | Public key | No |
| `known_hosts` | Pinned server host keys | No |
| `state/inventory/<server>.json` | Last package list | No (sensitive) |
| `state/findings.json` | Findings, snoozes, notification IDs | No |
| `state/cache/` | OSV/KEV/EPSS/CVE cache and ETags | No |

There's no cloud sync and no telemetry. `mis doctor` warns if the directory sits inside a synced folder (iCloud Drive, Dropbox, …).

**Outbound connections:** `api.osv.dev`, `osv-vulnerabilities.storage.googleapis.com`, `raw.githubusercontent.com` (CVE List, KEV mirror), `www.cisa.gov`, `api.first.org`, `endoflife.date`, and your servers over SSH. Nothing else.

---

## 5. Security

### 5.1 Threat model

| Threat | Protection |
|---|---|
| Laptop stolen while off | Only `key.enc` is on disk. Argon2id + strong passphrase. |
| Laptop compromised while unlocked | The key only opens the `mis` user, which can only print package lists. Admin credentials are never held by `mis`. |
| Key file copied | Same as above. Offline guessing is slowed by Argon2id and strict passphrase rules. |
| Man-in-the-middle on SSH | Pinned host keys. A mismatch blocks the connection and raises an alert. |
| Compromised/malicious server | Collector output is treated as hostile: size limits, strict parsing, name validation, fuzz-tested parser. Nothing from it is executed. |
| Poisoned or wrong feed data | Feed text never reaches commands. Worst case is a wrong alert, not code execution. Data comes over HTTPS. |
| Another local user | 0700/0600 permissions, socket peer-UID check |
| Fake button events | The daemon acts only on (server, CVE) pairs in its own state, with commands it built itself |
| Misconfigured sshd locks you out | `sshd -t` before reload, admin session kept open, automatic rollback |

### 5.2 Passphrase standard

The baseline is **NIST SP 800-63B-4** (final, August 2025), §3.1.1.2 *Password Verifiers*:

| NIST requirement | Our implementation |
|---|---|
| Single-factor passwords: **minimum 15 characters** (SHALL) | Minimum 15 characters, counted as Unicode code points |
| Permit a maximum of at least 64 (SHOULD) | Up to 1024 characters |
| Accept printable ASCII, space and Unicode (SHOULD); NFC normalization | All accepted. NFC-normalized before key derivation. |
| **No composition rules** (SHALL NOT) | No "must contain a symbol/number" rules |
| **Blocklist** of common, expected and breached passwords, dictionary words and context words. Reject with a reason. (SHALL) | The zxcvbn estimator's bundled lists (common and breached passwords, English words, names), plus context words: `make-it-safer`, `mis`, your username, hostname and server names. The reason is shown. |
| **No periodic change**; change only on compromise (SHALL NOT / SHALL) | No expiry. `mis passphrase change` when needed. |
| **No hints** (SHALL NOT) | None stored |
| Full password verified, no truncation (SHALL) | Whole passphrase goes into Argon2id |
| Offer guidance (SHALL); allow paste and password managers (SHALL/SHOULD) | A plain-language reason for every rejection. Paste allowed. Offers a generated 6-word passphrase (EFF wordlist, ≈ 77 bits). |

**Stricter than NIST, on purpose.** NIST assumes the server limits guessing attempts. A stolen `key.enc` can be guessed **offline** without any limit, so we add:
- **Strength floor:** estimated at least 10¹⁴ guesses (≈ 47 bits) by a zxcvbn estimator. Weaker phrases are rejected with a reason.
- **Slow derivation:** Argon2id at RFC 9106 parameters (§4.2), so each guess costs about 1 s and up to 2 GiB of memory.

---

## 6. Tech stack and repository layout

| Need | Choice |
|---|---|
| CLI | `spf13/cobra` |
| SSH | `golang.org/x/crypto/ssh` (client, host-key callback for pinning) |
| Crypto | `golang.org/x/crypto/argon2`, `chacha20poly1305`; `awnumar/memguard` for secret memory |
| Prompt | `golang.org/x/term` (no echo); `golang.org/x/text/unicode/norm` (NFC) |
| Strength | Go zxcvbn port (chosen in M1) + embedded blocklist |
| Linux notifications | `godbus/dbus/v5` |
| macOS notifications | Swift helper app (SwiftPM), UserNotifications framework |
| Config | YAML (`go.yaml.in/yaml/v3`, the maintained successor of `gopkg.in/yaml.v3`); state as JSON with atomic writes |
| Install | From source: `make install` builds `mis` and the macOS helper (ad-hoc signed) |

The package layout is in `CLAUDE.md` (Layout).

---

## 7. Risks and things to verify early

| Risk | Plan |
|---|---|
| macOS: exact number of action buttons shown in Alerts style, and re-post behaviour after a click | Spike S2 on your Mac before M5. Fallback is the "All servers…" picker. |
| macOS helper signing | Ad-hoc signing (`codesign -s -`) is enough for personal use |
| Swift helper can't be built in Linux cloud sessions | You build and test it on your Mac. A macOS CI job compiles it on pull requests (macOS minutes cost more on private repos). |
| OSV naming details (Ubuntu Pro ecosystems, source package queries) | Spike S1 against the real API before M3, with recorded fixtures |
| `Match` blocks inside `sshd_config.d` drop-ins on each distro | Covered by the M2 Docker matrix. Fallback: append to `sshd_config`. |
| Linux: opening a terminal from a systemd user service needs the desktop's `DISPLAY`/`WAYLAND_DISPLAY` | Spike S3 on your Linux desktop. `mis doctor` checks it. |
| KDE/other Linux notification servers ignoring `resident` | Detect via `GetCapabilities`. Fallback: re-post like macOS. |
| OSV API unavailable | Retry with backoff. `mis status` shows feed age. Alert if data is stale for more than 24 h. |
| Laptop asleep → missed checks | Catch up on wake. Weekly summary shows the last successful check per server. |

---

## 8. Later (not in v1)

- AlmaLinux/Rocky servers (dnf/rpm)
- Docker images and hand-installed software (Trivy/OSV for containers, GitHub releases watchlist)
- Local matching mode (download distro data, nothing sent to OSV)
- Other alert channels (Telegram, email, ntfy)
- Password login for the `mis` user (fallback where keys are impossible)
- Public release: Homebrew tap, signed release builds, Apple Developer ID signing and notarization
- Optional online breach check for new passphrases (Have I Been Pwned range API)
- Quiet hours, multiple users or teams
