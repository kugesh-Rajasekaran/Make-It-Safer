# Make-It-Safer: Design

How Make-It-Safer works and why. The step-by-step build plan is in [`implementation-plan.md`](implementation-plan.md).

Make-It-Safer is a command-line tool (`mis`) for people who run a few VPS servers across providers such as OVH. It watches for new vulnerabilities, works out which of your servers are affected, and alerts you with a desktop notification. From that notification you can open an SSH session with the fix command already typed in, waiting for you to press Enter.

---

## 1. Principles

1. **Simple:** one program, one passphrase, a few small files. No vulnerability database to maintain.
2. **Credentials are never stored in readable form:** the passphrase is never saved, and the login key is saved only encrypted.
3. **Read-only on servers:** the checker can *only* read package lists. It cannot change anything.
4. **Local:** no accounts, no cloud sync of configs, no telemetry. The internet is used only for vulnerability data and SSH. Matching sends package names and versions to OSV.dev, never server names or addresses (§4.9).
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
| Audience (v1) | Personal use. Installed with `install.sh` from GitHub Releases, or from source. No Apple notarization: the macOS helper is ad-hoc signed. |
| Confirmed vulnerabilities | OSV.dev API: the server's distro release, package names and versions in; matching vulnerabilities out |
| Early warning (unconfirmed) | Official CVE List, polled every 15 min. Only **severity ≥ 9** or actively exploited, by default. |
| Prioritisation | CISA KEV (actively exploited), EPSS (exploit probability), CVSS, OS end-of-life |
| Server access | Dedicated read-only `mis` user with a forced command. No shell, no tunnels, no sudo. |
| Login secret | One Ed25519 key, saved encrypted with your passphrase. Unlocked once per restart (or by itself at login with auto-unlock, macOS Keychain) and held in memory only. |
| Passphrase rules | At least 8 characters; looser than NIST SP 800-63B-4 by choice (§5.2, ADR 0001) |
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

**Safe apply:** the script makes its changes, then checks them before it reloads sshd: `sshd -t` accepts the config; `root` and your admin login get the same effective settings as before; `mis` gets the forced command and the restrictions; and sshd's `AllowUsers`, `DenyUsers`, `AllowGroups` and `DenyGroups` don't lock `mis` out. Only then does it reload sshd. If a check fails, up to and including the reload, or your session drops or is stopped part-way, the script undoes what it changed and shows the reason. Running it again is safe.

The login as `mis` is tested afterwards, by `mis server add` (the same checks as `mis server verify`). If a check fails, the server stays set up: the failed checks are listed, and you can fix it, re-run `mis server verify`, or take the server out with `mis server remove`.

**How setup runs:** `mis` calls your normal `ssh` program (`ssh -t you@server '…'`) and pipes the script, base64-encoded, into `sh` on the server. That `ssh` program handles your admin password or key, and `sudo` asks on your terminal. If your admin login is `root`, no `sudo` is used. `mis` **never sees your admin credentials**.

**Collector output** (plain text, versioned, no server-side dependencies):
```
mis-collect 1
os-id=ubuntu
os-version=24.04
kernel=6.8.0-49-generic
arch=amd64
reboot-required=no
groups=mis
pkg	ii 	libssl3t64:amd64	3.0.13-0ubuntu3.16	openssl	3.0.13-0ubuntu3.16
pkg	ii 	openssh-server	1:9.6p1-3ubuntu13.5	openssh	1:9.6p1-3ubuntu13.5
…
```
Each `pkg` line is, separated by tabs: the dpkg status (`ii ` = installed), the binary package, its version, the source package and the source version. Commands used: `sed` on `/etc/os-release`, `uname -r`, `dpkg --print-architecture`, `test -e /var/run/reboot-required`, `id -Gn`, `dpkg-query -W -f=…`. None of them need root.

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

**Removal:** `mis server remove` runs a teardown script through your own `ssh` login (deletes the user, collector and drop-in), then forgets the server: its settings, pinned host key, package list and findings. The script ends the user's sessions first; if the user still can't be deleted, it stops with an error and keeps its marker, so it can be run again. `--forget` skips the script and only forgets the server. For this computer there is nothing to delete: `mis server remove this-mac` (`this-computer` on Linux) just stops checking it.

### 4.2 Vault: passphrase and key

| Step | What happens |
|---|---|
| Setup | Generate an Ed25519 key. Encrypt it with your passphrase. Save `key.enc`. Install the public key on each server. |
| Restart | Daemon starts **locked** → notification "Make-It-Safer is locked, click to unlock", shown again once a day while it stays locked. With auto-unlock on, it unlocks itself instead (below). |
| Unlock | Click → Terminal → `mis unlock` → type passphrase → key decrypted **into locked memory** → passphrase wiped |
| Lock | Reboot, crash, logout or `mis lock` → key gone. After `mis lock` it stays locked until `mis unlock` or the next start. |

**Auto-unlock (optional, macOS; [ADR 0002](adr/0002-auto-unlock-keychain.md)):**
- `key.auto` holds the same key, encrypted (XChaCha20-Poly1305, authenticated header with the public key) with a random 256-bit **unlock key**.
- The unlock key lives in your **login Keychain**: item "Make-It-Safer auto-unlock", account = Make-It-Safer's folder, so separate installs never share one. macOS unlocks that Keychain when you log in.
- Every Keychain call is pinned to the login keychain by its path, never the *default* keychain, which any program running as you can switch.
- At start the daemon reads the unlock key and opens `key.auto`; no passphrase. The passphrase itself is still never stored, and `mis passphrase change` doesn't affect auto-unlock.
- `key.auto` must match `key.enc`'s public key. A leftover from an older key fails safely (locked + notice), and `mis init` removes it.
- macOS trusts only the build of `mis` that saved the item. `mis` is ad-hoc signed, so after each update macOS asks once ("Always Allow" doesn't last for ad-hoc builds). The daemon then saves the item again as the new build, and macOS stops asking.
- On, off: `mis init` asks (default yes), or `mis auto-unlock on|off`. Linux (Secret Service) is planned.

**Key file format (`key.enc`):**
- Argon2id key derivation, using RFC 9106 recommended parameters:
  - **2 GiB, t=1, p=4** on machines with at least 8 GiB of usable memory (a Linux computer sold as 8 GB may report a little less and get the 64 MiB setting)
  - **64 MiB, t=3, p=4** otherwise
- Random 16-byte salt.
- XChaCha20-Poly1305 encryption with a random 24-byte nonce. The header (format version, KDF parameters, salt) is authenticated.
- Parameters are stored in the header so they can be raised later (`mis passphrase change`).

**Memory hygiene:**
- The decrypted key lives in a `memguard` locked buffer (no swap): in the daemon for as long as it is unlocked, and in a `mis` command that unlocks the key itself (`mis init`, `mis server add` and `verify`, `mis check` when the service is locked or not running, `mis auto-unlock on`, `mis passphrase change`) until that command ends.
- The passphrase, the socket line carrying it, and the short-lived key copies used to unlock and sign are ordinary memory, wiped after use. Go's crypto code keeps copies it can't be asked to wipe: the expanded Ed25519 key in its key cache, and the key schedule inside each XChaCha20-Poly1305 object. They stay until the memory is reused.
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
  - When the daemon isn't running or is locked, commands that need the key ask for the passphrase themselves.
- **States:**
  - `LOCKED`: feeds and matching keep running against the **saved package lists**. No SSH.
  - `UNLOCKED`: also refreshes package lists over SSH.
- **Sleep/wake:** on wake, jobs that are overdue run immediately.

### 4.4 Vulnerability engine

**Sources and schedule:**

| Job | Source | Default interval | Needs unlock? |
|---|---|---|---|
| Feed change check | OSV `modified_id.csv` for Debian and Ubuntu (HEAD + ETag, a few bytes), plus the CISA KEV catalog (ETag) | 30 min | No |
| Match | OSV `POST /v1/querybatch` (all servers together, ≤ 1000 queries per request) | When a feed changed, and every 6 h regardless | No (uses saved package lists) |
| Vulnerability details | OSV `GET /v1/vulns/{id}`, cached by `modified` time | On new or changed IDs | No |
| Exploited list | CISA KEV JSON (GitHub mirror as fallback, saved copy when offline) | With the feed check | No |
| Exploit probability | EPSS API, only for findings that can alert | With each match | No |
| OS end-of-life | endoflife.date | With each match | No |
| Early warning | CVE List `deltaLog.json` (its newest part, by byte range) + the new CVE records | 15 min | No |
| Package lists | SSH → collector | Every 12 h, on unlock, and after a fix click | **Yes** |
| This computer | Read directly (§4.10); on a Mac, Apple security notes | With each match | No |

The four timers are settings (`schedule` in config.yaml, **Checks** in `mis config`), each with a minimum so the sources aren't asked too often: new CVEs ≥ 5 min, data changes ≥ 10 min, full check ≥ 30 min, servers ≥ 1 h (all ≤ 7 days). A shorter value applies within a minute. Sending due notifications stays every 15 min.

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
new ──► notified ──► (snoozed ⇄ accepted) ──► resolved ✅
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
| 🟡 Normal | Other vulnerabilities with a fix available | Weekly summary (counts what is open: not snoozed, accepted or fixed) |
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

**First check after adding a server:** one *summary* notification per server ("ovh-web-1: 14 open vulnerabilities, 2 urgent"), not 14 separate ones. Alerts per CVE start from then on. This holds whichever process runs that first check: the first check records its findings as already announced, so `mis check` while the service is locked doesn't cause a flood at the next reminder.

### 4.5 Early warning (unconfirmed)

1. **Every 15 min, read what changed in the CVE List.**
   - `cves/deltaLog.json` lists every change set of the last 30 days, newest first: about 37 MB, with a new set every ~11 min.
   - Only its start is read with an HTTP range request: 64 KB covers the usual 15 minutes. After a longer gap it reads 1 MB, then 8 MB, then the whole file.
   - The first run, or a gap longer than the log, starts from now. OSV covers anything older.
2. **Read each new CVE record** (about 600 a day, a few KB each).
3. **Keep the severe ones:** CVSS ≥ `rules.early_warning.min_severity` (default 9, from the CNA or CISA), or actively exploited (CISA KEV, or KEV noted in the record by CISA).
4. **Match the record's products to installed source packages** (`internal/match`):
   - Exact name after normalising case and punctuation (`XZ Utils` = `xz-utils`), from the CNA's and CISA's product and package names.
   - A curated alias table, e.g. `OpenSSH → openssh`, `GNU C Library → glibc`, `Apache HTTP Server → apache2`, `xz → xz-utils`, `PostgreSQL → postgresql-NN`, `Linux kernel → the kernel`.
   - **Vendor sanity check:** a bare product name only counts when the vendor is missing, known (an upstream project or distro), or names the product itself (`RsyncProject`). On two days of real CVEs this rejected "Git for Windows" → `git` and Tanium's "Patch" → `patch`.
   - Skipped: language-registry packages (npm, PyPI, …), CMS plugins and themes, and other operating systems.
5. **Skip it if the distro already has a record** (`UBUNTU-CVE-…`, `DEBIAN-CVE-…` on OSV), or the server already has a finding for that CVE. The regular check handles those.
6. **Not severe yet, or no product named yet?** Watch it for 7 days: CISA often adds scores, products and KEV status to the record later, and every change to a watched CVE is read again.
7. **Notify once:** 🟡 *"Heads-up · CVE-… · openssh"*, *"Not confirmed by your distro yet · may affect 2 servers · CVSS 9.8 · no fix yet"*. It has no buttons, because there is no fix command yet. Clicking it opens its dialog (§4.6), or `mis show CVE-…` without one. It is never reminded.
8. **It ends at the next regular check** after the distro speaks:
   - **Confirmed:** a vulnerability finding exists for the server and CVE. The heads-up is removed and the normal alert takes over.
   - **Not affected:** the distro has a record, but OSV doesn't report it for the installed version. You get ✅ *"not affected"*.
   - **Expired:** no distro record after 30 days. It ends quietly.

On a typical server (369 source packages), two days of real CVEs (1,236 records) gave three matches, all correct: apt, rsync, glibc. None was severe enough to notify.

**Threshold note:** CVE-2024-6387 (regreSSHion) is scored 8.1, so the default `min_severity: 9` would not have raised an early warning for it. Lower it (e.g. 8) for more heads-ups, at the cost of more noise.

### 4.6 Notifications

**Why it matters, in plain words** (`internal/explain`). Every vulnerability gets a verdict and one line saying why:
- **Verdict** from the priority (§4.4): urgent → *Act now*, high → *This week*, normal → *Can wait*, no fix → *No fix yet*, ignored (silent with a fix) → *Ignored*. The text can't disagree with the priority.
- **Why line** from fixed rules: "being exploited" (CISA KEV), or "N% chance of attacks soon" when EPSS (≥ 10%) made the finding high or urgent; then from the CVSS vector, how it's reached (remotely / local network / local access / someone opening a malicious file / physical; login, admin login or none; user action) and what it allows to the affected software (take it over / read data / change data / crash it). It is never cut short. For Apple's software, Apple's "Impact:" sentence comes first. Without a vector: the source's impact sentence (first sentence; ≤ 80 characters, cut at a word, in one-line places; whole in `mis show`), else the distro's rating.
- **Honest wording:** CVSS "network" means the attack data can arrive over the network, not that the server is reachable from the internet, so it says "can be triggered remotely".
- **Facts kept per finding** at check time: the CVSS vector, the first CWE and the description from the CVE record, Apple's "Impact:" sentence per CVE, CISA's short description. Display only, cleaned of control and formatting characters.
- **Shown in** the notification (second line; an Apple update shows "Worst: …", the worst fix Apple described, in Apple's words), `mis findings` (verdict column, why on the line below), `mis show` (verdict, what an attacker could do, how it's triggered, severity, being exploited, servers, one fix line per server, details, weakness; wrapped to 80 columns) and the fix banner ("Why: …", naming the CVE when several are listed) and the dialog (below).
- `mis show` is about the most severe open finding of the CVE ("FIXED" when none is open), and looks the CVE record up when a finding has none (findings without a fix aren't looked up during checks); offline it says the record couldn't be loaded.

**One notification per CVE, one button per affected server, plus "All servers…".**
```
┌ Make-It-Safer ───────────────────────────────────────┐
│ 🔴 CVE-2026-XXXXX · openssh · actively exploited      │
│ Can be triggered remotely, no login · could take it   │
│ over                                                  │
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
| Clicks come from | The helper, over `notify.sock` (0600, same-user check) | Only the current owner of `org.freedesktop.Notifications`; signals from other programs on the bus are ignored. Dialog buttons: the zenity process the daemon started |
| Clicking the body (or "All servers…") | Opens the dialog: a window of the helper app | Opens the dialog with `zenity` (optional: the release build has no GUI libraries) |

- **Dialog** (vulnerability, heads-up, restart and Apple update notifications): the verdict; **what it is** (the `mis show` facts, "Why it matters" above); **the fix**, with the exact command (one line, or one per server when they differ); **what it affects**, a row per server with **Update** (**Restart**, **Open Software Update**). No button where there's nothing to run.
  - All text is plain: AppKit labels on macOS, `zenity --no-markup` on Linux. A button sends back only `fix:<server>`, which the daemon checks like a notification button (§4.7).
  - It stays open until closed. After **Update** the daemon marks that server ✓: on macOS the open window updates in place and stays behind the terminal the button opened; zenity closes on a button, so it reopens. The notification isn't re-posted.
  - **No dialog** (helper not connected, no zenity): the click does what it did before: the terminal picker `mis pick CVE-…` (stays open; choose a server and its SSH window opens), `mis show CVE-…` for a heads-up, the fix itself for a restart or Apple update. `mis doctor` warns when zenity is missing.
- **As fixes land:** "2 of 3 fixed" … then ✅ replaces the notification: "fixed on all servers" for a CVE, "macOS 15.8.2 installed" for an Apple update, "web restarted" after a restart.
- **Lock notice:** "Make-It-Safer is locked, click to unlock" → opens Terminal with `mis unlock`.
- **Buttons:** `notifications.max_buttons` (default 3) counts the server buttons plus "All servers…".
- **Without the background service:** `mis fix <server> [CVE]` and `mis pick <CVE>` open the same SSH sessions from the command line.

### 4.7 Fix flow: click → terminal → SSH → prefilled command

1. **Click a server button** → the daemon checks that the server and CVE exist in its own state (it ignores anything else).
2. **Write a launcher script** in a private temp dir (0700, auto-deleted). It contains no secrets.
3. **Open the terminal** (config `terminal:`):
   - **default** = macOS `open -a Terminal x.command`, or on Linux the first that exists of `$TERMINAL` (only a plain program name: it is ignored if it has a space or `/`), `x-terminal-emulator`, `gnome-terminal`, `konsole`, `xfce4-terminal`, `kgx`, `kitty`, `alacritty`, `wezterm`, `ghostty`, `xterm`
   - Also: `iterm2`, `ghostty`, `kitty`, `alacritty`, `wezterm`, or a custom `"cmd {script}"`. The custom command is split on spaces and quotes aren't understood, so the program and its arguments can't contain spaces (`{script}` itself may expand to a path with spaces).
   - `$TERMINAL` gets the same arguments as the terminal of that name in the list (`wezterm start --`, kitty takes the script as is), and `-e` when it isn't in the list.
   - **A terminal that doesn't open is an error.** On macOS the daemon waits (up to 10 s) for `open` to accept the request; on Linux a terminal that exits at once with an error counts as failed. The click then shows an error notification (with what the terminal said): no ✓ on the button and no follow-up checks.
4. **SSH as you:** `ssh -t <admin_ssh>` (e.g. `ubuntu@51.x.x.x` or your `~/.ssh/config` alias). Your own keys and password prompts apply, and `mis` stores only this login name.
5. **On the server, before the prompt**, a short bash snippet shows the banner and runs `read -e -i "<command>"`, so the command is already typed in. Nothing runs without Enter:
```
Make-It-Safer · ovh-web-1
  CVE-2026-XXXXX  openssh  installed 1:9.6p1-3ubuntu13.5 → fixed in 1:9.6p1-3ubuntu13.8  (actively exploited)
  Why: being exploited · can be triggered remotely, no login · could take it over
Enter = run · edit it first · Ctrl-C = skip to a normal shell

ubuntu@ovh-web-1:~$ sudo apt-get update && sudo apt-get install --only-upgrade openssh-server openssh-client▌
```
   One line per finding (at most 8, then "…and N more"), then why the most severe one matters. Notes follow, each marked with ⚠: for example that the fix comes from Ubuntu Pro, or that you should restart afterwards.
   - **Enter** runs it. apt still asks `[Y/n]`, so you see what changes first.
   - **Ctrl-C** at the prompt, or while the command runs, leaves you in a normal shell. The line is read, and the command run, in subshells with normal Ctrl-C, because bash's `read -e` ignores a trapped Ctrl-C.
   - The snippet travels base64-encoded (`bash -c "$(printf %s … | base64 -d)"`), so no quoting breaks on the way.
6. **After you run it**, the daemon refreshes that server's package list every 10 min, for up to 1 h → ✅ resolved.

**Fix command builder:**

| Case | Command |
|---|---|
| Debian/Ubuntu package | `sudo apt-get update && sudo apt-get install --only-upgrade <installed binaries of the source package>` |
| Kernel | Upgrade the installed kernel meta-packages (e.g. `linux-image-generic`, `linux-generic-hwe-22.04` or `linux-oem-24.04` on Ubuntu, `linux-image-amd64` on Debian). The banner adds: "then run `sudo reboot`" (never auto-run). |
| Restart needed (a newer kernel is installed) | `sudo reboot`, typed in like any other fix |
| Fix only via Ubuntu Pro | The same apt command; the banner adds that it needs Ubuntu Pro (`sudo pro attach`). Once attached, apt installs the fix. |
| Admin login is `root` | Same commands without `sudo` |

Package names must match `^[a-z0-9][a-z0-9+.-]{0,127}(:[a-z0-9-]{1,32})?$` and are shell-quoted. **No feed text ever enters the command.** Banner text is printed as data, with control characters removed.

### 4.8 CLI

```
mis init                         setup wizard: passphrase → terminal → alerts → servers →
                                 background service (unlocked) → test notification → first check
mis server add|list|remove       manage servers
mis server verify [name]         prove read-only restrictions
mis server setup-script         print the setup script to run yourself
mis unlock | mis lock            give / wipe the key (memory only)
mis auto-unlock on|off           unlock by itself at login, with an unlock key in the Keychain
mis config                       every setting in one list: ↑/↓ move, Enter change, q quit
mis config get [name] | set <name> <value>   the same settings for scripts and agents
mis status                       locked?, last checks, open findings per server
mis findings [--server X]        what is vulnerable where
mis show CVE-…                   act now or later and why, servers, fix, details
mis check [server]               run checks now
mis fix <server> [CVE-…]         with a CVE: same as clicking that button; without one: everything fixable on the server
mis pick CVE-…                   server picker (used by "All servers…")
mis ack CVE-… [--server X] [--until DATE] [--reason TEXT]
mis passphrase change            re-encrypt key with a new passphrase
mis notify setup                 allow notifications (opens System Settings on macOS, checks), then a test
mis notify test                  send a test notification with buttons
mis service install|uninstall|status|logs
mis doctor                       files, sync, service, notifications, terminal, desktop session,
                                 data sources (incl. Apple's security notes on a Mac that checks itself),
                                 servers, data age; each problem with its fix
```

### 4.9 Files and network

Files live in `~/.config/mis` (Linux) or `~/Library/Application Support/MakeItSafer` (macOS). The directory is 0700, files are 0600, and the daemon refuses to start if they're more open.

| File | Content | Secret? |
|---|---|---|
| `config.yaml` | Servers, rules, terminal, notification options | No |
| `key.enc` | Encrypted private key | Encrypted |
| `key.auto` | Same key, encrypted with the auto-unlock key (only while auto-unlock is on) | Encrypted |
| `key.pub` | Public key | No |
| `known_hosts` | Pinned server host keys | No |
| `state/inventory/<server>.json` | Last package list | No (sensitive) |
| `state/findings.json` | Findings, snoozes, notification IDs | No |
| `state/cache/` | OSV/KEV/EPSS/CVE cache and ETags. The CVE and OSV record files not written for 30 days are deleted, checked once a day | No |

There's no cloud sync and no telemetry. `mis doctor` warns if the directory sits inside a synced folder (iCloud Drive, Dropbox, …).

**Outbound connections:** `api.osv.dev`, `osv-vulnerabilities.storage.googleapis.com`, `raw.githubusercontent.com` (CVE List, KEV mirror), `www.cisa.gov`, `api.first.org`, `endoflife.date`, `support.apple.com` (Apple security notes, only when this computer is a Mac, ADR 0003), and your servers over SSH. Nothing else. A redirect is followed only to another URL on this list over HTTPS; any other is refused. (`softwareupdate`, which `mis` runs to read a Mac, contacts Apple itself, as it always does. `brew outdated` runs with Homebrew's auto-update and analytics switched off.)

**What is sent:**
- To `api.osv.dev`: one query per installed source package of the checked servers and of a Linux desktop, with the package name, its version and the OS release as OSV's ecosystem (e.g. `Debian:12`; Ubuntu LTS releases are asked twice, standard and Pro). Then it fetches the records that matched, by ID (for an early warning, also the distro's record of a CVE ID). A Mac's package list is never sent: it is matched against Apple's notes on your computer.
- To `api.first.org` (EPSS) and `raw.githubusercontent.com` (CVE List): the CVE IDs of findings that can alert (§4.4), and the CVE you ask about with `mis show`.
- Everything else is a plain download (KEV, endoflife.date for the operating systems you use, Apple's public pages).
- Not sent: server names, host names, IP addresses, SSH logins, kernel versions.
- Every request carries `User-Agent: make-it-safer/<version>`, and the service sees your computer's IP address, as with any web request.

### 4.10 This computer (optional)

The computer `mis` runs on can be checked too: `mis init` asks (default yes), or `this_computer` in `mis config`. Nothing is installed or changed for it: no `mis` user, no SSH, no key needed, so it's checked even while locked.

| | Linux desktop (Ubuntu, Debian) | Mac |
|---|---|---|
| Read with | The same collector as servers, run directly | `sw_vers`, Safari's version, `softwareupdate --list`, `brew outdated --json=v2` |
| Vulnerabilities | Exactly as a server: OSV, then KEV, EPSS and CVSS | Every CVE fixed by the macOS and Safari updates Apple offers it: all security releases newer than what's installed, up to the offered update (Apple security notes), then KEV, EPSS and CVSS like a server. A major upgrade is skipped while the current release is supported. |
| End of life | Debian or Ubuntu dates | macOS dates (endoflife.date) |
| Other | | Outdated Homebrew packages: one Normal finding (no CVE data), in the weekly summary |
| Notification | One per CVE, button "This computer" | One per Apple update ("macOS 15.8.2 · fixes 197 vulnerabilities · 2 actively exploited"), button "This Mac" |
| Button opens | A local terminal with the fix typed in | System Settings › Software Update |

- It's checked with every match (every 6 h, and right after wake-up) and after its button is clicked; its findings use the name `this-mac` (Linux: `this-computer`), which no server may use.
- If any part can't be read (e.g. `softwareupdate` fails, or Apple's notes are unreachable with no saved copy), the check reports an error and keeps the last findings: a missing answer never resolves anything. The same goes for a page that arrives but can't be read (an error page, a changed layout), even when an older saved copy exists.

---

## 5. Security

### 5.1 Threat model

| Threat | Protection |
|---|---|
| Laptop stolen while off | Only `key.enc` (and `key.auto`) are on disk. Argon2id + passphrase; the auto-unlock key sits in the login Keychain, encrypted with your Mac login password (and FileVault). |
| Malware running as you, auto-unlock on | A separate program can't read the Keychain item silently (macOS asks), and switching the default keychain doesn't redirect it (calls are pinned to the login keychain). It can use the unlocked daemon, as it could anyway while unlocked. Code injected *into* `mis` could read the item: the hardened runtime (blocks `DYLD_INSERT_LIBRARIES`) is a follow-up. Same impact either way: package lists only. Turn auto-unlock off if you'd rather type the passphrase. |
| Laptop compromised while unlocked | The key only opens the `mis` user, which can only print package lists. Admin credentials are never held by `mis`. |
| Key file copied | Same as above. Offline guessing is slowed by Argon2id and strict passphrase rules. |
| Man-in-the-middle on SSH | Pinned host keys. A mismatch blocks the connection and raises an urgent notification. |
| Compromised/malicious server | Collector output is treated as hostile: size limits, strict parsing, name validation, fuzz-tested parser. Nothing from it is executed. |
| Poisoned or wrong feed data | Feed text never reaches commands. Worst case is a wrong alert, not code execution. Data comes over HTTPS. |
| Another local user | 0700/0600 permissions, socket peer-UID check |
| Fake button events | The daemon acts only on (server, CVE) pairs in its own state, with commands it built itself. Clicks come only from the macOS helper (same-user socket), the D-Bus notification server (other senders are ignored) or a zenity window the daemon started; a dialog button carries only a server name. |
| Secrets in logs | Passphrases and keys are never logged; a test scans a fully logged unlock/check/lock/wrong-passphrase run for them. |
| Misconfigured sshd locks you out | `sshd -t` and probes of the effective settings before the reload; any failure up to and including the reload is rolled back automatically; the login test as `mis` runs afterwards and lists what failed |

### 5.2 Passphrase standard

**Rule: at least 8 characters.** That's the only check (decided in [ADR 0001](adr/0001-passphrase-minimum-8.md)). It is deliberately looser than **NIST SP 800-63B-4** (August 2025), §3.1.1.2 *Password Verifiers*:

| NIST requirement | Our implementation |
|---|---|
| Single-factor passwords: **minimum 15 characters** (SHALL) | **Not followed:** minimum 8 characters, counted as Unicode code points after NFC |
| Permit a maximum of at least 64 (SHOULD) | Up to 1024 characters |
| Accept printable ASCII, space and Unicode (SHOULD); NFC normalization | All accepted. NFC-normalized before key derivation. |
| **No composition rules** (SHALL NOT) | No "must contain a symbol/number" rules |
| **Blocklist** of common, expected and breached passwords, dictionary words and context words. Reject with a reason. (SHALL) | **Not followed:** no blocklist and no strength estimate |
| **No periodic change**; change only on compromise (SHALL NOT / SHALL) | No expiry. `mis passphrase change` when needed. |
| **No hints** (SHALL NOT) | None stored |
| Full password verified, no truncation (SHALL) | Whole passphrase goes into Argon2id |
| Offer guidance (SHALL); allow paste and password managers (SHALL/SHOULD) | A plain-language reason for every rejection. Paste allowed. Offers a generated 6-word passphrase (EFF wordlist, ≈ 77 bits). |

**What still protects a stolen `key.enc`:** it can be guessed **offline** without any limit, so the defence is:
- **Slow derivation:** Argon2id at RFC 9106 parameters (§4.2), so each guess costs about 1 s and up to 2 GiB of memory.
- **Limited blast radius:** the key only opens the read-only `mis` user (§4.1). It can list packages, nothing else.
- **Residual risk:** a common or short passphrase (e.g. `password`) falls to a dictionary attack quickly. The generated passphrase avoids this.

---

## 6. Tech stack and repository layout

| Need | Choice |
|---|---|
| CLI | `spf13/cobra` |
| SSH | `golang.org/x/crypto/ssh` (client, host-key callback for pinning) |
| Crypto | `golang.org/x/crypto/argon2`, `chacha20poly1305`; `awnumar/memguard` for secret memory |
| Prompt | `golang.org/x/term` (no echo); `golang.org/x/text/unicode/norm` (NFC) |
| Linux notifications | `godbus/dbus/v5` |
| macOS notifications | Swift helper app (SwiftPM), UserNotifications framework |
| Config | YAML (`go.yaml.in/yaml/v3`, the maintained successor of `gopkg.in/yaml.v3`); state as JSON with atomic writes |
| Install | `install.sh` downloads the release archive for the OS and processor, checks its SHA-256 checksum and installs without sudo. A version tag runs `.github/workflows/release.yml`: it first runs `make check` and `govulncheck` on the newest Go 1.26 patch release, then builds macOS (arm64, amd64, built for macOS 13 or later; helper universal, ad-hoc signed) and Linux (amd64, arm64) archives. From source: `make install`. |

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
| OSV API unavailable | Retry with backoff. `mis status` shows feed age. Alert if the last successful check is more than 24 h old. |
| EPSS or CVE record lookup fails | The finding keeps the score it had (a failed lookup is never stored as 0, which would lower its priority and bring back an accepted finding when the source recovers). `mis check` and the log show a warning. |
| Laptop asleep → missed checks | Catch up on wake. |
| A server's package list stops refreshing (service locked, server unreachable) | The checks keep succeeding on the old list, so each server's list has its own age: a "getting old" warning names every server whose list is more than 24 h old (twice the refresh interval, if that is longer). `mis doctor` reports the same. |

---

## 8. Later (not in v1)

- AlmaLinux/Rocky servers (dnf/rpm)
- Docker images and hand-installed software (Trivy/OSV for containers, GitHub releases watchlist)
- Local matching mode (download distro data, nothing sent to OSV)
- Other alert channels (Telegram, email, ntfy)
- Password login for the `mis` user (fallback where keys are impossible)
- Auto-unlock on Linux desktops (Secret Service: GNOME Keyring, KWallet)
- This computer on other systems (Windows, other Linux distributions); App Store and other apps on a Mac
- Homebrew tap; Apple Developer ID signing and notarization of the release builds
- Optional online breach check for new passphrases (Have I Been Pwned range API)
- Quiet hours, multiple users or teams
