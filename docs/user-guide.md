# Make-It-Safer user guide

Make-It-Safer (`mis`) watches your Ubuntu and Debian servers for vulnerabilities. It tells you which servers are affected, and one click opens an SSH session with the fix already typed in.

- [Install](#install)
- [Set up](#set-up)
- [Daily use](#daily-use)
- [Fixing](#fixing)
- [After a restart: unlock](#after-a-restart-unlock)
- [This computer](#this-computer)
- [Servers](#servers)
- [Settings](#settings)
- [Removing Make-It-Safer](#removing-make-it-safer)
- [Troubleshooting](#troubleshooting)

---

## Install

**You need:**

| | |
|---|---|
| Your computer | macOS 13 or later (Apple Silicon or Intel), or a Linux desktop (GNOME, KDE, …; x86_64 or ARM) |
| Servers | Ubuntu 22.04/24.04 LTS or Debian 12/13, with your usual `ssh` login that can use `sudo` (or is `root`) |

**Install:**

```bash
curl -fsSL https://raw.githubusercontent.com/kugesh-Rajasekaran/Make-It-Safer/main/install.sh | sh
```

- The [install script](../install.sh) downloads the latest release for your system from GitHub Releases and checks its SHA-256 checksum. It needs no sudo.
- `mis` goes to `~/.local/bin`. If that isn't on your `PATH`, add it to `~/.zshrc` or `~/.bashrc`: `export PATH="$HOME/.local/bin:$PATH"`.
- On macOS it also installs the notification helper (`Make-It-Safer Notifier.app`) into `~/Applications`.
- A specific version: `curl -fsSL …/install.sh | MIS_VERSION=v0.1.0 sh`.

**Update:** run the same command again.
- A running background service restarts with the new version. Unlock it again.
- With auto-unlock on, macOS asks once to let the new version use your Keychain: click **Always Allow** (or **Allow**).

**From source instead:** you need Go 1.26 or later, and on macOS the Xcode command line tools (`xcode-select --install`) for the notification helper.

```bash
git clone https://github.com/kugesh-Rajasekaran/Make-It-Safer.git
cd Make-It-Safer
make install      # update later: git pull && make install
```

---

## Set up

Run `mis init` and follow the steps. Every step after the passphrase can be skipped and done later; each step says how.

| Step | What happens |
|---|---|
| 1. Passphrase | Choose one (at least 8 characters), or press Enter for a generated one. **It's never saved anywhere: keep it in your password manager.** It encrypts the key Make-It-Safer uses to read your servers. |
| 2. Terminal | The app that opens when you click a server button. `default` is Terminal on macOS, your desktop's terminal on Linux. |
| 3. Alerts | The CVSS score from which fixable vulnerabilities alert you (default 7), and from which early warnings come (default 9, or `off`). |
| 4. Servers | First: **"Check this Mac too?"** (Enter = yes; on Linux "this computer"), see [This computer](#this-computer). Then adds your servers (see [Servers](#servers)). |
| 5. Background service | Starts at every login and checks on a schedule. It's unlocked with the passphrase from step 1. On macOS you're then asked **"Unlock automatically after a restart?"** (Enter = yes; your passphrase is never stored): see [auto-unlock](#after-a-restart-unlock). |
| 6. Notifications | On macOS it opens **System Settings › Notifications › Make-It-Safer Notifier** for you: turn on *Allow notifications*, choose **Alerts** (they stay on screen), press Enter. It checks, and opens it again if something's still off. Then it shows a test notification. Later, the same with `mis notify setup`. |
| 7. First check | Reads each server's package list and shows what's open. |

When it's done, `mis doctor` should be all green (✓).

---

## Daily use

You mostly do nothing: the background service checks by itself and notifies you.

| Notification | Means | Click |
|---|---|---|
| 🔴 / 🟠 **CVE-… · openssh** · "2 servers affected · fix available" | A confirmed vulnerability with a fix. 🔴 is urgent (actively exploited, or CVSS ≥ 9), reminded every 4 h; 🟠 daily. | A server button opens its fix. "All servers…" lists them. |
| 🟡 **Heads-up · CVE-… · openssl** | An early warning: a critical new CVE that names software you have, before your distro has confirmed it. No fix yet. | Opens `mis show CVE-…` |
| ✅ **CVE-… · Fixed on all servers** | Every affected server is fixed. A heads-up can also end as ✅ "not affected". | — |
| **Weekly summary** | Normal-priority updates waiting. | Opens `mis findings` |
| **Make-It-Safer is locked** | After a restart. See [unlock](#after-a-restart-unlock). | Opens `mis unlock` |
| **Vulnerability data is getting old** | No successful check for a day (offline?). | Opens `mis findings` |

**Commands you'll use:**

| Command | Does |
|---|---|
| `mis status` | Is the service running and unlocked, and what's open per server |
| `mis findings` | Everything open, most urgent first (`--all` includes items without a fix and accepted ones) |
| `mis show CVE-…` | One vulnerability: what it is, which servers, the fix |
| `mis check` | Check now, instead of waiting |
| `mis ack CVE-… --until 2026-12-01` | Snooze it until a date (`--reason` to remember why) |
| `mis ack CVE-…` | Accept the risk: no more reminders. It comes back if it gets more urgent. |
| `mis doctor` | Checks everything and says how to fix what's wrong |

Every command accepts `--json` for scripts and AI agents.

---

## Fixing

1. **Click the server's button** in the notification (or run `mis fix <server> [CVE-…]`, or `mis pick CVE-…` to choose from a list).
2. Your terminal opens and logs in with **your own** `ssh` login. Your keys and password prompts apply as usual.
3. A banner shows what's being fixed, and the command is **typed in for you**:
   ```
   Make-It-Safer · ovh-web-1
     CVE-2024-6387  openssh  installed 1:9.6p1-3ubuntu13.5 → fixed in 1:9.6p1-3ubuntu13.8
   Enter = run · edit it first · Ctrl-C = skip to a normal shell

   ubuntu@ovh-web-1:~$ sudo apt-get update && sudo apt-get install --only-upgrade openssh-client openssh-server
   ```
4. **Enter** runs it. apt still asks `[Y/n]`, so you see what changes. **Ctrl-C** gives you a normal shell instead.
5. Over the next hour, Make-It-Safer re-checks that server every 10 minutes, and the notification turns into ✅.

**Special cases:**
- **Kernel:** the kernel packages are upgraded; restart afterwards with `sudo reboot`. A "needs a restart" notification types `sudo reboot` in for you.
- **Ubuntu Pro:** if the fix is only in Ubuntu Pro, the banner says so (`sudo pro attach <token>`).
- **No fix yet:** nothing to install. Make-It-Safer tells you when the fix arrives.

---

## After a restart: unlock

After you restart your computer, the service starts **locked**: it keeps matching the saved package lists, but can't log in to your servers.

- Click the "Make-It-Safer is locked" notification, or run `mis unlock`, and type your passphrase.
- `mis lock` wipes the key from memory again, whenever you like. It stays locked until `mis unlock` (or, with auto-unlock, your next login).
- `mis passphrase change` changes your passphrase.

**Auto-unlock (macOS):** the service unlocks itself when you log in, so you never type the passphrase after a restart.

| | |
|---|---|
| Turn on | `mis auto-unlock on` (asks for your passphrase once), or answer yes in `mis init` |
| Turn off | `mis auto-unlock off` |
| How | An unlock key is kept in your login Keychain ("Make-It-Safer auto-unlock"), which macOS opens when you log in. Your passphrase is still never stored. |
| After an update | macOS asks once to let the new `mis` use it: click **Always Allow**. |
| Trade-off | Anyone who can use your Mac while you're logged in gets the same as an unlocked service: the package lists of your servers, nothing more. |

---

## This computer

`mis` can check the computer it runs on too. Nothing is installed or changed for it, and it's checked even while the service is locked.

| | Mac | Linux desktop (Ubuntu, Debian) |
|---|---|---|
| Finds | Every vulnerability fixed by the macOS and Safari updates Apple offers you (from Apple's security notes), with the same urgency rules as servers | The same as on a server |
| Also | macOS end of support; outdated Homebrew packages (weekly summary) | Release end of support |
| Notification | One per update: "macOS 15.8.2 · fixes 197 vulnerabilities · 2 actively exploited" | One per vulnerability |
| Button | **This Mac** opens System Settings › Software Update | **This computer** opens a terminal with the fix typed in |

- It appears as `this-mac` (Linux: `this-computer`) in `mis status`, `mis findings` and `mis show`. `mis check this-mac` checks just it; `mis fix this-mac` does what the button does.
- Turn it on or off in `mis config` ("Also check this Mac") or with `mis config set this_computer yes|no`.

---

## Servers

| Command | Does |
|---|---|
| `mis server add` | Sets up a server (questions, or flags: `--host`, `--admin`, `--port`, `--fingerprint`) |
| `mis server list` | Your servers and when their package list was read |
| `mis server verify [name]` | Proves, from the outside, that the server only lets Make-It-Safer read |
| `mis server remove <name>` | Removes the read-only user from the server, then forgets it |
| `mis server setup-script` | Prints the setup script, to read it or run it yourself |

**What `mis server add` does:**
1. Shows the server's host key fingerprint. Compare it with your provider's console (or `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub` on the server). It's pinned from then on.
2. Runs a setup script **through your own `ssh` login** (Make-It-Safer never sees it). The script creates a `mis` user that can only run a read-only collector: no password, no sudo, no shell, no forwarding.
3. Logs in as `mis` and proves the restrictions: other commands, a terminal, forwarding and passwords are all refused.

---

## Settings

Run **`mis config`**. It shows every setting with its current value, 10 at a time:

```
Make-It-Safer settings      ↑/↓ move · Enter change · q quit

› Alerts         Alert for fixable vulnerabilities from CVSS     7.0
                 …or when the exploit chance (EPSS) is at least  10%
                 Always alert actively exploited (CISA KEV)      yes
                 Alert when there's no fix yet                   only when urgent
  Early warnings Heads-ups before your distro confirms           on, from CVSS 9.0
  Reminders      Remind urgent findings                          every 4h
                 …
                 ↓ 4 more
```

- **↑/↓** move (the list scrolls), **Enter** changes the highlighted setting, **q** quits.
- Yes/no settings flip on Enter. Choices open a small list. Others ask for the new value; Enter alone keeps the current one, and a wrong value is explained.
- Each change is saved right away, and you're back on the same list.
- The background service picks changes up within 15 minutes. New alert scores apply at its next check; `mis check` applies them now.

**For scripts and agents:** `mis config get` lists every setting by name, `mis config get <name>` prints one, `mis config set <name> <value>` changes one (all accept `--json`):

| Name | Example value | Means |
|---|---|---|
| `this_computer` | `yes` | Also check the computer `mis` runs on |
| `rules.alert_when.min_severity` | `7.0` | Alert for fixable vulnerabilities from this CVSS score |
| `rules.alert_when.min_epss` | `10%` | …or from this exploit chance |
| `rules.alert_when.actively_exploited` | `yes` | Always alert for CISA's actively-exploited list |
| `rules.unfixed` | `urgent_only` or `all` | Alert for vulnerabilities without a fix |
| `rules.early_warning` | `9.0` or `off` | Heads-ups before your distro confirms |
| `rules.remind.urgent` / `.high` / `.normal` | `4h` / `1d` / `7d` | How often open findings are repeated |
| `schedule.new_cves` | `15m` (at least 5m) | How often to look for brand-new CVEs (early warnings) |
| `schedule.data_changes` | `30m` (at least 10m) | How often to ask Debian, Ubuntu and CISA whether their data changed; if it did, everything is checked again |
| `schedule.full_check` | `6h` (at least 30m) | How often to check everything again anyway, including this computer |
| `schedule.servers` | `12h` (at least 1h) | How often to log in to your servers and read their installed packages (needs unlocked) |
| `rules.ignore.packages` / `.cves` | `linux-firmware,tzdata` | Never alert for these |
| `terminal.app` | `default`, `iterm2`, `ghostty`, …, `custom` | The app a server button opens |
| `terminal.command` | `foot {script}` | Only for `custom` (set it first) |
| `notifications.sound` | `yes` | Play a sound with alerts |
| `notifications.max_buttons` | `3` | Buttons per notification, servers plus "All servers…" |

The settings live in `config.yaml` in Make-It-Safer's folder (`~/Library/Application Support/MakeItSafer` on macOS, `~/.config/mis` on Linux). You can still edit it by hand; `mis doctor` reports any mistake.

---

## Removing Make-It-Safer

1. Remove each server: `mis server remove <name>`. This deletes the `mis` user on the server, through your own login.
2. `mis auto-unlock off`, if it's on. This removes the unlock key from your Keychain.
3. Remove the service, `mis` and the macOS helper:
   - Installed with the script: `mis service uninstall`, then `rm ~/.local/bin/mis`, and on macOS `rm -rf ~/Applications/"Make-It-Safer Notifier.app"`.
   - Built from source: `make uninstall` (in the repository).
4. Delete Make-It-Safer's folder (see [Settings](#settings)) to remove your settings and encrypted key.

---

## Troubleshooting

Start with **`mis doctor`**: it checks everything and says what to do.

| Problem | What to do |
|---|---|
| No notifications (macOS) | `mis notify setup`: it opens the right page in System Settings, checks the result and shows a test. (The helper app lives in `~/Applications`; `make install` puts it there.) |
| No notifications (Linux) | Your desktop needs a notification service (GNOME and KDE have one). Test with `mis notify test`. |
| A button does nothing | Check the terminal in `mis doctor`. On Linux, the service may not see your desktop: `systemctl --user import-environment DISPLAY WAYLAND_DISPLAY DBUS_SESSION_BUS_ADDRESS`, then `mis service install`. |
| "locked" | `mis unlock` |
| "locked" although auto-unlock is on | Did you run `mis lock`? Otherwise macOS may be waiting for you to allow Keychain access, or it was denied: `mis auto-unlock on` sets it up again. |
| "host key mismatch" | The server's identity changed. If you reinstalled it, that's expected: `mis server remove <name> --forget`, then add it again and compare the fingerprint. If you didn't, **don't connect**: someone may be intercepting the connection. |
| "Vulnerability data is getting old" | Check your internet connection; `mis doctor` shows which source doesn't answer. |
| Too many heads-ups | Raise `rules.early_warning.min_severity`, or set `enabled: false`. |
| Forgot the passphrase | It can't be recovered. Remove each server (`mis server remove`), delete `key.enc` from Make-It-Safer's folder, run `mis init`, and add the servers again. (With auto-unlock on, the service still unlocks until then, but the passphrase is needed to change settings that ask for it.) |
| Anything else | `mis service logs` shows the background service's log. |
