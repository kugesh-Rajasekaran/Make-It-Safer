# Make-It-Safer user guide

Make-It-Safer (`mis`) watches your Ubuntu and Debian servers for vulnerabilities. It tells you which servers are affected, and one click opens an SSH session with the fix already typed in.

- [Install](#install)
- [Set up](#set-up)
- [Daily use](#daily-use)
- [Fixing](#fixing)
- [After a restart: unlock](#after-a-restart-unlock)
- [Servers](#servers)
- [Settings](#settings)
- [Removing Make-It-Safer](#removing-make-it-safer)
- [Troubleshooting](#troubleshooting)

---

## Install

**You need:**

| | |
|---|---|
| Your computer | macOS 13 or later, or a Linux desktop (GNOME, KDE, …) |
| Tools | Go 1.26 or later. On macOS also the Xcode command line tools (`xcode-select --install`), for the notification helper. |
| Servers | Ubuntu 22.04/24.04 LTS or Debian 12/13, with your usual `ssh` login that can use `sudo` (or is `root`) |

**Install:**

```bash
git clone https://github.com/kugesh-Rajasekaran/Make-It-Safer.git
cd Make-It-Safer
make install
```

- `mis` goes to `~/.local/bin`. If that isn't on your `PATH`, add it to `~/.zshrc` or `~/.bashrc`: `export PATH="$HOME/.local/bin:$PATH"`.
- On macOS, `make install` also builds the notification helper (`Make-It-Safer Notifier.app`) into `~/Applications`.
- To update later: `git pull && make install`. A running background service restarts with the new version; unlock it again.

---

## Set up

Run `mis init` and follow the steps. Every step after the passphrase can be skipped and done later; each step says how.

| Step | What happens |
|---|---|
| 1. Passphrase | Choose one (at least 15 characters; several random words work best), or press Enter for a generated one. **It's never saved anywhere: keep it in your password manager.** It encrypts the key Make-It-Safer uses to read your servers. |
| 2. Terminal | The app that opens when you click a server button. `default` is Terminal on macOS, your desktop's terminal on Linux. |
| 3. Alerts | The CVSS score from which fixable vulnerabilities alert you (default 7), and from which early warnings come (default 9, or `off`). |
| 4. Servers | Adds your servers (see [Servers](#servers)). |
| 5. Background service | Starts at every login and checks on a schedule. It's unlocked with the passphrase from step 1. |
| 6. Notifications | Shows a test notification. On macOS, allow notifications for **Make-It-Safer Notifier** and choose the **Alerts** style, so they stay on screen. |
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
- `mis lock` wipes the key from memory again, whenever you like.
- `mis passphrase change` changes your passphrase.

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

Your settings are in `config.yaml`, in Make-It-Safer's folder:

| | Folder |
|---|---|
| macOS | `~/Library/Application Support/MakeItSafer` (logs: `~/Library/Logs/MakeItSafer`) |
| Linux | `~/.config/mis` |

The parts you may want to change:

```yaml
rules:
  alert_when:
    actively_exploited: true   # CISA KEV
    min_severity: 7.0          # CVSS
    min_epss: 0.10             # exploit probability
  early_warning:
    enabled: true
    min_severity: 9.0          # e.g. 8.0 for more heads-ups
  unfixed: urgent_only         # alert without a fix only if urgent
  ignore:
    packages: [linux-firmware]
    cves: []
terminal:
  app: default                 # or iterm2, ghostty, kitty, … or custom
  command: ""                  # custom only, e.g. "foot {script}"
notifications:
  sound: true
  max_buttons: 3               # server buttons + "All servers…"
```

Run `mis doctor` after editing: a mistake in the file is reported with what is wrong.

---

## Removing Make-It-Safer

1. Remove each server: `mis server remove <name>`. This deletes the `mis` user on the server, through your own login.
2. `make uninstall` (in the repository) removes the service, `mis` and the macOS helper.
3. Delete Make-It-Safer's folder (see [Settings](#settings)) to remove your settings and encrypted key.

---

## Troubleshooting

Start with **`mis doctor`**: it checks everything and says what to do.

| Problem | What to do |
|---|---|
| No notifications (macOS) | `make install` puts the helper in `~/Applications`. Then System Settings → Notifications → **Make-It-Safer Notifier**: allow, and choose **Alerts**. Test with `mis notify test`. |
| No notifications (Linux) | Your desktop needs a notification service (GNOME and KDE have one). Test with `mis notify test`. |
| A button does nothing | Check the terminal in `mis doctor`. On Linux, the service may not see your desktop: `systemctl --user import-environment DISPLAY WAYLAND_DISPLAY DBUS_SESSION_BUS_ADDRESS`, then `mis service install`. |
| "locked" | `mis unlock` |
| "host key mismatch" | The server's identity changed. If you reinstalled it, that's expected: `mis server remove <name> --forget`, then add it again and compare the fingerprint. If you didn't, **don't connect**: someone may be intercepting the connection. |
| "Vulnerability data is getting old" | Check your internet connection; `mis doctor` shows which source doesn't answer. |
| Too many heads-ups | Raise `rules.early_warning.min_severity`, or set `enabled: false`. |
| Forgot the passphrase | It can't be recovered. Remove each server (`mis server remove`), delete `key.enc` from Make-It-Safer's folder, run `mis init`, and add the servers again. |
| Anything else | `mis service logs` shows the background service's log. |
