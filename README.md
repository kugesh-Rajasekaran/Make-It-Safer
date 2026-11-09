# Make-It-Safer

**Know when a new vulnerability hits your servers, and fix it in one click.**

`mis` is a command-line tool with a background service for macOS and Linux desktops. It watches public vulnerability data and works out which of your Ubuntu and Debian servers are affected, plus the computer it runs on. Then it sends a desktop notification. Click it, and your terminal opens an SSH session with the fix already typed in.

**Status:** early release (v0.x), for your own computer and servers.

## Why Make-It-Safer

| | |
|---|---|
| **No accounts, no telemetry** | No cloud sync. Settings, findings and the encrypted key stay on your computer. To find vulnerabilities, `mis` sends package names and versions, never your server names or addresses ([exactly what](#where-the-data-comes-from)). |
| **Read-only on your servers** | Each server gets a `mis` user that can do exactly one thing: print the list of installed packages. No sudo, no shell, no write access. `mis` never stores or uses your admin login. |
| **Your own computer counts too** | The computer running `mis` is checked like any server. A Mac's macOS and Safari are checked against Apple's security notes, and outdated Homebrew packages go into the weekly summary (Homebrew has no vulnerability data). A Linux desktop gets the same package check as your servers. |
| **One click from alert to fix** | A notification button opens your terminal, connects with your own SSH login, and types the exact update command. You press Enter. [How it works](#from-notification-to-fix) |
| **Encrypted, passphrase never stored** | The only secret is an SSH key, saved encrypted with Argon2id and XChaCha20-Poly1305. [How the encryption works](#how-the-encryption-works) |
| **Only what matters interrupts you** | Debian and Ubuntu severity, CISA's list of actively exploited vulnerabilities and exploit likelihood (EPSS) decide the priority. Urgent and high findings notify you; the rest waits for a weekly summary. |

## Install

```bash
curl -fsSL https://raw.githubusercontent.com/kugesh-Rajasekaran/Make-It-Safer/main/install.sh | sh
mis init
```

The [install script](install.sh):
- downloads the release for your system from GitHub Releases;
- checks its SHA-256 checksum;
- puts `mis` in `~/.local/bin` and, on a Mac, the notification helper in `~/Applications`.

It needs no sudo and changes nothing else. To read it before running it:

```bash
curl -fsSLO https://raw.githubusercontent.com/kugesh-Rajasekaran/Make-It-Safer/main/install.sh
less install.sh
sh install.sh
```

| You need | |
|---|---|
| Your computer | macOS 13 or later (Apple Silicon or Intel), or a Linux desktop (x86_64 or ARM) |
| Your servers | Ubuntu 22.04/24.04 or Debian 12/13, and your usual `ssh` login that can use `sudo` |

- **Update:** run the same command again. A running background service restarts with the new version.
- **A specific version:** `curl -fsSL …/install.sh | MIS_VERSION=v0.1.0 sh`
- **Downloaded the archive in a browser instead?** The notification helper isn't notarized by Apple, so macOS blocks it. Run `xattr -dr com.apple.quarantine ~/Applications/"Make-It-Safer Notifier.app"` once. The install script avoids this.
- **Build from source:** see [below](#build-from-source).

## Set up

`mis init` walks you through it:
1. a passphrase (or a generated one);
2. your terminal app;
3. alert levels;
4. this computer and your servers;
5. the background service and auto-unlock;
6. notifications.

Every step after the passphrase can be skipped and done later. The [user guide](docs/user-guide.md#set-up) explains each one.

It's interactive on purpose: your passphrase is only ever typed into your terminal, and adding a server uses your own admin login.

## Let an AI agent install it

Paste this into Claude Code, Codex, Cursor or another coding agent:

```text
Install Make-It-Safer (https://github.com/kugesh-Rajasekaran/Make-It-Safer) on this computer.

1. Read its README.md and docs/user-guide.md first.
2. Download https://raw.githubusercontent.com/kugesh-Rajasekaran/Make-It-Safer/main/install.sh,
   tell me in two lines what it does, then run it with `sh`. If there is no release for this
   computer, build from source instead (README, "Build from source").
3. Make sure ~/.local/bin is on my PATH and that `mis version` works in a new shell.
4. Don't run `mis init` yourself, and never ask for my passphrase or server passwords. Setup is
   interactive on purpose: tell me to run `mis init` in my own terminal, and explain what each
   step will ask.
5. When I say I'm done, run `mis doctor` and `mis status`, and help me fix anything not marked ✓.
```

After setup, agents can read and adjust everything through `--json`:
- `mis status --json` and `mis findings --json`;
- `mis check`;
- `mis config get` and `mis config set`.

Unlocking and adding servers stay with you.

## From notification to fix

When a vulnerability with a fix affects your servers, you get one notification per CVE:

```text
🟠 CVE-2024-6387 · openssh
2 servers affected · fix available
[ db-1 ]   [ web-1 ]   [ All servers… ]
```

1. **Click a server button** (here `web-1`).
2. **Your terminal opens and connects with `ssh` as you.**
   - It uses your own login for that server: your keys, your `~/.ssh/config`, your password prompt if you use one.
   - Works with Terminal, iTerm2, Ghostty, kitty, Alacritty, WezTerm, GNOME Terminal, Konsole and others. Any other app (Warp, for example) works through a custom command.
3. **The fix is typed in on the server, not run:**

   ```text
   Make-It-Safer · web-1
     CVE-2024-6387  openssh  installed 1:9.6p1-3ubuntu13 → fixed in 1:9.6p1-3ubuntu13.3
   Enter = run · edit it first · Ctrl-C = skip to a normal shell

   ubuntu@web-1:~$ sudo apt-get update && sudo apt-get install --only-upgrade openssh-client openssh-server openssh-sftp-server
   ```

4. **Press Enter to run it.** You can also edit it first, or press Ctrl-C for a normal shell. **Nothing runs until you press Enter.**
5. **`mis` checks again** every 10 minutes for the next hour. Once the update is in, the finding closes and the notification becomes ✅. The button shows ✓ as soon as you use it, so you can see which servers you've already opened.

Why doesn't it just run the fix? Running it automatically would mean `mis` holds admin access to every server. Instead `mis` only ever has read-only access, and anything that changes a server happens in your own session, where you can see it.

The other buttons:
- **All servers…** (or a click on the notification itself) opens a list in your terminal. Pick a server and its SSH window opens; the list comes back so you can pick the next one, and `q` leaves it.
- **On a Mac update notification** ("macOS 15.8.2 · fixes 58 vulnerabilities"), the **This Mac** button (or a click on the notification) opens System Settings › Software Update.

## How the encryption works

**The only secret is one SSH key.** `mis` uses it to log in to your servers as the read-only `mis` user. Your admin login is never given to `mis`.

```text
 passphrase ──Argon2id──▶ 256-bit key ──XChaCha20-Poly1305──▶ key.enc        (on disk)
                                                                │  mis unlock
                                                                ▼
                                   SSH key in locked memory, only while in use
                                                                │  ssh as user "mis"
                                                                ▼
                                   server: prints its package list, nothing else
```

1. **Setup.** `mis init` creates a new Ed25519 key on your computer. The public half goes onto your servers. The private half is encrypted before it's written anywhere.
2. **On disk (`key.enc`).**
   - Your passphrase is stretched with **Argon2id** into a 256-bit key, using a random 16-byte salt.
   - Argon2id uses the RFC 9106 settings: 2 GiB of memory, 1 pass, 4 lanes. Computers with less than 8 GiB of usable memory use 64 MiB and 3 passes.
   - That key encrypts the SSH key with **XChaCha20-Poly1305** and a random 24-byte nonce.
   - The file header (format, Argon2id settings, salt) is authenticated too, so any change to the file is detected.
   - **The passphrase itself is never stored anywhere.**
3. **Unlocking.** The background service starts locked.
   - `mis unlock` reads your passphrase from the terminal only, never from flags or environment variables.
   - It decrypts the key into locked memory (`memguard`: kept out of swap), then wipes the passphrase.
   - Wrong guesses are slowed down.
4. **While running.**
   - The key is kept in locked memory: in the background service while it's unlocked, and inside a short-lived `mis` command that unlocks it itself (`mis init`, `mis server add` and `verify`, `mis check` when the service is locked or not running, `mis auto-unlock on`, `mis passphrase change`), until that command ends. Short-lived copies (the typed passphrase, the copy used to sign) are wiped after use, but they live in ordinary memory, and Go's crypto code can keep its own copy until that memory is reused.
   - Core dumps and debuggers are blocked.
   - `mis lock`, logging out, restarting or a crash wipe it.
5. **Auto-unlock (optional, macOS).**
   - A random 256-bit unlock key is stored in your **login Keychain**, which your Mac login password protects. `key.auto` holds the SSH key encrypted with it (XChaCha20-Poly1305).
   - When you log in, the service unlocks itself with no passphrase.
   - macOS asks for permission when a new version first reads it.
   - Turn it off with `mis auto-unlock off`.

**If someone gets hold of:**

| | What they can do |
|---|---|
| Your computer while it's off | Only `key.enc` is on disk, plus `key.auto` if auto-unlock is on (it's useless without your login Keychain, which your Mac login password protects). On a typical computer each passphrase guess costs about a second and 2 GiB of memory (a low-memory computer uses 64 MiB, see above). With the generated six-word passphrase (about 77 bits), guessing is hopeless. |
| `key.enc` and your passphrase, or your unlocked computer | Log in as `mis` and read package lists. Nothing else: your admin credentials were never there. |
| Your network (man in the middle) | Nothing: each server's host key is pinned. A changed key blocks the connection and sends you an urgent alert. |

The full threat model is in [design §5](docs/design.md#5-security).

## Where the data comes from

All of it is public and comes over HTTPS. None of it needs an API key or account.

| Source | Used for | What `mis` sends it |
|---|---|---|
| [OSV.dev](https://osv.dev) | Debian and Ubuntu advisories: which package versions are affected, and the fixed version | The **names and versions of installed packages** (source package name, version and OS release such as `Debian:12`) of your servers and, on Linux, of the desktop `mis` runs on. Then the IDs of the advisories that matched |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Vulnerabilities being exploited right now, which makes them urgent | Nothing: it downloads the whole list |
| [EPSS](https://www.first.org/epss/) | How likely a vulnerability is to be exploited soon | The CVE IDs of your findings |
| [CVE List](https://github.com/CVEProject/cvelistV5) | Scores, and early warnings for brand-new CVEs, before your distribution confirms them | The CVE IDs of your findings (the records are downloaded from `raw.githubusercontent.com`) |
| [endoflife.date](https://endoflife.date) | Operating system releases that no longer get security fixes | Nothing: it downloads one list per operating system you use |
| [Apple security releases](https://support.apple.com/en-us/100100) | macOS and Safari fixes, for a Mac running `mis` | Nothing: it downloads Apple's public pages |

- **Never sent:** server names, host names, IP addresses, SSH logins, or anything from a Mac's inventory (a Mac is matched against Apple's notes on your computer).
- **Every request** carries the user agent `make-it-safer/<version>`. As with any web request, each service also sees your computer's IP address.
- **On a Mac,** `softwareupdate` contacts Apple by itself to see which updates are offered.

`mis` refuses to connect anywhere else ([design §4.9](docs/design.md)).

## Daily use

```bash
mis status          # what's open on each server and this computer
mis findings        # everything open, most urgent first
mis show CVE-…      # what it is, which servers have it, the fix
mis fix web-1       # open the fix for everything fixable on web-1 (add a CVE for just that one)
mis check           # check now instead of waiting
mis config          # settings: alert levels, timers, terminal, notifications
mis doctor          # is everything working? says how to fix what isn't
```

## Docs

- [User guide](docs/user-guide.md): install, daily use, fixing, troubleshooting
- [Design](docs/design.md): how it works, security, decisions
- [Implementation plan](docs/implementation-plan.md): milestones and tasks
- [Glossary](CONTEXT.md)

## Build from source

Needs Go (the version in `go.mod`) and `golangci-lint` v2. On macOS you also need the Xcode command line tools (`xcode-select --install`) to build the notification helper.

```bash
git clone https://github.com/kugesh-Rajasekaran/Make-It-Safer.git
cd Make-It-Safer
make install      # mis into ~/.local/bin (and the notification helper on macOS)

make build        # builds bin/mis
make check        # format check, lint, unit tests
make test-integration   # Docker: throwaway Ubuntu/Debian SSH servers
                        # (MIS_TEST_IMAGES=ubuntu:24.04 runs a subset)
git config core.hooksPath .githooks   # run `make check` before each commit
```

**Releasing:** push a tag such as `v0.1.0`. The [release workflow](.github/workflows/release.yml) runs the checks (`make check`, `govulncheck`), builds the macOS and Linux archives and publishes them, with `checksums.txt`, as a GitHub Release.

## Security

Found a vulnerability in Make-It-Safer itself? Please report it privately; see [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE). Generated passphrases use the [EFF long word list](https://www.eff.org/deeplinks/2016/07/new-wordlists-random-passphrases) (CC BY 3.0 US) through [go-diceware](https://github.com/sethvargo/go-diceware).
