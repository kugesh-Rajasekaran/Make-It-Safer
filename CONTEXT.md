# Make-It-Safer Context

The shared vocabulary for Make-It-Safer. Use these terms in code, docs, notifications and issues.

## Places and People

**Server**:
A VPS the user registered with `mis` (OVH or any other provider).
_Avoid_: host, node, box, machine

**Your computer**:
The user's macOS or Linux desktop where `mis` and the Daemon run.
_Avoid_: client, local host, laptop (when speaking generally)

**`mis` user**:
The read-only Linux account on each Server. It can only run the Collector.
_Avoid_: service account, agent user, scanner user

**Admin login**:
The user's own SSH login on a Server (e.g. `ubuntu@51.x.x.x`), used for setup and fixes. `mis` never holds it.
_Avoid_: root login, sudo user

## Data

**Collector**:
The root-owned, read-only script on each Server that the `mis` user is forced to run. It prints the Inventory.
_Avoid_: agent, probe, scanner

**Inventory**:
What the Collector prints, saved on Your computer: OS release, running kernel, reboot flag and installed packages (binary and source names with versions).
_Avoid_: snapshot, SBOM, package dump

**Vulnerability**:
A security flaw as published by a Source, identified by a CVE ID or a distro ID (e.g. `UBUNTU-CVE-…`, `DEBIAN-CVE-…`).
_Avoid_: bug, issue

**Finding**:
One Vulnerability that applies to one Server through one source package. It has a lifecycle: new → notified → snoozed/accepted → resolved.
_Avoid_: alert, hit, issue, match

**Early warning**:
An unconfirmed Finding from the CVE List, raised before the distro has assessed it. It has no Fix command. It ends as **confirmed** (a Finding from distro data takes over), **not affected**, or **expired** (no distro data after 30 days).
_Avoid_: pre-alert, heads-up (in code)

**Confirmed**:
A Finding based on distro data (via OSV) for the exact installed version.

**Priority**:
Urgent, High, Normal or Silent. Decides whether and how often the user is reminded.
_Avoid_: severity (severity is the CVSS score; Priority is our decision)

**Source**:
An external data provider: OSV.dev, CVE List, CISA KEV, EPSS, endoflife.date.
_Avoid_: feed provider, database

**Ecosystem**:
OSV's identifier for a distro release, e.g. `Ubuntu:24.04:LTS`, `Debian:12`.

## Secrets and State

**Passphrase**:
The secret only the user knows. It unlocks the Key file and is never stored.
_Avoid_: password, master password

**Key file**:
`key.enc`, the SSH private key for the `mis` user, encrypted with the Passphrase.
_Avoid_: keystore, vault file

**Locked / Unlocked**:
The Daemon's two states. While Locked, it matches against saved Inventories only. While Unlocked, it holds the key in memory and can refresh Inventories over SSH.

**Auto-unlock**:
The Daemon unlocks itself when the user logs in, with an Unlock key kept in the macOS login Keychain. Optional; `mis lock` still locks until `mis unlock` or the next login.
_Avoid_: auto-login, remember me, keychain mode

**Unlock key**:
The random 256-bit key in the Keychain that opens `key.auto` (the same private key, encrypted for Auto-unlock). Not the Passphrase.

**Daemon**:
The `mis` background service that runs at login on Your computer.
_Avoid_: agent (confused with ssh-agent and AI agents), worker

## Actions

**Notification**:
A desktop notification for one Vulnerability, with one Server button per affected Server plus "All servers…".

**Fix command**:
The update command `mis` builds for a Finding (e.g. `sudo apt-get install --only-upgrade …`). It is typed into the user's SSH session, never run automatically.
_Avoid_: patch script, remediation

**Picker**:
The terminal menu opened by "All servers…". It stays open while the user opens Servers one by one.
