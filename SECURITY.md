# Security policy

Make-It-Safer holds an SSH key to your servers, so a flaw in it matters.

## Reporting a vulnerability

Please **don't open a public issue**. Report it privately instead:

1. Go to the repository's **Security** tab.
2. Click **Report a vulnerability**.
3. Describe what you found, how to reproduce it, and what an attacker could do with it.

I aim to reply within a week. Once it's fixed, you'll be credited in the fix unless you'd rather not be.

## What counts

In scope:

- Reading or using the SSH key or passphrase without the user's passphrase or Keychain approval
- Getting more than read-only access to a server through the `mis` user or its collector
- Another local user talking to the daemon or the notification helper
- Making `mis` run commands or open URLs it shouldn't (for example from a crafted feed or a notification)
- Making `mis` miss or hide a vulnerability it should report

Out of scope:

- Attacks that need root on your computer or server already
- Vulnerabilities in the data sources themselves (report those to OSV, CISA, Apple or the distribution)

## Supported versions

Only the latest commit on `main` gets fixes.

## How it's built

Section 5 of [docs/design.md](docs/design.md) explains the key storage, the read-only server user and the other safeguards.
