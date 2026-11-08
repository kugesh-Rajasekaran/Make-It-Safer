# Make-It-Safer

`mis` tells you which of your Ubuntu and Debian servers are affected by new vulnerabilities. It sends a desktop notification, and one click opens an SSH session with the fix command already typed in, waiting for Enter.

- Read-only on your servers: the checker can only list installed packages.
- Your passphrase is never stored; the login key is saved only encrypted.
- Local: no accounts, no cloud sync, no telemetry.

**Status:** all milestones built (M0–M7). The last checks happen on your own Mac, Linux desktop and servers; see the [implementation plan](docs/implementation-plan.md).

## Get started

```bash
make install   # mis into ~/.local/bin (and the notification helper on macOS)
mis init       # guided setup: passphrase, terminal, alerts, servers, background service
mis doctor     # checks everything
```

Everything else is in the [user guide](docs/user-guide.md).

## Docs

- [User guide](docs/user-guide.md): install, daily use, fixing, troubleshooting
- [Design](docs/design.md): how it works, security, decisions
- [Implementation plan](docs/implementation-plan.md): milestones and tasks
- [Glossary](CONTEXT.md)

## Build from source

Needs Go (the version in `go.mod`) and `golangci-lint` v2.

```bash
make build        # builds bin/mis
make check        # format check, lint, unit tests
make test-integration   # Docker: throwaway Ubuntu/Debian SSH servers
                        # (MIS_TEST_IMAGES=ubuntu:24.04 runs a subset)
git config core.hooksPath .githooks   # run `make check` before each commit
```

## Security

Found a vulnerability in Make-It-Safer itself? Please report it privately; see [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE). Generated passphrases use the [EFF long word list](https://www.eff.org/deeplinks/2016/07/new-wordlists-random-passphrases) (CC BY 3.0 US) through [go-diceware](https://github.com/sethvargo/go-diceware).
