# Make-It-Safer

`mis` tells you which of your Ubuntu and Debian servers are affected by new vulnerabilities. It sends a desktop notification, and one click opens an SSH session with the fix command already typed in, waiting for Enter.

- Read-only on your servers: the checker can only list installed packages.
- Your passphrase is never stored; the login key is saved only encrypted.
- Local: no accounts, no cloud sync, no telemetry.

**Status:** under development. See the [implementation plan](docs/implementation-plan.md) for progress.

## Docs

- [Design](docs/design.md): how it works, security, decisions
- [Implementation plan](docs/implementation-plan.md): milestones and tasks
- [Glossary](CONTEXT.md)

## Build from source

Needs Go (the version in `go.mod`) and `golangci-lint` v2.

```bash
make build        # builds bin/mis
make check        # format check, lint, unit tests
make test-integration   # Docker: throwaway Ubuntu/Debian SSH servers
git config core.hooksPath .githooks   # run `make check` before each commit
```
