# Contributing to ZoneLint

Thank you for considering a contribution. ZoneLint is a read-only DNS audit
tool; we welcome bug reports, documentation improvements, and well-scoped
features.

## Ground rules

- **Read-only by design.** No change may introduce network write access,
  brute-force enumeration, amplification, or any behavior that turns the tool
  into an attack primitive.
- **Pure checks.** New checks are pure functions over collected records so
  they can be unit-tested without the network.
- **Stable findings.** Every finding carries a stable ID, severity, category,
  evidence, and references. Do not reuse or silently renumber existing IDs.
- **Bounded queries.** Any new network path must respect the query budget
  (`internal/budget`).

## Before you start

1. Open an issue or comment on an existing one to describe the intent.
2. For non-trivial changes, propose an approach in the issue first.

## Development setup

```sh
go build ./...
go test -race ./...
```

See [`docs/development.md`](docs/development.md) for testing, fuzzing, and
benchmarking instructions.

## Style

- `gofmt` and `go vet` must pass (enforced in CI).
- Prefer small, focused commits with descriptive messages.
- Keep the commit history logical; each stage is a real commit.

## Pull requests

- Reference the issue you are addressing.
- Include tests for new behavior (unit tests; functional tests where the audit
  pipeline is exercised).
- Do not commit local toolchain, cache, or environment files.

## Review criteria

- Correctness against the check catalog in [`docs/checks.md`](docs/checks.md).
- No new security or safety regressions.
- Deterministic, testable output.
