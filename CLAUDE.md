# CLAUDE.md

Instructions for Claude working in this repository.

## Project overview

ZoneLint is a read-only DNS audit and lint tool written in Go. It audits DNS
zones and their infrastructure: delegations, authoritative servers, SOA
parameters, AXFR exposure, DNSSEC chain of trust, TTL policy, CAA records,
CNAME structure, address classification, and wildcard behavior.

It is an **audit and lint tool, not an exploitation framework**. It issues
minimal, bounded queries and never performs denial-of-service, amplification,
spoofing, brute force, or DNS poisoning.

## Build and test

```sh
go build ./...
go test -race ./...
```

Use the system Go toolchain. The minimum version is declared in `go.mod`.

## Architecture

The codebase is split into small, focused packages:

- `cmd/zonelint` — CLI, flag parsing, output rendering.
- `internal/audit` — orchestration. `Run` resolves the apex, gathers records,
  invokes every check, sorts findings, and returns a `Result`.
- `internal/report` — human, JSON (`schema_version: "1"`), and SARIF output.
- `internal/resolver` — `Resolver` interface with a network implementation and
  an in-memory fake for tests.
- `internal/budget` — query budget enforcement (max queries, QPS, concurrency,
  per-server timeout).
- `internal/dns` — DNS wire-format helpers (canonical RDATA, name encoding).
- `internal/findings` — `Finding` model, severity ranking, stable IDs.
- `internal/dnssec` — DNSKEY/RRSIG/DS parsing and cryptographic validation.
- `internal/{delegation,soa,authserver,axfr,nsec,ttl,caa,cname,addrs,wildcard,active}` —
  individual check packages.
- `testdata` — controlled authoritative zones for tests.

## Conventions

- **Pure checks.** Each check package exposes pure functions that take
  collected records and return `[]*findings.Finding`. No network I/O inside a
  check.
- **Stable finding IDs.** IDs follow `DNS-<CATEGORY>-<NNN>` (for example
  `DNS-DELEGATION-002`). Never reuse or silently renumber an ID.
- **Severities.** One of `critical`, `high`, `medium`, `low`, `info`, `pass`.
- **Every finding** carries evidence strings and references.
- **Budgets first.** Every network call goes through the resolver, which
  enforces the query budget.
- **Deterministic output.** Findings are sorted by severity, then category,
  then ID.

## Testing

- Unit tests live next to each package.
- Functional tests in `internal/audit/functional/` exercise the full pipeline
  against `testdata/` zones via the fake resolver. They never touch the
  network.
- Fuzz targets live in `internal/dnssec/`. Benchmarks live in
  `internal/audit/`.

## Adding a check

1. Create `internal/<name>/<name>.go` with a pure `Check(...)` function.
2. Add stable finding IDs in `internal/findings/ids.go`.
3. Add unit tests. If the check belongs in the audit pipeline, add a
   functional test in `internal/audit/functional/`.
4. Document the finding in `docs/checks.md`.

## Guardrails

- No network write access, brute force, amplification, or spoofing.
- Do not commit toolchain, cache, or environment files (see `.gitignore`).
- Keep the commit history logical; each stage is a real commit.
