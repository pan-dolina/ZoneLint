# AGENTS.md

Operational guide for AI coding agents working in this repository.

## Project

ZoneLint is a read-only DNS audit and lint tool written in Go. It inspects
delegations, authoritative servers, SOA parameters, AXFR exposure, DNSSEC
chain of trust, TTL policy, CAA records, CNAME structure, address
classification, and wildcard behavior. It is **not** an exploitation
framework: it issues minimal, bounded queries and never mounts attacks.

## Build and test

```sh
go build ./...
go test -race ./...
```

The toolchain is the system Go (see `go.mod` for the minimum version). No local
vendor or environment scripts are required.

## Layout

```
cmd/zonelint/        CLI entry point and flag handling
internal/audit/      Orchestration; runs every check and aggregates findings
  functional/        End-to-end tests over the audit pipeline (in-memory zones)
internal/report/     Human, JSON, and SARIF rendering
internal/resolver/   Resolver abstraction: network + in-memory fake
internal/budget/     Query budget: max queries, QPS, concurrency, timeout
internal/dns/        DNS wire-format helpers
internal/findings/   Finding model, severity ranking, stable IDs
internal/dnssec/     DNSKEY/RRSIG/DS parsing and cryptographic validation
internal/{delegation,soa,authserver,axfr,nsec,ttl,caa,cname,addrs,wildcard,active}/
                       Individual check packages (pure functions)
testdata/            Controlled authoritative zones for tests
docs/                Documentation
```

## Conventions

- **Pure checks.** Each check package exposes pure functions that take
  collected records and return `[]*findings.Finding`. No network I/O inside a
  check.
- **Stable finding IDs.** IDs follow the pattern `DNS-<CATEGORY>-<NNN>`
  (for example `DNS-DELEGATION-002`). Never reuse or silently renumber an ID.
- **Severities.** One of `critical`, `high`, `medium`, `low`, `info`, `pass`.
  Ranking lives in `internal/findings`.
- **Evidence and references.** Every finding carries evidence strings and
  references (RFC numbers or best-practice citations).
- **Budgets first.** Every network call goes through the resolver, which
  enforces the query budget. Do not bypass it.
- **Deterministic output.** Findings are sorted by severity then category then
  ID before output.

## Testing

- Unit tests live next to each package (`*_test.go`).
- Functional tests in `internal/audit/functional/` exercise the full pipeline
  against `testdata/` zones via the fake resolver. They never touch the
  network.
- Fuzz targets exist in `internal/dnssec/` (for example `FuzzParseDNSKEY`).
- Benchmarks exist in `internal/audit/` (for example `BenchmarkAudit`).

## Adding a check

1. Create `internal/<name>/<name>.go` with a pure `Check(...)` function.
2. Add stable finding IDs in `internal/findings/ids.go`.
3. Add unit tests. If the check belongs in the audit pipeline, add a
   functional test in `internal/audit/functional/`.
4. Document the finding in `docs/checks.md`.

## Guardrails

- No network write access, brute force, amplification, or spoofing.
- No committing of toolchain, cache, or environment files (see `.gitignore`).
- Keep the commit history logical; each stage is a real commit.
