# Development

This document describes how to develop and test ZoneLint.

## Requirements

- Go 1.23+
- The Go toolchain is vendored under `.toolchain/`. Source `.env.sh` to set up
  the environment:

```sh
source .env.sh
```

## Build

```sh
go build ./...
go build -o dist/zonelint ./cmd/zonelint
```

## Test

```sh
go test ./...
go test -race ./...
```

### Functional tests

`internal/audit/functional/` contains 20 end-to-end tests that run the full
audit pipeline against controlled in-memory zones in `testdata/`. These use a
fake resolver so they never touch the network.

### Fuzzing

```sh
go test -run xxx -fuzz FuzzParseDNSKEY ./internal/dnssec/ -fuzztime 30s
```

### Benchmarks

```sh
go test -run xxx -bench BenchmarkAudit ./internal/audit/
```

## Linting

The CI gate runs:

- `gofmt` — formatting.
- `go vet` — static analysis.
- `staticcheck` — advanced static analysis (`staticcheck.conf`).
- `gosec` — security scanning (`gosec.json`).
- `govulncheck` — dependency vulnerability scanning (`govulncheck.conf`).
- `go mod verify` — module integrity.
- `OSV-Scanner` — supply-chain scanning.

## Architecture

- `internal/dns` — DNS wire-format helpers.
- `internal/dnssec` — DNSSEC parsing and validation.
- `internal/{delegation,soa,authserver,axfr,nsec,ttl,caa,cname,addrs,wildcard,active}` — check packages.
- `internal/resolver` — network and fake resolver abstraction.
- `internal/budget` — query budget enforcement.
- `internal/audit` — orchestration.
- `internal/report` — human/JSON/SARIF rendering.
- `internal/findings` — finding model and stable IDs.
- `cmd/zonelint` — CLI entry point.

## Testing without network

All functional tests use `resolver.NewFake()` and `testdata` zones. The fake
resolver emulates authoritative behavior, wildcard matching, and zone transfer
control. Never commit real network-dependent tests.
