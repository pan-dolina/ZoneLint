# ZoneLint

> DNS zone, delegation, authoritative-server, and DNSSEC audit & lint tool.

ZoneLint is a read-only, network-safe command-line tool that audits DNS zones and
their infrastructure. It inspects delegations, authoritative servers, SOA
parameters, AXFR exposure, DNSSEC chain of trust, TTL policy, CAA records, CNAME
structure, address classification, and wildcard behavior.

It is an **audit and lint tool**, not an exploitation framework. It performs
minimal, bounded queries and never mounts attacks.

## Highlights

- **Delegation audit** — parent NS vs. child authoritative NS, glue, A/AAAA,
  lame delegation, stale/missing glue, unreachable or inconsistent NS.
- **Authoritative server probing** — UDP/TCP, AA flag, SOA/NS presence, EDNS,
  response consistency.
- **SOA validation** — MNAME, RNAME, serial, refresh/retry/expire/minimum.
- **Bounded AXFR** — per-server transfer attempts with strict record limits.
- **Real DNSSEC validation** — DS/DNSKEY/RRSIG, chain of trust, key tag,
  algorithm, digest, inception/expiration, NSEC/NSEC3.
- **TTL policy** — conservative / balanced / agile profiles.
- **CAA validation**, **CNAME loop/dangling detection**, **private-address
  classification**, **safe wildcard detection**.
- **Opt-in active scans** — AXFR, recursion check, limited protocol probes.
- **Query budgets** — bounded concurrency, max QPS, max queries, per-server
  timeout.
- **Rich output** — human report, versioned JSON, optional SARIF.

## Quick start

```sh
# Human report
zonelint example.com

# Machine-readable JSON
zonelint example.com --json

# Use Cloudflare resolver
zonelint example.com --resolver 1.1.1.1

# Conservative TTL profile, fail on high+ findings
zonelint example.com --profile conservative --fail-on high

# Active checks (AXFR, recursion)
zonelint example.com --active

# Version
zonelint version
```

## Safety model

ZoneLint is read-only and conservative by design:

- It issues only the queries required to answer each check.
- Every check is bounded by a **query budget** (max queries, max QPS, bounded
  concurrency, per-server timeout).
- It never performs denial-of-service, amplification, spoofing, brute force,
  subdomain takeover, or DNS poisoning.
- Wildcard detection uses a single cryptographically random name.
- Active scans are opt-in and limited.

See [`docs/checks.md`](docs/checks.md) for the full check catalog, and
[`SECURITY.md`](SECURITY.md) for the security model.

## Installation

### From source

Requires Go 1.23 or later.

```sh
# Install into your Go bin directory
go install github.com/pan-dolina/ZoneLint/cmd/zonelint@latest

# Run it (the binary is in $(go env GOPATH)/bin)
zonelint example.com
```

Or build locally from a checkout:

```sh
git clone https://github.com/pan-dolina/ZoneLint.git
cd ZoneLint
go build -o dist/zonelint ./cmd/zonelint
./dist/zonelint example.com
```

### From a release

Prebuilt binaries are published per release for Linux/macOS/Windows on amd64
and arm64. See [`docs/release-verification.md`](docs/release-verification.md).

## Documentation

- [`docs/checks.md`](docs/checks.md) — the check catalog (IDs, rationale,
  severity, evidence, recommendations, false positives, references).
- [`docs/dnssec.md`](docs/dnssec.md) — DNSSEC validation model.
- [`docs/ttl.md`](docs/ttl.md) — TTL policy profiles.
- [`docs/active-scans.md`](docs/active-scans.md) — active scan safety.
- [`docs/standards.md`](docs/standards.md) — RFCs and standards referenced.
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — architecture.
- [`docs/DEVELOPMENT_PLAN.md`](docs/DEVELOPMENT_PLAN.md) — roadmap.

## License

Apache-2.0. See [`LICENSE`](LICENSE).
