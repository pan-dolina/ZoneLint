# ZoneLint

**Read-only DNS audit and lint tool** — inspects zone configurations, delegations, DNSSEC chain of trust, TTL policy, and infrastructure security without mounting any attacks.

## What it does

ZoneLint performs **read-only** DNS audits against authoritative servers and resolvers. It issues minimal, bounded queries and never performs denial-of-service, amplification, spoofing, or brute-force operations. It's a diagnostic and linting tool, not an exploitation framework.

### Audit coverage

ZoneLint checks 15+ categories of DNS configuration and security issues:

- **Delegation** — lame delegations, parent/child NS mismatches, stale glue records, unreachable NS servers
- **Authoritative servers** — UDP/TCP reachability, AA flag validation, SOA presence, response consistency
- **SOA parameters** — malformed MNAME/RNAME, serial format heuristics, refresh/retry/expire sanity
- **Zone transfers (AXFR)** — open transfer detection (opt-in active probing)
- **DNSSEC** — RRSIG without DNSKEY, broken chain of trust, expired/invalid signatures, deprecated algorithms, missing NSEC/NSEC3
- **TTL policy** — low/extreme TTL detection across SOA, NS, A, AAAA, MX, CNAME, TXT, CAA records with configurable profiles
- **CAA records** — malformed entries, unknown critical properties
- **CNAME structure** — loops, excessive chains, coexistence with other records, dangling targets
- **Address classification** — private (RFC1918), loopback, link-local, reserved, documentation-range addresses
- **Wildcard behavior** — wildcard record detection
- **Recursion** — open recursion detection on authoritative servers (opt-in)

## Key features

- **Stable finding IDs** — every finding carries a stable, non-renumbering ID (`DNS-<CATEGORY>-<NNN>`) for reliable CI integration and alerting
- **Severity ranking** — findings ranked as `critical`, `high`, ` medium`, `low`, `info`, or `pass`
- **Multiple output formats** — human-readable, JSON (`schema_version: "1"`), and SARIF for IDE/CI integration
- **Query budget enforcement** — configurable max queries, QPS limits, concurrency caps, and per-server timeouts ensure the tool stays lightweight and safe
- **Pure check architecture** — each check is a pure function with no network I/O, making the audit logic testable and deterministic
- **Profile-based policy** — configurable TTL policies (`conservative`, `balanced`, `agile`) to match organizational standards

## Use cases

- **CI/CD pipelines** — gate DNS changes with `-fail-on` severity thresholds
- **Security audits** — identify DNSSEC misconfigurations, open transfers, and infrastructure weaknesses
- **Operational monitoring** — detect TTL drift, delegation problems, and address misconfigurations
- **Compliance** — verify CAA records, DNSSEC deployment, and zone transfer policies

## Example

```bash
# Audit a zone with human-readable output
./dist/zonelint example.com

# Audit with JSON output for programmatic processing
./dist/zonelint example.com --format json

# Fail CI if medium+ severity findings are detected
./dist/zonelint example.com --fail-on medium

# Enable active probing for AXFR and recursion checks
./dist/zonelint example.com --active
```

## Installation

```bash
git clone https://github.com/example/ZoneLint.git
cd ZoneLint
go build -o dist/zonelint ./cmd/zonelint
```

## Development

```bash
go build ./...
go test -race ./...
```

## License

MIT
