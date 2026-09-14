# Changelog

All notable changes to ZoneLint are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0]

### Added

- DNS and delegation audit: parent NS vs. child NS, glue, A/AAAA, lame
  delegation, stale/missing glue, unreachable or inconsistent NS.
- Authoritative server probing: UDP/TCP reachability, AA flag, SOA/NS
  presence, EDNS support, response consistency.
- SOA validation: MNAME, RNAME, serial format, refresh/retry/expire/minimum.
- Bounded AXFR assessment with per-server record limits.
- DNSSEC validation: DNSKEY/RRSIG/DS parsing, chain of trust, key tag,
  algorithm, digest, inception/expiration, NSEC/NSEC3.
- TTL policy profiles: conservative, balanced, agile.
- CAA validation, CNAME loop/dangling detection, private-address
  classification, and wildcard detection.
- Opt-in active scans: AXFR and recursion checks, subject to the query budget.
- Query budget enforcement: max queries, QPS, concurrency, per-server timeout.
- Output formats: human report, versioned JSON, and optional SARIF.
- CLI flags: `--json`, `--format`, `--active`, `--resolver`, `--profile`,
  `--fail-on`, `--timeout`, `--max-qps`, `--max-queries`, `--no-color`,
  `--quiet`, `--verbose`, `--show-axfr-records`, `version`.
- Documentation, CI gate, and cross-platform release pipeline.
