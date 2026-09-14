# Security Model

ZoneLint is a read-only DNS audit tool. This document describes its security
boundaries and how it avoids becoming an attack vector.

## Design principles

1. **Read-only.** ZoneLint only sends queries and reads responses. It never
   modifies DNS state, never sends zone transfers as an attacker, and never
   crafts spoofed packets.
2. **Bounded.** Every query is subject to a query budget: max queries, max QPS,
   bounded concurrency, and per-server timeout. This prevents accidental or
   abusive load on target servers.
3. **Minimal queries.** Each check issues only the queries needed to answer it.
   No brute-force enumeration of subdomains.
4. **Safe wildcards.** Wildcard detection uses a single cryptographically
   random name per zone — no enumeration.
5. **Opt-in active scans.** AXFR, recursion checks, and protocol probes require
   `--active` and are strictly bounded.

## What ZoneLint does NOT do

- No denial-of-service.
- No amplification or reflection.
- No DNS spoofing or poisoning.
- No subdomain takeover exploitation.
- No brute-force or enumeration of names.
- No mutation of DNS records.

## Attack surface

- **Network:** ZoneLint sends DNS queries to configured resolvers. Configure
  `--resolver` to point at a trusted resolver.
- **Dependencies:** Pinned in `go.mod`/`go.sum`. CI runs `govulncheck` and
  `OSV-Scanner` on every push.
- **Secrets:** ZoneLint stores no secrets. Signing keys (if used) are external.

## Reporting vulnerabilities

Report security issues to the maintainers privately. Do not open a public
issue for potential security vulnerabilities.
