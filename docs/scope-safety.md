# DNS Audit Scope and Safety Model

Status: accepted
Audience: engineers, reviewers, downstream consumers

## 1. Purpose

ZoneLint audits the *publicly observable* DNS behavior of a zone and its
infrastructure. It answers the question: *"Given what the public DNS already
reveals about this zone, what are the configuration, resilience, and security
posture issues an operator should know about?"*

It is a **static + light-probe audit tool**, not a network attack tool.

## 2. In scope

For a target zone `example.com` ZoneLint evaluates:

| Category | Checks |
| --- | --- |
| Delegation | parent NS vs child NS, glue present/consistent, A/AAAA glue, lame delegation, unreachable NS, inconsistent NS, non-authoritative NS, inconsistent answer sets |
| Authoritative servers | UDP reachability, TCP reachability, AA flag, SOA present, NS present, EDNS/DO support, response consistency |
| SOA | MNAME, RNAME, serial format/rollover, refresh/retry/expire sanity, minimum/negative TTL |
| AXFR | allowed / refused / failed / record count, per authoritative NS |
| DNSSEC | DS present, DNSKEY present, RRSIG coverage, chain of trust, key tag match, algorithm acceptability, digest types, signature inception/expiration, NSEC/NSEC3 present |
| TTL | SOA/NS/A/AAAA/MX/CNAME/TXT/CAA/DNSKEY/DS TTLs vs policy profile |
| CAA | issue / issuewild / iodef, unknown critical, malformed syntax |
| CNAME | loops, excessive chains, coexistence violations, dangling targets |
| Address classification | public records pointing to RFC1918 / loopback / link-local / reserved / documentation ranges |
| Wildcard | presence via single random-name probe |
| Open recursion (active, opt-in) | authoritative server answering recursive queries |

## 3. Out of scope (explicitly forbidden)

ZoneLint must **never** perform:

- Denial-of-service (amplification, zone-transfer flooding, query floods).
- DNS spoofing / cache poisoning.
- Subdomain brute force or enumeration.
- Subdomain takeover attempts or resource claim.
- Any active exploitation beyond a single, bounded, read-only probe.

## 4. Safety model

### 4.1 Read-only

All queries are standard, idempotent DNS lookups (A, NS, SOA, DNSKEY, DS,
RRSIG, NSEC, etc.). ZoneLint never mutates state on any server.

### 4.2 Query budget

Every run is governed by a `Budget` (see `internal/budget`):

- `MaxQueries` — absolute cap on outbound queries; the run stops when spent.
- `MaxQPS` — token-bucket rate limit across all outbound queries.
- `MaxConcurrency` — bounded in-flight queries.
- `PerServerTimeout` — per-server dial/response timeout.
- `RecursionLimit` — guard against runaway resolution chains.

The budget is enforced by the resolver layer and cannot be bypassed by a check.

### 4.3 Minimal query count

- Delegation discovery uses a single parent-NS query plus per-NS probes.
- Wildcard detection uses **one** cryptographically random QNAME.
- DNSSEC validation reuses the responses gathered for other checks; it does not
  issue extra round-trips purely to validate.

### 4.4 Active scans are opt-in

AXFR, recursion probing, and limited protocol probes run only with `--active`.
They remain bounded by the same budget and record limits.

### 4.5 Response hardening

All DNS message parsing is defensive: oversized messages, malformed RRs, and
hostile content are parsed without panics and bounded in size. See
`docs/standards.md` §6.

## 5. Severity model

Severities follow a CVSS-adjacent qualitative scale:

- `critical` — data exposure / trust break (e.g., AXFR allowed, broken DNSSEC
  chain).
- `high` — strong resilience or security weakness (e.g., lame delegation,
  expired signatures).
- `medium` — notable misconfiguration (e.g., inconsistent NS, low TTL).
- `low` — minor issue or best-practice deviation.
- `info` — informational.
- `pass` — check ran and found no problem.

Heuristics (e.g., low TTL) are explicitly labeled as resilience/operations
heuristics, not hard RFC violations, and are never auto-escalated to
vulnerabilities.

## 6. False-positive control

Each check documents known false positives in `docs/checks.md`. The tool
prefers `info`/`pass` over `high` when evidence is ambiguous, and always
includes machine-readable `evidence` so downstream tooling can triage.
