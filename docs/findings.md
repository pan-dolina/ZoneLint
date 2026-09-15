# Finding catalog

Finding IDs are stable across releases. This file is generated from
`internal/findings/catalog.go` by `go test ./internal/findings -update`.

Severity is the default; context may raise or lower it for a specific
finding.

## delegation

| ID | Default severity | Category | Title |
|----|------------------|----------|-------|
| `DNS-DELEGATION-001` | high | security-weakness | No delegation — parent cannot find the zone NS |
| `DNS-DELEGATION-002` | high | security-weakness | Lame delegation — the queried server does not claim authority |
| `DNS-DELEGATION-003` | medium | standard-violation | Glue A/AAAA records are stale or missing |
| `DNS-DELEGATION-004` | medium | standard-violation | NS without glue for in-bailiwick name server |
| `DNS-DELEGATION-005` | medium | security-weakness | Name server is unreachable |
| `DNS-DELEGATION-006` | high | standard-violation | Parent and child name server sets do not match |
| `DNS-DELEGATION-007` | medium | security-weakness | Name server is not authoritative for the zone |
| `DNS-DELEGATION-008` | low | informational | Inconsistent answer sets across name servers |

## authserver

| ID | Default severity | Category | Title |
|----|------------------|----------|-------|
| `DNS-AUTHSERVER-001` | high | security-weakness | Authoritative server not reachable over UDP |
| `DNS-AUTHSERVER-002` | medium | security-weakness | TCP fallback fails |
| `DNS-AUTHSERVER-003` | high | standard-violation | AA flag not set on authoritative response |
| `DNS-AUTHSERVER-004` | medium | standard-violation | SOA record not present in the response |
| `DNS-AUTHSERVER-005` | low | standard-violation | NS records not present in the response |
| `DNS-AUTHSERVER-006` | info | hardening | EDNS/DO not supported |
| `DNS-AUTHSERVER-007` | medium | security-weakness | Inconsistent responses across name servers |

## soa

| ID | Default severity | Category | Title |
|----|------------------|----------|-------|
| `DNS-SOA-001` | medium | standard-violation | Malformed SOA MNAME |
| `DNS-SOA-002` | medium | standard-violation | Malformed SOA RNAME |
| `DNS-SOA-003` | low | hardening | SOA serial format heuristic |
| `DNS-SOA-004` | low | hardening | SOA refresh/retry/expire sanity |
| `DNS-SOA-005` | info | hardening | Low negative-cache TTL |

## axfr

| ID | Default severity | Category | Title |
|----|------------------|----------|-------|
| `DNS-AXFR-001` | critical | security-weakness | Zone transfer allowed to arbitrary clients |
| `DNS-AXFR-002` | pass | informational | Zone transfer refused (good default) |
| `DNS-AXFR-003` | info | informational | Zone transfer failed or errored |

## dnssec

| ID | Default severity | Category | Title |
|----|------------------|----------|-------|
| `DNS-DNSSEC-001` | high | security-weakness | RRSIG present without DNSKEY |
| `DNS-DNSSEC-002` | medium | security-weakness | DNSKEY present without RRSIG |
| `DNS-DNSSEC-003` | high | security-weakness | Expired signature |
| `DNS-DNSSEC-004` | medium | security-weakness | Not-yet-valid signature |
| `DNS-DNSSEC-005` | low | hardening | Deprecated DNSSEC algorithm |
| `DNS-DNSSEC-006` | high | security-weakness | Broken chain of trust |
| `DNS-DNSSEC-007` | medium | hardening | No DS record at the delegation |
| `DNS-DNSSEC-008` | low | hardening | No NSEC/NSEC3 records |
| `DNS-DNSSEC-009` | medium | standard-violation | Malformed NSEC3 parameters |

## ttl

| ID | Default severity | Category | Title |
|----|------------------|----------|-------|
| `DNS-TTL-001` | info | informational | Low TTL |
| `DNS-TTL-002` | low | hardening | Extreme TTL |

## caa

| ID | Default severity | Category | Title |
|----|------------------|----------|-------|
| `DNS-CAA-001` | low | standard-violation | Malformed CAA record |
| `DNS-CAA-002` | medium | security-weakness | Unknown critical CAA property |

## cname

| ID | Default severity | Category | Title |
|----|------------------|----------|-------|
| `DNS-CNAME-001` | high | standard-violation | CNAME loop |
| `DNS-CNAME-002` | medium | hardening | Excessive CNAME chain |
| `DNS-CNAME-003` | medium | standard-violation | CNAME coexists with other records |
| `DNS-CNAME-004` | high | security-weakness | Dangling CNAME target |

## address

| ID | Default severity | Category | Title |
|----|------------------|----------|-------|
| `DNS-ADDRESS-001` | medium | standard-violation | Public record points to a private address |
| `DNS-ADDRESS-002` | medium | standard-violation | Public record points to a loopback address |
| `DNS-ADDRESS-003` | low | standard-violation | Public record points to a link-local address |
| `DNS-ADDRESS-004` | low | standard-violation | Public record points to a reserved address |
| `DNS-ADDRESS-005` | low | standard-violation | Public record points to a documentation-range address |

## wildcard

| ID | Default severity | Category | Title |
|----|------------------|----------|-------|
| `DNS-WILDCARD-001` | info | informational | Wildcard DNS record present |

## recursion

| ID | Default severity | Category | Title |
|----|------------------|----------|-------|
| `DNS-RECURSION-001` | high | security-weakness | Open recursion on an authoritative server |

## transport

| ID | Default severity | Category | Title |
|----|------------------|----------|-------|
| `DNS-TRANSPORT-001` | medium | informational | Query transport timeout |

## general

| ID | Default severity | Category | Title |
|----|------------------|----------|-------|
| `DNS-GENERAL-001` | high | security-weakness | Initial resolution failed |
