# Check Catalog

ZoneLint emits findings with stable IDs. Each finding carries a severity,
category, title, explanation, evidence, recommendation, and references.

## Severities

| Severity | Meaning |
|----------|---------|
| critical | Immediate exposure (e.g. open AXFR). |
| high     | Strong indicator of misconfiguration or exposure. |
| medium   | Likely misconfiguration; investigate. |
| low      | Weak signal or operational heuristic. |
| info     | Informational; not a vulnerability. |
| pass     | Positive control confirmed. |

## Categories

`delegation`, `authserver`, `soa`, `axfr`, `dnssec`, `ttl`, `caa`, `cname`,
`address`, `wildcard`, `recursion`, `transport`, `general`.

## Finding Reference

### Delegation (`DNS-DELEGATION-*`)

| ID | Severity | Description |
|----|----------|-------------|
| DNS-DELEGATION-001 | high | No delegation — parent cannot find zone NS. |
| DNS-DELEGATION-002 | high | Lame delegation — child does not claim authority. |
| DNS-DELEGATION-003 | medium | Stale or missing glue A/AAAA. |
| DNS-DELEGATION-004 | medium | NS without glue for sub-domain NS. |
| DNS-DELEGATION-005 | medium | NS host unreachable. |
| DNS-DELEGATION-006 | high | Parent/child NS set mismatch. |
| DNS-DELEGATION-007 | medium | NS server not authoritative. |
| DNS-DELEGATION-008 | medium | Inconsistent answer sets. |

### Authoritative Server (`DNS-AUTHSERVER-*`)

| ID | Severity | Description |
|----|----------|-------------|
| DNS-AUTHSERVER-001 | high | UDP not reachable. |
| DNS-AUTHSERVER-002 | medium | TCP fallback fails. |
| DNS-AUTHSERVER-003 | high | AA flag not set. |
| DNS-AUTHSERVER-004 | medium | SOA not in answer. |
| DNS-AUTHSERVER-005 | low | NS not in answer. |
| DNS-AUTHSERVER-006 | info | EDNS/DO unsupported. |
| DNS-AUTHSERVER-007 | medium | Inconsistent responses across servers. |

### SOA (`DNS-SOA-*`)

| ID | Severity | Description |
|----|----------|-------------|
| DNS-SOA-001 | medium | Malformed SOA MNAME. |
| DNS-SOA-002 | medium | Malformed SOA RNAME. |
| DNS-SOA-003 | low | SOA serial format heuristic. |
| DNS-SOA-004 | low | Refresh/retry/expire sanity. |
| DNS-SOA-005 | info | Low negative-cache TTL. |

### AXFR (`DNS-AXFR-*`)

| ID | Severity | Description |
|----|----------|-------------|
| DNS-AXFR-001 | critical | Zone transfer allowed. |
| DNS-AXFR-002 | pass | Transfer refused (good default). |
| DNS-AXFR-003 | info | Transfer failed/error. |

### DNSSEC (`DNS-DNSSEC-*`)

| ID | Severity | Description |
|----|----------|-------------|
| DNS-DNSSEC-001 | high | RRSIG present without DNSKEY. |
| DNS-DNSSEC-002 | medium | DNSKEY present without RRSIG. |
| DNS-DNSSEC-003 | high | DS/DNSKEY mismatch. |
| DNS-DNSSEC-004 | medium | No DS at delegation. |
| DNS-DNSSEC-005 | high | Expired signature. |
| DNS-DNSSEC-006 | medium | Not-yet-valid signature. |
| DNS-DNSSEC-007 | low | Deprecated algorithm. |
| DNS-DNSSEC-008 | high | Broken chain of trust. |
| DNS-DNSSEC-009 | low | No NSEC/NSEC3 records. |
| DNS-DNSSEC-010 | medium | Malformed NSEC3 parameters. |

### TTL (`DNS-TTL-*`)

| ID | Severity | Description |
|----|----------|-------------|
| DNS-TTL-001 | info | Low TTL (profile-dependent). |
| DNS-TTL-002 | low | Extreme TTL. |

### CAA (`DNS-CAA-*`)

| ID | Severity | Description |
|----|----------|-------------|
| DNS-CAA-001 | low | Malformed CAA record. |
| DNS-CAA-002 | medium | Unknown critical CAA property. |

### CNAME (`DNS-CNAME-*`)

| ID | Severity | Description |
|----|----------|-------------|
| DNS-CNAME-001 | high | CNAME loop. |
| DNS-CNAME-002 | medium | Excessive CNAME chain. |
| DNS-CNAME-003 | medium | CNAME coexistence with other records. |
| DNS-CNAME-004 | high | Dangling CNAME target. |

### Address Classification (`DNS-ADDRESS-*`)

| ID | Severity | Description |
|----|----------|-------------|
| DNS-ADDRESS-001 | medium | Private (RFC1918) address. |
| DNS-ADDRESS-002 | medium | Loopback address. |
| DNS-ADDRESS-003 | low | Link-local address. |
| DNS-ADDRESS-004 | low | Reserved address. |
| DNS-ADDRESS-005 | low | Documentation-range address. |

### Wildcard (`DNS-WILDCARD-001`)

| ID | Severity | Description |
|----|----------|-------------|
| DNS-WILDCARD-001 | info | Wildcard DNS record present. |

### Recursion (`DNS-RECURSION-001`)

| ID | Severity | Description |
|----|----------|-------------|
| DNS-RECURSION-001 | high | Open recursion on authoritative server. |

### Transport / General

| ID | Severity | Description |
|----|----------|-------------|
| DNS-TRANSPORT-001 | medium | Query transport timeout. |
| DNS-GENERAL-001 | high | General error (e.g. initial resolution failed). |
