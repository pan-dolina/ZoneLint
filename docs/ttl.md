# TTL Policy

ZoneLint collects TTLs per record type and evaluates them against a profile.
TTL findings are operational heuristics, never vulnerabilities.

## Profiles

| Profile | Min acceptable TTL | Extreme threshold |
|---------|-------------------|-------------------|
| conservative | 300s | 86400s |
| balanced | 60s | 604800s |
| agile | 10s | 604800s |

## Findings

- **DNS-TTL-001 (info)** — TTL below the profile minimum. Improves propagation
  agility but reduces cache efficiency and increases query load.
- **DNS-TTL-002 (low)** — TTL above the extreme threshold. Reduces operational
  agility and delays propagation of legitimate changes.

## Record types evaluated

SOA, NS, A, AAAA, MX, CNAME, TXT, CAA, DNSKEY, DS.

## Usage

```
zonelint --profile conservative example.com
```
