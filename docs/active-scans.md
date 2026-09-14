# Active Scans

Active scans are opt-in and safe. They issue a minimal number of queries and
never perform denial-of-service, amplification, spoofing, or poisoning.

Enable with `--active`.

## Scans

- **AXFR** — attempts a bounded zone transfer per authoritative server, capped
  at 1000 records. Never prints the full zone unless `--show-axfr-records`.
- **Recursion check** — issues a single query for a cryptographically random
  name to each authoritative server. Reports open recursion only if the server
  answers recursively for a non-existent name.
- **Protocol probes** — limited, bounded queries to assess reachability and
  behavior.

## Budgets

All active scans are subject to the query budget: max QPS, max queries,
concurrency cap, and per-server timeout. Set via `--max-qps`, `--max-queries`,
`--timeout`.

## Safety guarantees

- Random names are generated with `crypto/rand`.
- No amplification: queries are small, responses are bounded.
- No spoofing: queries go to configured resolvers only.
- No DoS: query budget strictly limits load.
