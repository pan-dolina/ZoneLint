# Architecture and Implementation Roadmap

Status: accepted

## 1. Design principles

- **Interface-driven DNS** — every network interaction goes through a
  `Resolver` interface, so tests use an in-memory authoritative server and
  production uses a real UDP/TCP resolver.
- **Budget-first** — the query budget is enforced at the transport boundary.
- **Pure checks** — each check is a pure function over collected records,
  making it unit-testable without the network.
- **Deterministic output** — findings carry stable IDs, severities, and
  evidence for golden testing.

## 2. Package layout

```
ZoneLint/
├── cmd/
│   └── zonelint/            # CLI entrypoint (flag parsing, orchestration)
├── internal/
│   ├── findings/            # Finding, Severity, IDs, category constants
│   ├── dns/                 # DNS message parsing helpers, record extraction
│   ├── resolver/            # Resolver interface, network + fake implementations
│   ├── budget/              # Query budget, token bucket, concurrency
│   ├── delegation/          # Parent/child NS + glue comparison
│   ├── authserver/          # Authoritative server probing
│   ├── soa/                 # SOA validation
│   ├── axfr/                # Bounded AXFR
│   ├── dnssec/              # DS/DNSKEY/RRSIG/NSEC parsing + chain validation
│   ├── ttl/                 # TTL collection + policy profiles
│   ├── caa/                 # CAA validation
│   ├── cname/               # CNAME loop/dangling detection
│   ├── addrs/               # Address classification
│   ├── wildcard/            # Wildcard detection
│   ├── active/              # Opt-in recursion + protocol probes
│   └── report/              # Human, JSON, SARIF renderers
├── testdata/                # Controlled zones (healthy, axfr, brokendnssec, ...)
└── docs/
```

## 3. Core data model

### 3.1 Finding

```go
type Finding struct {
    ID          string   // e.g. DNS-DELEGATION-001
    Severity    string   // critical|high|medium|low|info|pass
    Category    string   // delegation|authserver|soa|axfr|dnssec|ttl|caa|cname|address|wildcard|recursion
    Title       string
    Explanation string
    Evidence    []string
    Recommendation string
    References  []string
}
```

### 3.2 AuditResult

Aggregates findings, collected records, and metadata (zone, resolver, timing).

## 4. Resolver abstraction

```go
type Resolver interface {
    Lookup(ctx, req *dns.Msg) (*dns.Msg, error)
    Transfer(ctx, req *dns.Msg) (records, error) // for AXFR, budget-bounded
}
```

Implementations:

- `network.Resolver` — real UDP/TCP with EDNS, DO bit, retries, timeout.
- `fake.Resolver` — serves controlled zones from `testdata` for tests.

## 5. Check pipeline

1. Resolve zone NS from parent (delegation).
2. Probe each authoritative server (authserver).
3. Query SOA, DNSSEC, TTL-bearing records (reused across checks).
4. Attempt AXFR per server (bounded).
5. Run pure checks over collected records (delegation, soa, dnssec, ttl, caa,
   cname, addrs, wildcard).
6. (opt-in) Active recursion probe.
7. Render report.

## 6. Roadmap

See `DEVELOPMENT_PLAN.md` for the commit-level plan. Key milestones:

- M1: transport + testscaffold (resolver + controlled zones).
- M2: delegation + authserver + SOA.
- M3: AXFR + DNSSEC + NSEC.
- M4: TTL + CAA + CNAME + addresses + wildcard + recursion.
- M5: budgets + reporting + CLI.
- M6: tests (unit/functional/fuzz/bench), CI, security tooling.
- M7: supply-chain, release, docs.
