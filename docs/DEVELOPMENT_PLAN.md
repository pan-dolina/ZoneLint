# Development Plan

This is the roadmap for ZoneLint. The current release implements the core
audit pipeline, CLI, reporting, and CI.

## Completed

- [x] Findings model with stable IDs and severity ranking.
- [x] DNS transport and resolver abstraction (network + fake).
- [x] DNSSEC parsing and cryptographic validation.
- [x] Delegation, glue, and lame delegation checks.
- [x] Authoritative server probing.
- [x] SOA validation.
- [x] Bounded AXFR assessment.
- [x] NSEC/NSEC3 assessment.
- [x] TTL policy profiles.
- [x] CAA validation.
- [x] CNAME loop/dangling detection.
- [x] Address classification.
- [x] Wildcard detection.
- [x] Active recursion assessment.
- [x] Query budget enforcement.
- [x] Audit orchestration.
- [x] Human, JSON, SARIF reporting.
- [x] CLI with all flags.
- [x] 20 functional tests, fuzz targets, benchmarks.
- [x] CI gate (gofmt, vet, test, staticcheck, gosec, govulncheck, OSV-Scanner).
- [x] Cross-platform build/release workflow.
- [x] Documentation suite.

## Future

- [ ] Additional check packages per the 43-step commit plan.
- [ ] SARIF rule metadata enrichment.
- [ ] Cosign/SLSA provenance signing in release pipeline.
- [ ] Interactive/TUI output mode.
- [ ] Plugin/check authoring API.
- [ ] Multi-resolver fan-out with consensus.
