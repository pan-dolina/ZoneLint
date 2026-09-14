# Standards and References

ZoneLint's checks map to the following standards and best practices.

| Area | Reference |
|------|-----------|
| DNS architecture | RFC 1034, RFC 1035 |
| DNS names | RFC 1035 §2.3.1 |
| SOA | RFC 1035 §4.1.1 |
| Negative caching | RFC 2308 |
| Name server selection | RFC 1912 |
| TTL / caching | RFC 1912 §2.2 |
| DNSSEC (DNSKEY/RRSIG/DS) | RFC 4034, RFC 4035, RFC 4038 |
| NSEC | RFC 4034 §3.4 |
| NSEC3 | RFC 5155 |
| EDNS0 | RFC 6891 |
| CAA | RFC 8659 |
| Deprecated algorithms | RFC 9037 |
| AXFR | RFC 5936 |
| TSIG (transfer access) | RFC 1969 |
| Zone transfer restriction | RFC 1969, best practice |
| Private addressing | RFC 1918 |
| Reserved addresses | RFC 6890 |
| Documentation ranges | RFC 5737 |
| Loopback | RFC 1122 |
| Link-local IPv4 | RFC 3927 |
| Link-local IPv6 | RFC 4291 |

## Output formats

- **Human** — default, colored report.
- **JSON** — `--json`; `schema_version: "1"`.
- **SARIF** — `--format sarif`; SARIF 2.1.0.
