# DNSSEC Validation

ZoneLint performs real cryptographic DNSSEC validation, not just record presence.

## What is validated

- **DNSKEY parsing** — flags, protocol, algorithm, public key bytes.
- **RRSIG verification** — canonical RRSIG data (18-byte header + signed RDATA)
  verified against the zone DNSKEY using the correct algorithm.
- **DS/DNSKEY matching** — digest computation (SHA-1/SHA-256/SHA-512) compared
  against the parent DS record.
- **Key tag** — computed per RFC 4034 Appendix B.
- **Algorithm support** — RSA-SHA1 (5), RSA-SHA1-NSEC3 (7), RSA-SHA256 (8),
  RSA-SHA512 (10), ECDSA-P256 (13), ECDSA-P384 (14), Ed25519 (15).
- **Signature timing** — inception/expiration checked against the current time.
- **NSEC/NSEC3** — presence, hash algorithm, iterations, salt sanity.

## Chain of trust

Validation follows the chain of trust from a known anchor: the zone's DS
records must match the zone's DNSKEY, and RRSIGs must verify against those
DNSKEYs. A broken link (DS/DNSKEY mismatch, missing DNSKEY, or unverifiable
RRSIG) is reported.

## Algorithm deprecation

RFC 9037 deprecated RSASHA1 and RSASHA1-NSEC3. Signatures using these algorithms
are flagged as low severity and recommend re-signing with a modern algorithm.

## Safety

All verification is read-only. ZoneLint never sends crafted queries to trigger
cache poisoning or amplification. DNSSEC checks operate on responses already
returned by the resolver.
