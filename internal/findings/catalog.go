package findings

import (
	"slices"
	"strings"
)

// The catalog holds every rule known to ZoneLint. Rule IDs are a public
// interface: they are never renumbered or reused. A rule that is no longer
// emitted stays in the catalog with a "Deprecated:" title prefix.

// Reference URLs used across rules.
const (
	RFC1035 = "https://www.rfc-editor.org/rfc/rfc1035"
	RFC1034 = "https://www.rfc-editor.org/rfc/rfc1034"
	RFC1918 = "https://www.rfc-editor.org/rfc/rfc1918"
	RFC1969 = "https://www.rfc-editor.org/rfc/rfc1969"
	RFC1982 = "https://www.rfc-editor.org/rfc/rfc1982"
	RFC1996 = "https://www.rfc-editor.org/rfc/rfc1996"
	RFC2181 = "https://www.rfc-editor.org/rfc/rfc2181"
	RFC2308 = "https://www.rfc-editor.org/rfc/rfc2308"
	RFC4034 = "https://www.rfc-editor.org/rfc/rfc4034"
	RFC4035 = "https://www.rfc-editor.org/rfc/rfc4035"
	RFC4592 = "https://www.rfc-editor.org/rfc/rfc4592"
	RFC5155 = "https://www.rfc-editor.org/rfc/rfc5155"
	RFC5936 = "https://www.rfc-editor.org/rfc/rfc5936"
	RFC5321 = "https://www.rfc-editor.org/rfc/rfc5321"
	RFC6762 = "https://www.rfc-editor.org/rfc/rfc6762"
	RFC6890 = "https://www.rfc-editor.org/rfc/rfc6890"
	RFC6891 = "https://www.rfc-editor.org/rfc/rfc6891"
	RFC7505 = "https://www.rfc-editor.org/rfc/rfc7505"
	RFC8020 = "https://www.rfc-editor.org/rfc/rfc8020"
	RFC8659 = "https://www.rfc-editor.org/rfc/rfc8659"
)

var catalog = map[string]Rule{}

func register(r Rule) Rule {
	if _, dup := catalog[r.ID]; dup {
		panic("findings: duplicate rule ID " + r.ID)
	}
	catalog[r.ID] = r
	return r
}

// Lookup returns the rule with the given ID.
func Lookup(id string) (Rule, bool) {
	r, ok := catalog[id]
	return r, ok
}

// Rules returns all rules ordered by ID.
func Rules() []Rule {
	out := make([]Rule, 0, len(catalog))
	for _, r := range catalog {
		out = append(out, r)
	}
	slices.SortFunc(out, func(a, b Rule) int { return strings.Compare(a.ID, b.ID) })
	return out
}

// Delegation rules.
var (
	DelegMissing = register(Rule{
		ID:             "DNS-DELEGATION-001",
		Component:      ComponentDelegation,
		Category:       CategoryWeakness,
		Severity:       SeverityHigh,
		Title:          "No delegation — parent cannot find the zone NS",
		Recommendation: "Verify the parent zone's NS records for this zone. A missing delegation means resolvers cannot find the authoritative name servers.",
		References:     []string{RFC1035 + "#section-3.5.3", RFC2181 + "#section-10.3"},
	})
	DelegLame = register(Rule{
		ID:             "DNS-DELEGATION-002",
		Component:      ComponentDelegation,
		Category:       CategoryWeakness,
		Severity:       SeverityHigh,
		Title:          "Lame delegation — the queried server does not claim authority",
		Recommendation: "Ensure the child zone publishes the NS records named by the parent. A lame delegation forces every resolver to fall back to the parent.",
		References:     []string{RFC1035 + "#section-3.5.3", RFC2181 + "#section-10.3"},
	})
	DelegStaleGlue = register(Rule{
		ID:             "DNS-DELEGATION-003",
		Component:      ComponentDelegation,
		Category:       CategoryViolation,
		Severity:       SeverityMedium,
		Title:          "Glue A/AAAA records are stale or missing",
		Recommendation: "Publish current A and AAAA glue for in-bailiwick NS hosts. Stale glue can cause the delegated zone to become unreachable.",
		References:     []string{RFC1035 + "#section-3.5.3", RFC2181 + "#section-10.3"},
	})
	DelegMissingGlue = register(Rule{
		ID:             "DNS-DELEGATION-004",
		Component:      ComponentDelegation,
		Category:       CategoryViolation,
		Severity:       SeverityMedium,
		Title:          "NS without glue for in-bailiwick name server",
		Recommendation: "For a name server that is itself a subdomain of the delegated zone, publish A/AAAA glue records so resolvers can reach it.",
		References:     []string{RFC1035 + "#section-4.1.1", RFC2181 + "#section-10.3"},
	})
	DelegUnreachable = register(Rule{
		ID:             "DNS-DELEGATION-005",
		Component:      ComponentDelegation,
		Category:       CategoryWeakness,
		Severity:       SeverityMedium,
		Title:          "Name server is unreachable",
		Recommendation: "Ensure every NS host is reachable over UDP and TCP. An unreachable name server makes the zone intermittently unavailable.",
		References:     []string{RFC1035 + "#section-3.5.3"},
	})
	DelegInconsistentNS = register(Rule{
		ID:             "DNS-DELEGATION-006",
		Component:      ComponentDelegation,
		Category:       CategoryViolation,
		Severity:       SeverityHigh,
		Title:          "Parent and child name server sets do not match",
		Recommendation: "Make the parent zone's NS records and the child zone's NS records agree. Mismatched sets cause intermittent lame delegations.",
		References:     []string{RFC1035 + "#section-3.5.3", RFC2181 + "#section-10.3"},
	})
	DelegNonAuthNS = register(Rule{
		ID:             "DNS-DELEGATION-007",
		Component:      ComponentDelegation,
		Category:       CategoryWeakness,
		Severity:       SeverityMedium,
		Title:          "Name server is not authoritative for the zone",
		Recommendation: "Point the delegation at servers that answer AA=1 for the zone. A non-authoritative NS host cannot serve the zone.",
		References:     []string{RFC1035 + "#section-3.5.3"},
	})
	DelegInconsistentAnswer = register(Rule{
		ID:             "DNS-DELEGATION-008",
		Component:      ComponentDelegation,
		Category:       CategoryInformational,
		Severity:       SeverityLow,
		Title:          "Inconsistent answer sets across name servers",
		Recommendation: "Investigate why name servers return different records. Inconsistency often indicates misconfiguration or split-horizon DNS.",
		References:     []string{RFC1035 + "#section-3.5.3"},
	})
)

// Authoritative server rules.
var (
	AuthUDPFail = register(Rule{
		ID:             "DNS-AUTHSERVER-001",
		Component:      ComponentAuthServer,
		Category:       CategoryWeakness,
		Severity:       SeverityHigh,
		Title:          "Authoritative server not reachable over UDP",
		Recommendation: "Ensure the authoritative server accepts UDP queries on port 53. UDP is required for normal DNS resolution.",
		References:     []string{RFC1035 + "#section-4.2"},
	})
	AuthTCPFail = register(Rule{
		ID:             "DNS-AUTHSERVER-002",
		Component:      ComponentAuthServer,
		Category:       CategoryWeakness,
		Severity:       SeverityMedium,
		Title:          "TCP fallback fails",
		Recommendation: "Ensure the authoritative server accepts TCP connections on port 53. Responses larger than 512 octets require TCP.",
		References:     []string{RFC1035 + "#section-4.2.1"},
	})
	AuthNoAA = register(Rule{
		ID:             "DNS-AUTHSERVER-003",
		Component:      ComponentAuthServer,
		Category:       CategoryViolation,
		Severity:       SeverityHigh,
		Title:          "AA flag not set on authoritative response",
		Recommendation: "The authoritative server must set the AA flag for answers about its zone. A missing AA flag makes the response ambiguous.",
		References:     []string{RFC1035 + "#section-4.1.1"},
	})
	AuthNoSOA = register(Rule{
		ID:             "DNS-AUTHSERVER-004",
		Component:      ComponentAuthServer,
		Category:       CategoryViolation,
		Severity:       SeverityMedium,
		Title:          "SOA record not present in the response",
		Recommendation: "Every authoritative answer, including denial of existence, must include the zone SOA in the authority section.",
		References:     []string{RFC1035 + "#section-3.3.2", RFC1035 + "#section-4.1.1"},
	})
	AuthNoNS = register(Rule{
		ID:             "DNS-AUTHSERVER-005",
		Component:      ComponentAuthServer,
		Category:       CategoryViolation,
		Severity:       SeverityLow,
		Title:          "NS records not present in the response",
		Recommendation: "The zone apex answer should include the zone NS records. Missing NS records can confuse resolvers.",
		References:     []string{RFC1035 + "#section-3.5.3"},
	})
	AuthNoEDNS = register(Rule{
		ID:             "DNS-AUTHSERVER-006",
		Component:      ComponentAuthServer,
		Category:       CategoryHardening,
		Severity:       SeverityInfo,
		Title:          "EDNS/DO not supported",
		Recommendation: "Enable EDNS0 (and the DNSSEC OK bit) so DNSSEC responses are not truncated.",
		References:     []string{RFC6891},
	})
	AuthInconsistent = register(Rule{
		ID:             "DNS-AUTHSERVER-007",
		Component:      ComponentAuthServer,
		Category:       CategoryWeakness,
		Severity:       SeverityMedium,
		Title:          "Inconsistent responses across name servers",
		Recommendation: "Investigate why name servers return different answers. Inconsistency often indicates misconfiguration or partial propagation.",
		References:     []string{RFC1035 + "#section-3.5.3"},
	})
)

// SOA rules.
var (
	SOAInvalidMNAME = register(Rule{
		ID:             "DNS-SOA-001",
		Component:      ComponentSOA,
		Category:       CategoryViolation,
		Severity:       SeverityMedium,
		Title:          "Malformed SOA MNAME",
		Recommendation: "The SOA MNAME (primary name server) must be a valid fully-qualified domain name.",
		References:     []string{RFC1035 + "#section-3.3.1", RFC1035 + "#section-5.1"},
	})
	SOAInvalidRNAME = register(Rule{
		ID:             "DNS-SOA-002",
		Component:      ComponentSOA,
		Category:       CategoryViolation,
		Severity:       SeverityMedium,
		Title:          "Malformed SOA RNAME",
		Recommendation: "The SOA RNAME (responsible authority email) must be a valid fully-qualified domain name.",
		References:     []string{RFC1035 + "#section-3.3.1", RFC1035 + "#section-5.1"},
	})
	SOASerialFormat = register(Rule{
		ID:             "DNS-SOA-003",
		Component:      ComponentSOA,
		Category:       CategoryHardening,
		Severity:       SeverityLow,
		Title:          "SOA serial format heuristic",
		Recommendation: "Use a serial format such as YYYYMMDDnn or an incrementing counter so changes are detectable.",
		References:     []string{RFC1035 + "#section-3.3.1"},
	})
	SOASchedule = register(Rule{
		ID:             "DNS-SOA-004",
		Component:      ComponentSOA,
		Category:       CategoryHardening,
		Severity:       SeverityLow,
		Title:          "SOA refresh/retry/expire sanity",
		Recommendation: "Choose refresh, retry and expire values that let secondary servers keep the zone fresh without excessive polling.",
		References:     []string{RFC1035 + "#section-3.3.1"},
	})
	SOANegativeTTL = register(Rule{
		ID:             "DNS-SOA-005",
		Component:      ComponentSOA,
		Category:       CategoryHardening,
		Severity:       SeverityInfo,
		Title:          "Low negative-cache TTL",
		Recommendation: "Raise the SOA minimum/TTL so that negative answers are not re-queried excessively.",
		References:     []string{RFC2308 + "#section-3"},
	})
)

// AXFR rules.
var (
	AXFRAllowed = register(Rule{
		ID:             "DNS-AXFR-001",
		Component:      ComponentAXFR,
		Category:       CategoryWeakness,
		Severity:       SeverityCritical,
		Title:          "Zone transfer allowed to arbitrary clients",
		Recommendation: "Restrict AXFR to authorized secondary name servers only. Open zone transfers leak the full zone contents.",
		References:     []string{RFC1035 + "#section-5.3.2"},
	})
	AXFRRefused = register(Rule{
		ID:         "DNS-AXFR-002",
		Component:  ComponentAXFR,
		Category:   CategoryInformational,
		Severity:   SeverityPass,
		Title:      "Zone transfer refused (good default)",
		References: []string{RFC1035 + "#section-5.3.2"},
	})
	AXFRFailed = register(Rule{
		ID:         "DNS-AXFR-003",
		Component:  ComponentAXFR,
		Category:   CategoryInformational,
		Severity:   SeverityInfo,
		Title:      "Zone transfer failed or errored",
		References: []string{RFC1035 + "#section-5.3.2"},
	})
)

// DNSSEC rules.
var (
	DNSSECNoDNSKEY = register(Rule{
		ID:             "DNS-DNSSEC-001",
		Component:      ComponentDNSSEC,
		Category:       CategoryWeakness,
		Severity:       SeverityHigh,
		Title:          "RRSIG present without DNSKEY",
		Recommendation: "Publish DNSKEY records. Without DNSKEY, RRSIGs cannot be validated.",
		References:     []string{RFC4034 + "#section-2.1", RFC4035 + "#section-2.4"},
	})
	DNSSECNoRRSIG = register(Rule{
		ID:             "DNS-DNSSEC-002",
		Component:      ComponentDNSSEC,
		Category:       CategoryWeakness,
		Severity:       SeverityMedium,
		Title:          "DNSKEY present without RRSIG",
		Recommendation: "Sign the zone so DNSKEY records are covered by RRSIGs. Uncovered DNSKEY records cannot be validated.",
		References:     []string{RFC4034 + "#section-2.2", RFC4035},
	})
	DNSSECSignExpired = register(Rule{
		ID:             "DNS-DNSSEC-003",
		Component:      ComponentDNSSEC,
		Category:       CategoryWeakness,
		Severity:       SeverityHigh,
		Title:          "Expired signature",
		Recommendation: "Re-sign the zone before signatures expire. Expired signatures break validation.",
		References:     []string{RFC4035 + "#section-3.1.3.1"},
	})
	DNSSECSignNotYet = register(Rule{
		ID:             "DNS-DNSSEC-004",
		Component:      ComponentDNSSEC,
		Category:       CategoryWeakness,
		Severity:       SeverityMedium,
		Title:          "Not-yet-valid signature",
		Recommendation: "Ensure signature inception times are correct. A future inception time causes transient validation failures.",
		References:     []string{RFC4035 + "#section-3.1.3.1"},
	})
	DNSSECDeprecatedAlgo = register(Rule{
		ID:             "DNS-DNSSEC-005",
		Component:      ComponentDNSSEC,
		Category:       CategoryHardening,
		Severity:       SeverityLow,
		Title:          "Deprecated DNSSEC algorithm",
		Recommendation: "Prefer current algorithms such as RSASHA256 or ECDSAP256SHA256 over deprecated ones.",
		References:     []string{RFC8020},
	})
	DNSSECBrokenChain = register(Rule{
		ID:             "DNS-DNSSEC-006",
		Component:      ComponentDNSSEC,
		Category:       CategoryWeakness,
		Severity:       SeverityHigh,
		Title:          "Broken chain of trust",
		Recommendation: "Ensure the DS record at the delegation matches a DNSKEY in the child zone. A mismatch breaks validation.",
		References:     []string{RFC4034 + "#section-5.1", RFC4035 + "#section-4.1"},
	})
	DNSSECNoDS = register(Rule{
		ID:             "DNS-DNSSEC-007",
		Component:      ComponentDNSSEC,
		Category:       CategoryHardening,
		Severity:       SeverityMedium,
		Title:          "No DS record at the delegation",
		Recommendation: "Publish a DS record at the parent to establish the chain of trust for a DNSSEC-signed child zone.",
		References:     []string{RFC4034 + "#section-5.1"},
	})
	DNSSECNoNSEC = register(Rule{
		ID:             "DNS-DNSSEC-008",
		Component:      ComponentDNSSEC,
		Category:       CategoryHardening,
		Severity:       SeverityLow,
		Title:          "No NSEC/NSEC3 records",
		Recommendation: "Enable NSEC or NSEC3 for authenticated denial of existence.",
		References:     []string{RFC4034 + "#section-3.4.1", RFC5155 + "#section-4"},
	})
	DNSSECMalformedNSEC3 = register(Rule{
		ID:             "DNS-DNSSEC-009",
		Component:      ComponentDNSSEC,
		Category:       CategoryViolation,
		Severity:       SeverityMedium,
		Title:          "Malformed NSEC3 parameters",
		Recommendation: "Use valid NSEC3 hash type, flags, iterations and salt. Invalid parameters break authenticated denial of existence.",
		References:     []string{RFC5155 + "#section-2.1"},
	})
)

// TTL rules.
var (
	TTLShort = register(Rule{
		ID:             "DNS-TTL-001",
		Component:      ComponentTTL,
		Category:       CategoryInformational,
		Severity:       SeverityInfo,
		Title:          "Low TTL",
		Recommendation: "A low TTL increases query load and amplification surface. Raise it to a reasonable value unless fast changes are required.",
		References:     []string{RFC1035 + "#section-3.3.1"},
	})
	TTLExtreme = register(Rule{
		ID:             "DNS-TTL-002",
		Component:      ComponentTTL,
		Category:       CategoryHardening,
		Severity:       SeverityLow,
		Title:          "Extreme TTL",
		Recommendation: "A very high TTL delays propagation of legitimate changes. Keep TTLs within a reasonable range.",
		References:     []string{RFC1035 + "#section-3.3.1"},
	})
)

// CAA rules.
var (
	CAAMalformed = register(Rule{
		ID:             "DNS-CAA-001",
		Component:      ComponentCAA,
		Category:       CategoryViolation,
		Severity:       SeverityLow,
		Title:          "Malformed CAA record",
		Recommendation: "CAA records must follow RFC 8659 syntax: an issue or issuewild tag with a valid tag-value pair.",
		References:     []string{RFC8659},
	})
	CAACriticalUnknown = register(Rule{
		ID:             "DNS-CAA-002",
		Component:      ComponentCAA,
		Category:       CategoryWeakness,
		Severity:       SeverityMedium,
		Title:          "Unknown critical CAA property",
		Recommendation: "A critical CAA tag with an unknown meaning is ignored by compliant issuers. Use only defined tags such as issue and issuewild.",
		References:     []string{RFC8659},
	})
)

// CNAME rules.
var (
	CNAMELoop = register(Rule{
		ID:             "DNS-CNAME-001",
		Component:      ComponentCNAME,
		Category:       CategoryViolation,
		Severity:       SeverityHigh,
		Title:          "CNAME loop",
		Recommendation: "Remove the CNAME loop. A loop prevents the name from resolving.",
		References:     []string{RFC1035 + "#section-3.6.2", RFC1035 + "#section-5.1"},
	})
	CNAMEChainLong = register(Rule{
		ID:             "DNS-CNAME-002",
		Component:      ComponentCNAME,
		Category:       CategoryHardening,
		Severity:       SeverityMedium,
		Title:          "Excessive CNAME chain",
		Recommendation: "Shorten the CNAME chain. Long chains increase latency and risk of hitting the 10-CNAME limit.",
		References:     []string{RFC1035 + "#section-3.6.2"},
	})
	CNAMECoexist = register(Rule{
		ID:             "DNS-CNAME-003",
		Component:      ComponentCNAME,
		Category:       CategoryViolation,
		Severity:       SeverityMedium,
		Title:          "CNAME coexists with other records",
		Recommendation: "A CNAME must be the only record for a name. Remove the other records or replace the CNAME with the appropriate record type.",
		References:     []string{RFC1035 + "#section-3.6.2", RFC1035 + "#section-5.1"},
	})
	CNAMEDangling = register(Rule{
		ID:             "DNS-CNAME-004",
		Component:      ComponentCNAME,
		Category:       CategoryWeakness,
		Severity:       SeverityHigh,
		Title:          "Dangling CNAME target",
		Recommendation: "Point the CNAME at a name that resolves. A dangling CNAME can be hijacked by whoever registers the target name.",
		References:     []string{RFC1035 + "#section-3.6.2"},
	})
)

// Address classification rules.
var (
	AddrPrivate = register(Rule{
		ID:             "DNS-ADDRESS-001",
		Component:      ComponentAddress,
		Category:       CategoryViolation,
		Severity:       SeverityMedium,
		Title:          "Public record points to a private address",
		Recommendation: "Public records should not resolve to RFC1918 addresses unless intended.",
		References:     []string{RFC1918, RFC6890},
	})
	AddrLoopback = register(Rule{
		ID:             "DNS-ADDRESS-002",
		Component:      ComponentAddress,
		Category:       CategoryViolation,
		Severity:       SeverityMedium,
		Title:          "Public record points to a loopback address",
		Recommendation: "Public records should not resolve to 127.0.0.0/8. Loopback addresses are only meaningful on the local host.",
		References:     []string{RFC6890},
	})
	AddrLocal = register(Rule{
		ID:             "DNS-ADDRESS-003",
		Component:      ComponentAddress,
		Category:       CategoryViolation,
		Severity:       SeverityLow,
		Title:          "Public record points to a link-local address",
		Recommendation: "Public records should not resolve to link-local addresses (169.254.0.0/16, fe80::/10).",
		References:     []string{RFC6890},
	})
	AddrReserved = register(Rule{
		ID:             "DNS-ADDRESS-004",
		Component:      ComponentAddress,
		Category:       CategoryViolation,
		Severity:       SeverityLow,
		Title:          "Public record points to a reserved address",
		Recommendation: "Public records should not resolve to reserved address ranges.",
		References:     []string{RFC6890},
	})
	AddrDocumentation = register(Rule{
		ID:             "DNS-ADDRESS-005",
		Component:      ComponentAddress,
		Category:       CategoryViolation,
		Severity:       SeverityLow,
		Title:          "Public record points to a documentation-range address",
		Recommendation: "Public records should not resolve to documentation address ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24, 2001:db8::/32).",
		References:     []string{RFC6890},
	})
)

// Wildcard rules.
var (
	WildcardPresent = register(Rule{
		ID:             "DNS-WILDCARD-001",
		Component:      ComponentWildcard,
		Category:       CategoryInformational,
		Severity:       SeverityInfo,
		Title:          "Wildcard DNS record present",
		Recommendation: "A wildcard record answers for all undefined names in the zone. Ensure this is intended; wildcards can mask typosquatting and misconfiguration.",
		References:     []string{RFC1035 + "#section-3.3.3"},
	})
)

// Recursion rules.
var (
	RecursionOpen = register(Rule{
		ID:             "DNS-RECURSION-001",
		Component:      ComponentRecursion,
		Category:       CategoryWeakness,
		Severity:       SeverityHigh,
		Title:          "Open recursion on an authoritative server",
		Recommendation: "Disable open recursion on authoritative servers. Open resolvers can be abused for amplification attacks.",
		References:     []string{RFC2308 + "#section-5"},
	})
)

// Transport / general rules.
var (
	TransportTimeout = register(Rule{
		ID:             "DNS-TRANSPORT-001",
		Component:      ComponentTransport,
		Category:       CategoryInformational,
		Severity:       SeverityMedium,
		Title:          "Query transport timeout",
		Recommendation: "The query exceeded the configured timeout. Check the resolver and network path to the authoritative server.",
		References:     []string{RFC1035 + "#section-4.2"},
	})
	GeneralError = register(Rule{
		ID:             "DNS-GENERAL-001",
		Component:      ComponentGeneral,
		Category:       CategoryWeakness,
		Severity:       SeverityHigh,
		Title:          "Initial resolution failed",
		Recommendation: "The zone could not be resolved. Verify the zone name and the resolver configuration.",
		References:     []string{RFC1035},
	})
)
