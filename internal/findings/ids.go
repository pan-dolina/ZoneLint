package findings

import "fmt"

// sprintf is a tiny indirection so tests can stub string formatting if needed,
// and keeps the package free of a direct fmt import in hot paths.
func sprintf(format string, args ...any) string {
	return fmt.Sprintf(format, args...)
}

// Stable finding IDs. These are part of the public contract: do not rename.
const (
	// Delegation.
	DelegMissing            = "DNS-DELEGATION-001" // no delegation / parent cannot find zone NS
	DelegLame               = "DNS-DELEGATION-002" // lame delegation
	DelegStaleGlue          = "DNS-DELEGATION-003" // glue A/AAAA stale or missing
	DelegMissingGlue        = "DNS-DELEGATION-004" // NS without glue for sub-domain NS
	DelegUnreachable        = "DNS-DELEGATION-005" // NS host unreachable
	DelegInconsistentNS     = "DNS-DELEGATION-006" // parent/child NS set mismatch
	DelegNonAuthNS          = "DNS-DELEGATION-007" // NS server not authoritative
	DelegInconsistentAnswer = "DNS-DELEGATION-008" // inconsistent answer sets

	// Authoritative server.
	AuthUDPFail      = "DNS-AUTHSERVER-001" // UDP not reachable
	AuthTCPFail      = "DNS-AUTHSERVER-002" // TCP fallback fails
	AuthNoAA         = "DNS-AUTHSERVER-003" // AA flag not set
	AuthNoSOA        = "DNS-AUTHSERVER-004" // SOA not in answer
	AuthNoNS         = "DNS-AUTHSERVER-005" // NS not in answer
	AuthNoEDNS       = "DNS-AUTHSERVER-006" // EDNS/DO unsupported
	AuthInconsistent = "DNS-AUTHSERVER-007" // inconsistent responses across servers

	// SOA.
	SOAInvalidMNAME = "DNS-SOA-001"
	SOAInvalidRNAME = "DNS-SOA-002"
	SOASerialFormat = "DNS-SOA-003"
	SOASchedule     = "DNS-SOA-004" // refresh/retry/expire sanity
	SOANegativeTTL  = "DNS-SOA-005" // minimum/negative TTL

	// AXFR.
	AXFRAllowed = "DNS-AXFR-001" // zone transfer allowed (critical)
	AXFRRefused = "DNS-AXFR-002" // transfer refused (info)
	AXFRFailed  = "DNS-AXFR-003" // transfer failed/error

	// DNSSEC.
	DNSSECNoDNSKEY       = "DNS-DNSSEC-001"
	DNSSECNoRRSIG        = "DNS-DNSSEC-002"
	DNSSECDSMismatch     = "DNS-DNSSEC-003"
	DNSSECNoDS           = "DNS-DNSSEC-004"
	DNSSECSignExpired    = "DNS-DNSSEC-005"
	DNSSECSignNotYet     = "DNS-DNSSEC-006"
	DNSSECDeprecatedAlgo = "DNS-DNSSEC-007"
	DNSSECBrokenChain    = "DNS-DNSSEC-008"
	DNSSECNoNSEC         = "DNS-DNSSEC-009"
	DNSSECMalformedNSEC3 = "DNS-DNSSEC-010"

	// TTL.
	TTLShort   = "DNS-TTL-001"
	TTLExtreme = "DNS-TTL-002"

	// CAA.
	CAAMalformed       = "DNS-CAA-001"
	CAACriticalUnknown = "DNS-CAA-002"

	// CNAME.
	CNAMELoop      = "DNS-CNAME-001"
	CNAMEChainLong = "DNS-CNAME-002"
	CNAMECoexist   = "DNS-CNAME-003"
	CNAMEDangling  = "DNS-CNAME-004"

	// Address classification.
	AddrPrivate       = "DNS-ADDRESS-001"
	AddrLoopback      = "DNS-ADDRESS-002"
	AddrLocal         = "DNS-ADDRESS-003"
	AddrReserved      = "DNS-ADDRESS-004"
	AddrDocumentation = "DNS-ADDRESS-005"

	// Wildcard.
	WildcardPresent = "DNS-WILDCARD-001"

	// Recursion.
	RecursionOpen = "DNS-RECURSION-001"

	// Transport / general.
	TransportTimeout = "DNS-TRANSPORT-001"
	GeneralError     = "DNS-GENERAL-001"
)
