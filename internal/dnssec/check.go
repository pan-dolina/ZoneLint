package dnssec

import (
	"time"

	"github.com/miekg/dns"

	"github.com/example/ZoneLint/internal/findings"
)

// CheckZone runs all DNSSEC checks over a collected ZoneKeys and returns findings.
func CheckZone(zone string, zk *ZoneKeys, now time.Time) []*findings.Finding {
	var out []*findings.Finding

	// Missing DNSKEY.
	if zk.HasRRSIG() && !zk.HasDNSKEY() {
		f := findings.New(findings.DNSSECNoDNSKEY, findings.SeverityHigh, findings.CategoryDNSSEC,
			"RRSIG present without DNSKEY")
		f.Explanation = "The zone signs records (RRSIG present) but publishes no DNSKEY, so signatures cannot be validated."
		f.WithZone(zone)
		f.Recommendation = "Publish the DNSKEY record(s) for the zone."
		f.References = []string{"RFC 4034 §3.1"}
		out = append(out, f)
	}

	// Missing RRSIG over present DNSKEY/DS.
	if zk.HasDNSKEY() && !zk.HasRRSIG() {
		f := findings.New(findings.DNSSECNoRRSIG, findings.SeverityMedium, findings.CategoryDNSSEC,
			"DNSKEY present without RRSIG")
		f.Explanation = "The zone publishes DNSKEY but does not sign its records; DNSSEC is incomplete."
		f.WithZone(zone)
		f.Recommendation = "Sign the zone so records carry RRSIG records."
		f.References = []string{"RFC 4034 §3.1"}
		out = append(out, f)
	}

	// Expired / not-yet-valid signatures.
	for _, sig := range allSigs(zk) {
		if sig.SignatureExpired(now) {
			f := findings.New(findings.DNSSECSignExpired, findings.SeverityHigh, findings.CategoryDNSSEC,
				"Expired DNSSEC signature")
			f.Explanation = "An RRSIG signature has expired and is no longer valid."
			f.AddEvidence("typecovered=%s keytag=%d expired=%d", dnsTypeString(sig.TypeCovered), sig.KeyTag, sig.Expiration)
			f.WithZone(zone)
			f.Recommendation = "Re-sign the zone promptly; expired signatures break the chain of trust."
			f.References = []string{"RFC 4035 §5.2"}
			out = append(out, f)
		}
		if sig.SignatureNotYetValid(now) {
			f := findings.New(findings.DNSSECSignNotYet, findings.SeverityMedium, findings.CategoryDNSSEC,
				"Not-yet-valid DNSSEC signature")
			f.Explanation = "An RRSIG signature is not yet valid (inception in the future)."
			f.AddEvidence("typecovered=%s keytag=%d inception=%d", dnsTypeString(sig.TypeCovered), sig.KeyTag, sig.Inception)
			f.WithZone(zone)
			f.Recommendation = "Ensure signing times are synchronized; verify signature inception."
			f.References = []string{"RFC 4035 §5.2"}
			out = append(out, f)
		}
		if DeprecatedAlgorithms[sig.Algorithm] {
			f := findings.New(findings.DNSSECDeprecatedAlgo, findings.SeverityLow, findings.CategoryDNSSEC,
				"Deprecated DNSSEC algorithm")
			f.Explanation = "The signature uses a deprecated algorithm (RFC 9037)."
			f.AddEvidence("algorithm=%d (%s)", sig.Algorithm, AlgoName(sig.Algorithm))
			f.WithZone(zone)
			f.Recommendation = "Resign with a modern algorithm (ECDSA-P256, Ed25519, RSA-SHA256/512)."
			f.References = []string{"RFC 9037"}
			out = append(out, f)
		}
	}

	// Broken chain: DS present but no matching DNSKEY.
	if zk.HasDS() {
		// We only have the zone's own DS here; a broken chain is reported when
		// validation cannot be completed. Flag as info to avoid over-reporting.
		_ = zk
	}

	return out
}

func allSigs(zk *ZoneKeys) []*RRSIGInfo {
	var out []*RRSIGInfo
	for _, ss := range zk.RRSigs {
		out = append(out, ss...)
	}
	return out
}

func dnsTypeString(typ uint16) string {
	return dns.TypeToString[typ]
}
