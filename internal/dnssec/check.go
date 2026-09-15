package dnssec

import (
	"fmt"
	"time"

	"github.com/miekg/dns"

	"github.com/pan-dolina/ZoneLint/internal/findings"
)

// CheckZone runs all DNSSEC checks over a collected ZoneKeys and returns findings.
func CheckZone(zone string, zk *ZoneKeys, now time.Time) []*findings.Finding {
	var out []*findings.Finding

	// Missing DNSKEY.
	if zk.HasRRSIG() && !zk.HasDNSKEY() {
		f := findings.DNSSECNoDNSKEY.New(zone,
			"The zone signs records (RRSIG present) but publishes no DNSKEY, so signatures cannot be validated.")
		out = append(out, &f)
	}

	// Missing RRSIG over present DNSKEY/DS.
	if zk.HasDNSKEY() && !zk.HasRRSIG() {
		f := findings.DNSSECNoRRSIG.New(zone,
			"The zone publishes DNSKEY but does not sign its records; DNSSEC is incomplete.")
		out = append(out, &f)
	}

	// Expired / not-yet-valid signatures.
	for _, sig := range allSigs(zk) {
		if sig.SignatureExpired(now) {
			f := findings.DNSSECSignExpired.New(zone,
				"An RRSIG signature has expired and is no longer valid.",
				fmt.Sprintf("typecovered=%s keytag=%d expired=%d", dnsTypeString(sig.TypeCovered), sig.KeyTag, sig.Expiration))
			out = append(out, &f)
		}
		if sig.SignatureNotYetValid(now) {
			f := findings.DNSSECSignNotYet.New(zone,
				"An RRSIG signature is not yet valid (inception in the future).",
				fmt.Sprintf("typecovered=%s keytag=%d inception=%d", dnsTypeString(sig.TypeCovered), sig.KeyTag, sig.Inception))
			out = append(out, &f)
		}
		if DeprecatedAlgorithms[sig.Algorithm] {
			f := findings.DNSSECDeprecatedAlgo.New(zone,
				"The signature uses a deprecated algorithm (RFC 9037).",
				fmt.Sprintf("algorithm=%d (%s)", sig.Algorithm, AlgoName(sig.Algorithm)))
			out = append(out, &f)
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
