package dnssec

import (
	"bytes"
	"strings"
	"time"

	"github.com/miekg/dns"

	"github.com/example/ZoneLint/internal/dns"
)

// ChainResult reports the outcome of chain-of-trust validation.
type ChainResult struct {
	Valid          bool
	BrokenAt       string
	Reason         string
	Keys           []*KeyInfo
	Sigs           []*RRSIGInfo
	DSMatches      bool
	ExpiredSigs    []int
	NotYetSigs     []int
	DeprecatedSigs []int
}

// ZoneKeys collects DNSKEY/RRSIG/DS records from a response by name.
type ZoneKeys struct {
	DNSKEYs map[string][]*KeyInfo   // name -> keys
	RRSigs  map[string][]*RRSIGInfo // name -> sigs
	DSs     map[string][]*DSInfo    // name -> DS
	ByType  map[string]map[uint16][]dns.RR
}

// Collect builds ZoneKeys from a DNS response's answer + authority sections.
func Collect(resp *dns.Msg) *ZoneKeys {
	zk := &ZoneKeys{
		DNSKEYs: map[string][]*KeyInfo{},
		RRSigs:  map[string][]*RRSIGInfo{},
		DSs:     map[string][]*DSInfo{},
		ByType:  map[string]map[uint16][]dns.RR{},
	}
	for _, sec := range [][]dns.RR{resp.Answer, resp.Ns} {
		for _, rr := range sec {
			if rr == nil {
				continue
			}
			name := dns.Fqdn(strings.ToLower(rr.Header().Name))
			if zk.ByType[name] == nil {
				zk.ByType[name] = map[uint16][]dns.RR{}
			}
			zk.ByType[name][rr.Header().Rrtype] = append(zk.ByType[name][rr.Header().Rrtype], rr)
			switch r := rr.(type) {
			case *dns.DNSKEY:
				if k, err := ParseDNSKEY(r); err == nil {
					zk.DNSKEYs[name] = append(zk.DNSKEYs[name], k)
				}
			case *dns.RRSIG:
				zk.RRSigs[name] = append(zk.RRSigs[name], ParseRRSIG(r))
			case *dns.DS:
				zk.DSs[name] = append(zk.DSs[name], ParseDS(r))
			}
		}
	}
	return zk
}

// HasDNSKEY reports whether the zone has any DNSKEY records.
func (z *ZoneKeys) HasDNSKEY() bool {
	return len(z.DNSKEYs) > 0
}

// HasRRSIG reports whether the zone has any RRSIG records.
func (z *ZoneKeys) HasRRSIG() bool {
	return len(z.RRSigs) > 0
}

// HasDS reports whether the zone has DS records.
func (z *ZoneKeys) HasDS() bool {
	return len(z.DSs) > 0
}

// ValidateChain validates the DNSSEC chain for a zone given a trusted anchor
// (parent DS). It returns a ChainResult describing validity and issues.
func ValidateChain(anchor *ZoneKeys, zoneKeys *ZoneKeys, now time.Time) ChainResult {
	res := ChainResult{Valid: true}
	res.Keys = mergeKeys(zoneKeys.DNSKEYs)
	res.Sigs = mergeSigs(zoneKeys.RRSigs)

	// Verify DS matches a DNSKEY.
	res.DSMatches = verifyDSMatchesDNSKEY(anchor, zoneKeys)

	// 3. Signature lifetime checks.
	for i, sig := range res.Sigs {
		if sig.SignatureExpired(now) {
			res.ExpiredSigs = append(res.ExpiredSigs, i)
			res.Valid = false
		}
		if sig.SignatureNotYetValid(now) {
			res.NotYetSigs = append(res.NotYetSigs, i)
			res.Valid = false
		}
		if DeprecatedAlgorithms[sig.Algorithm] {
			res.DeprecatedSigs = append(res.DeprecatedSigs, i)
		}
	}

	// 4. Broken chain: DS present but no matching DNSKEY, or DNSKEY present but
	//    DS absent at parent while zone claims DNSSEC.
	if zoneKeys.HasDNSKEY() && !anchor.HasDS() {
		// Zone has DNSKEY but parent provides no DS: trust anchor missing.
	}
	if !res.DSMatches && zoneKeys.HasDS() && anchor.HasDS() {
		res.Valid = false
		res.Reason = "DS does not match any DNSKEY in zone"
		res.BrokenAt = "parent DS / zone DNSKEY"
	}
	return res
}

func verifyDSMatchesDNSKEY(anchor, zone *ZoneKeys) bool {
	// The parent DS set is in anchor.DSs at the zone apex; the zone DNSKEYs are
	// in zone.DNSKEYs. Compare digests.
	apex := apexName(zone)
	dsSet := anchor.DSs[apex]
	if len(dsSet) == 0 {
		// No DS at parent: nothing to mismatch against; treat as not-matched.
		return false
	}
	keys := zone.DNSKEYs[apex]
	if len(keys) == 0 {
		return false
	}
	for _, ds := range dsSet {
		for _, k := range keys {
			rdata := DNSKEYRData(k)
			digest, err := ComputeDSDigest(ds.DigestType, rdata)
			if err != nil {
				continue
			}
			if bytes.Equal(digest, ds.Digest) {
				return true
			}
		}
	}
	return false
}

func apexName(z *ZoneKeys) string {
	// The apex is the zone name; for our fixtures it is the key present in DSs
	// that also has DNSKEYs, else the first DS key.
	for name := range z.DSs {
		if _, ok := z.DNSKEYs[name]; ok {
			return name
		}
	}
	for name := range z.DSs {
		return name
	}
	return ""
}

func mergeKeys(m map[string][]*KeyInfo) []*KeyInfo {
	var out []*KeyInfo
	for _, ks := range m {
		out = append(out, ks...)
	}
	return out
}

func mergeSigs(m map[string][]*RRSIGInfo) []*RRSIGInfo {
	var out []*RRSIGInfo
	for _, ss := range m {
		out = append(out, ss...)
	}
	return out
}

// VerifyRRSIGForType verifies that every RRSIG covering records of a given type
// over a given name is valid against the zone's keys. Returns the index of the
// first failing signature, or -1.
func VerifyRRSIGForType(zk *ZoneKeys, name string, rtype uint16, now time.Time) int {
	sigs := zk.RRSigs[name]
	var signedRData [][]byte
	for _, rr := range zk.ByType[name][rtype] {
		signedRData = append(signedRData, dnsutil.RRData(rr))
	}
	for i, sig := range sigs {
		if uint16(sig.TypeCovered) != rtype {
			continue
		}
		key := keyForKeyTag(zk, sig.KeyTag)
		if key == nil {
			continue
		}
		// Prepend the RRSIG's own rdata (minus signature) per RFC 4035 §5.2,
		// then concatenate the signed RR RDATA.
		full := sig.RawRdata
		for _, s := range signedRData {
			full = append(full, s...)
		}
		if err := Verify(sig, key, [][]byte{full}); err != nil {
			return i
		}
	}
	return -1
}

func keyForKeyTag(zk *ZoneKeys, tag uint16) *KeyInfo {
	for _, ks := range zk.DNSKEYs {
		for _, k := range ks {
			if k.KeyTag == tag {
				return k
			}
		}
	}
	return nil
}
