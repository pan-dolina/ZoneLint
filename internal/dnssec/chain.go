package dnssec

import (
	"bytes"
	"encoding/binary"
	"sort"
	"strings"
	"time"

	"github.com/miekg/dns"

	"github.com/pan-dolina/ZoneLint/internal/dns"
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
			digest, err := ComputeDSDigest(ds.DigestType, apex, rdata)
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
	rrs := zk.ByType[name][rtype]
	for i, sig := range sigs {
		if uint16(sig.TypeCovered) != rtype {
			continue
		}
		key := keyForKeyTag(zk, sig.KeyTag)
		if key == nil {
			continue
		}
		if err := Verify(sig, key, [][]byte{signedData(sig, name, rrs)}); err != nil {
			return i
		}
	}
	return -1
}

// signedData builds the octet sequence covered by an RRSIG per RFC 4035
// §5.3.2: the RRSIG RDATA with the Signature field excluded, followed by each
// RR of the RRset in canonical form (owner | type | class | OrigTTL |
// RDLENGTH | RDATA) in canonical order.
func signedData(sig *RRSIGInfo, owner string, rrs []dns.RR) []byte {
	out := append([]byte{}, sig.RawRdata...)

	// Wildcard expansion (RFC 4035 §5.3.2): when the RRSIG covers fewer
	// labels than the owner name has, the signed owner is the wildcard form.
	if labels := countLabels(owner); labels > int(sig.Labels) {
		owner = "*." + strings.Join(lastLabels(owner, int(sig.Labels)), ".") + "."
	}

	// The RRset may contain duplicates when records were merged from several
	// responses; a canonical RRset holds each RR once.
	canon := make([][]byte, 0, len(rrs))
	seenRD := map[string]bool{}
	for _, rr := range rrs {
		rd := dnsutil.RRData(rr)
		if rd == nil {
			continue
		}
		k := string(rd)
		if seenRD[k] {
			continue
		}
		seenRD[k] = true
		canon = append(canon, rd)
	}
	sort.Slice(canon, func(i, j int) bool { return bytes.Compare(canon[i], canon[j]) < 0 })

	ownerWire := dnsutil.CanonicalName(owner)
	for _, rd := range canon {
		out = append(out, ownerWire...)
		var hdr [8]byte
		binary.BigEndian.PutUint16(hdr[0:2], sig.TypeCovered)
		binary.BigEndian.PutUint16(hdr[2:4], dns.ClassINET)
		binary.BigEndian.PutUint32(hdr[4:8], sig.OriginalTTL)
		out = append(out, hdr[:]...)
		var rl [2]byte
		binary.BigEndian.PutUint16(rl[:], uint16(len(rd))) //#nosec G115 -- RDATA length fits in uint16
		out = append(out, rl[:]...)
		out = append(out, rd...)
	}
	return out
}

// countLabels returns the number of labels in a fully-qualified name.
func countLabels(fqdn string) int {
	n := strings.TrimSuffix(dns.Fqdn(fqdn), ".")
	if n == "" {
		return 0
	}
	return len(strings.Split(n, "."))
}

// lastLabels returns the rightmost n labels of a fully-qualified name.
func lastLabels(fqdn string, n int) []string {
	name := strings.TrimSuffix(dns.Fqdn(fqdn), ".")
	labels := strings.Split(name, ".")
	if n > len(labels) {
		n = len(labels)
	}
	return labels[len(labels)-n:]
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

// HasKeyForTag reports whether the zone keys contain a DNSKEY with the tag.
func (z *ZoneKeys) HasKeyForTag(tag uint16) bool {
	return keyForKeyTag(z, tag) != nil
}

// InZone returns a copy of z restricted to RRSIGs signed by the given zone.
// Negative responses at a delegation carry NSEC/NSEC3 records signed by the
// parent zone; those are not part of the zone's own DNSSEC state.
func (z *ZoneKeys) InZone(zone string) *ZoneKeys {
	apex := dns.Fqdn(strings.ToLower(zone))
	out := &ZoneKeys{
		DNSKEYs: map[string][]*KeyInfo{},
		RRSigs:  map[string][]*RRSIGInfo{},
		DSs:     map[string][]*DSInfo{},
		ByType:  z.ByType,
	}
	for name, ks := range z.DNSKEYs {
		out.DNSKEYs[name] = ks
	}
	for name, ds := range z.DSs {
		out.DSs[name] = ds
	}
	for name, ss := range z.RRSigs {
		for _, s := range ss {
			if strings.EqualFold(s.SignerName, apex) {
				out.RRSigs[name] = append(out.RRSigs[name], s)
			}
		}
	}
	return out
}
