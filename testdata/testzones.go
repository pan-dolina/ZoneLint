// Package testzones builds controlled authoritative DNS zones used by ZoneLint
// tests. Each constructor returns a resolver.Zone with deterministic records
// so functional tests can assert on stable findings.
package testzones

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/miekg/dns"

	dnsutil "github.com/pan-dolina/ZoneLint/internal/dns"
	"github.com/pan-dolina/ZoneLint/internal/resolver"
)

func name(s string) string { return dns.Fqdn(s) }

// signRR returns a signed copy of rr with the given RRSIG timing fields. The
// signature is a placeholder (not cryptographically verified) sufficient for the
// audit's timing/algorithm checks.
func signRR(rr dns.RR, rtype uint16, exp, inc uint32, flags uint16, algo uint8) dns.RR {
	clone := dns.Copy(rr)
	sig := new(dns.RRSIG)
	sig.Hdr = dns.RR_Header{Name: clone.Header().Name, Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: clone.Header().Ttl}
	sig.TypeCovered = rtype
	sig.Algorithm = algo
	sig.Labels = uint8(len(splitLabels(clone.Header().Name))) //#nosec G115 -- test fixture: label count fits in uint8
	sig.OrigTtl = clone.Header().Ttl
	sig.Expiration = exp
	sig.Inception = inc
	sig.KeyTag = 1234
	sig.SignerName = clone.Header().Name
	sig.Signature = "placeholder-signature-for-tests"
	return sig
}

func splitLabels(n string) []string {
	var out []string
	start := 0
	for i := 0; i < len(n); i++ {
		if n[i] == '.' {
			out = append(out, n[start:i])
			start = i + 1
		}
	}
	if start < len(n) {
		out = append(out, n[start:])
	}
	return out
}

func mustIP(s string) net.IP {
	ip := net.ParseIP(s)
	if ip == nil {
		panic("bad ip: " + s)
	}
	return ip
}

func soa(zone, mname, mbox string, serial, refresh, retry, expire, mintl uint32, ttl uint32) dns.RR {
	r := new(dns.SOA)
	r.Hdr = dns.RR_Header{Name: name(zone), Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: ttl}
	r.Ns = name(mname)
	r.Mbox = name(mbox)
	r.Serial = serial
	r.Refresh = refresh
	r.Retry = retry
	r.Expire = expire
	r.Minttl = mintl
	return r
}

func ns(zone, nsname string, ttl uint32) dns.RR {
	r := new(dns.NS)
	r.Hdr = dns.RR_Header{Name: name(zone), Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: ttl}
	r.Ns = name(nsname)
	return r
}

func a(zone, ip string, ttl uint32) dns.RR {
	r := new(dns.A)
	r.Hdr = dns.RR_Header{Name: name(zone), Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl}
	r.A = mustIP(ip)
	return r
}

func aaaa(zone, ip string, ttl uint32) dns.RR {
	r := new(dns.AAAA)
	r.Hdr = dns.RR_Header{Name: name(zone), Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: ttl}
	r.AAAA = mustIP(ip)
	return r
}

func txt(zone, s string, ttl uint32) dns.RR {
	r := new(dns.TXT)
	r.Hdr = dns.RR_Header{Name: name(zone), Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: ttl}
	r.Txt = []string{s}
	return r
}

func mx(zone, exchange string, pref uint16, ttl uint32) dns.RR {
	r := new(dns.MX)
	r.Hdr = dns.RR_Header{Name: name(zone), Rrtype: dns.TypeMX, Class: dns.ClassINET, Ttl: ttl}
	r.Mx = name(exchange)
	r.Preference = pref
	return r
}

func cname(zone, target string, ttl uint32) dns.RR {
	r := new(dns.CNAME)
	r.Hdr = dns.RR_Header{Name: name(zone), Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: ttl}
	r.Target = name(target)
	return r
}

func caa(zone string, critical int, tag, value string, ttl uint32) dns.RR {
	r := new(dns.CAA)
	r.Hdr = dns.RR_Header{Name: name(zone), Rrtype: dns.TypeCAA, Class: dns.ClassINET, Ttl: ttl}
	r.Tag = tag
	r.Value = value
	r.Flag = byte(critical) //#nosec G115 -- test fixture: critical flag is 0 or 1
	return r
}

// Healthy returns a well-formed, secure zone.
func Healthy() *resolver.Zone {
	zone := "healthy.test."
	return &resolver.Zone{
		Name: zone,
		Records: map[string][]dns.RR{
			zone: {
				soa(zone, "ns1.healthy.test.", "admin.healthy.test.", 2024010101, 7200, 1800, 1209600, 3600, 3600),
				ns(zone, "ns1.healthy.test.", 3600),
				ns(zone, "ns2.healthy.test.", 3600),
				a("ns1.healthy.test.", "198.51.100.10", 3600),
				a("ns2.healthy.test.", "198.51.100.20", 3600),
				a("healthy.test.", "203.0.113.10", 300),
				txt("healthy.test.", "v=spf1 -all", 300),
			},
		},
	}
}

// LameDelegation has child NS pointing at servers that are not authoritative.
func LameDelegation() *resolver.Zone {
	zone := "lamedelegation.test."
	sub := "sub.lamedelegation.test."
	return &resolver.Zone{
		Name: zone,
		Records: map[string][]dns.RR{
			zone: {
				soa(zone, "ns1.lamedelegation.test.", "admin.lamedelegation.test.", 1, 7200, 1800, 1209600, 3600, 3600),
				ns(zone, "ns1.lamedelegation.test.", 3600),
				// child NS set is inconsistent with parent (parent only lists ns1)
			},
			sub: {
				ns(sub, "ns1.lamedelegation.test.", 3600),
				ns(sub, "ns2.lamedelegation.test.", 3600),
				a("ns1.lamedelegation.test.", "198.51.100.10", 3600),
			},
		},
	}
}

// AXFRAllowed permits zone transfer.
func AXFRAllowed() *resolver.Zone {
	zone := "axfr.test."
	return &resolver.Zone{
		Name:            zone,
		TransferAllowed: true,
		Records: map[string][]dns.RR{
			zone: {
				soa(zone, "ns1.axfr.test.", "admin.axfr.test.", 1, 7200, 1800, 1209600, 3600, 3600),
				ns(zone, "ns1.axfr.test.", 3600),
				a("ns1.axfr.test.", "198.51.100.30", 3600),
				a("axfr.test.", "203.0.113.40", 300),
			},
		},
	}
}

// AXFRDenied refuses transfer.
func AXFRDenied() *resolver.Zone {
	zone := "axfrdenied.test."
	return &resolver.Zone{
		Name: zone,
		Records: map[string][]dns.RR{
			zone: {
				soa(zone, "ns1.axfrdenied.test.", "admin.axfrdenied.test.", 1, 7200, 1800, 1209600, 3600, 3600),
				ns(zone, "ns1.axfrdenied.test.", 3600),
				a("ns1.axfrdenied.test.", "198.51.100.40", 3600),
			},
		},
	}
}

// Recursion enables open recursion probing.
func Recursion() *resolver.Zone {
	return &resolver.Zone{
		Name:      "recursion.test.",
		Recursive: true,
		Records: map[string][]dns.RR{
			"recursion.test.": {
				soa("recursion.test.", "ns1.recursion.test.", "admin.recursion.test.", 1, 7200, 1800, 1209600, 3600, 3600),
				ns("recursion.test.", "ns1.recursion.test.", 3600),
				a("ns1.recursion.test.", "198.51.100.50", 3600),
			},
		},
	}
}

// ShortTTL uses very low TTLs.
func ShortTTL() *resolver.Zone {
	zone := "shortttl.test."
	return &resolver.Zone{
		Name: zone,
		Records: map[string][]dns.RR{
			zone: {
				soa(zone, "ns1.shortttl.test.", "admin.shortttl.test.", 1, 60, 60, 3600, 60, 30),
				ns(zone, "ns1.shortttl.test.", 30),
				a(zone, "203.0.113.60", 30),
			},
		},
	}
}

// Wildcard has a wildcard record.
func Wildcard() *resolver.Zone {
	zone := "wildcard.test."
	return &resolver.Zone{
		Name: zone,
		Records: map[string][]dns.RR{
			zone: {
				soa(zone, "ns1.wildcard.test.", "admin.wildcard.test.", 1, 7200, 1800, 1209600, 3600, 3600),
				ns(zone, "ns1.wildcard.test.", 3600),
				a("ns1.wildcard.test.", "198.51.100.60", 3600),
				a(zone, "203.0.113.70", 300),
			},
			"*.wildcard.test.": {
				a("*.wildcard.test.", "203.0.113.71", 300),
			},
		},
	}
}

// CNANameLoop has a CNAME loop a -> b -> a.
func CNANameLoop() *resolver.Zone {
	zone := "cnameraise.test."
	return &resolver.Zone{
		Name: zone,
		Records: map[string][]dns.RR{
			zone: {
				soa(zone, "ns1.cnameraise.test.", "admin.cnameraise.test.", 1, 7200, 1800, 1209600, 3600, 3600),
				ns(zone, "ns1.cnameraise.test.", 3600),
				a("ns1.cnameraise.test.", "198.51.100.70", 3600),
			},
			"a.cnameraise.test.": []dns.RR{cname("a.cnameraise.test.", "b.cnameraise.test.", 300)},
			"b.cnameraise.test.": []dns.RR{cname("b.cnameraise.test.", "a.cnameraise.test.", 300)},
		},
	}
}

// CNDangling has a CNAME pointing to a non-existent target.
func CNDangling() *resolver.Zone {
	zone := "cnameraisedangle.test."
	return &resolver.Zone{
		Name: zone,
		Records: map[string][]dns.RR{
			zone: {
				soa(zone, "ns1.cnameraisedangle.test.", "admin.cnameraisedangle.test.", 1, 7200, 1800, 1209600, 3600, 3600),
				ns(zone, "ns1.cnameraisedangle.test.", 3600),
				a("ns1.cnameraisedangle.test.", "198.51.100.80", 3600),
			},
			"dangling.cnameraisedangle.test.": []dns.RR{cname("dangling.cnameraisedangle.test.", "missing.example.", 300)},
		},
	}
}

// PrivateAddr has a public record pointing to a private IP.
func PrivateAddr() *resolver.Zone {
	zone := "privateaddr.test."
	return &resolver.Zone{
		Name: zone,
		Records: map[string][]dns.RR{
			zone: {
				soa(zone, "ns1.privateaddr.test.", "admin.privateaddr.test.", 1, 7200, 1800, 1209600, 3600, 3600),
				ns(zone, "ns1.privateaddr.test.", 3600),
				a("ns1.privateaddr.test.", "198.51.100.90", 3600),
				a(zone, "10.0.0.5", 300),
			},
		},
	}
}

// MalformedCAA has an unknown critical CAA property.
func MalformedCAA() *resolver.Zone {
	zone := "malformedcaa.test."
	return &resolver.Zone{
		Name: zone,
		Records: map[string][]dns.RR{
			zone: {
				soa(zone, "ns1.malformedcaa.test.", "admin.malformedcaa.test.", 1, 7200, 1800, 1209600, 3600, 3600),
				ns(zone, "ns1.malformedcaa.test.", 3600),
				a("ns1.malformedcaa.test.", "198.51.100.100", 3600),
				// unknown critical tag "issuetoken" with critical bit set
				caa(zone, 1, "issuetoken", "url=...", 300),
			},
		},
	}
}

// ExtremeTTL uses an absurdly high TTL.
func ExtremeTTL() *resolver.Zone {
	zone := "extremettl.test."
	return &resolver.Zone{
		Name: zone,
		Records: map[string][]dns.RR{
			zone: {
				soa(zone, "ns1.extremettl.test.", "admin.extremettl.test.", 1, 7200, 1800, 1209600, 3600, 3600),
				ns(zone, "ns1.extremettl.test.", 3600),
				a(zone, "203.0.113.110", 999999999),
			},
		},
	}
}

// DNSKEYRecord builds a valid Ed25519 DNSKEY record for the zone.
func DNSKEYRecord(zone string) dns.RR {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	dk := new(dns.DNSKEY)
	dk.Hdr = dns.RR_Header{Name: zone, Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600}
	dk.Flags = 256
	dk.Protocol = 3
	dk.Algorithm = 15 // Ed25519
	dk.PublicKey = base64.StdEncoding.EncodeToString(pub)
	return dk
}

// ExpireDNSSec has a valid DNSKEY but an expired RRSIG.
func ExpireDNSSec() *resolver.Zone {
	zone := "expireddnssec.test."
	now := time.Now().Add(-48 * time.Hour)
	exp := uint32(now.Add(-1 * time.Hour).Unix())  //#nosec G115 -- test fixture: Unix time fits in uint32
	inc := uint32(now.Add(-48 * time.Hour).Unix()) //#nosec G115 -- test fixture: Unix time fits in uint32
	a := a(zone, "203.0.113.20", 300)
	signed := signRR(a, dns.TypeA, exp, inc, 256, 15)
	return &resolver.Zone{
		Name: zone,
		Records: map[string][]dns.RR{
			zone: {
				soa(zone, "ns1.expireddnssec.test.", "admin.expireddnssec.test.", 2024010101, 7200, 1800, 1209600, 3600, 3600),
				ns(zone, "ns1.expireddnssec.test.", 3600),
				DNSKEYRecord(zone),
				a,
				signed,
			},
		},
	}
}

// BrokenDNSSec has a DNSKEY but no RRSIG (incomplete DNSSEC).
func BrokenDNSSec() *resolver.Zone {
	zone := "brokendnssec.test."
	return &resolver.Zone{
		Name: zone,
		Records: map[string][]dns.RR{
			zone: {
				soa(zone, "ns1.brokendnssec.test.", "admin.brokendnssec.test.", 2024010101, 7200, 1800, 1209600, 3600, 3600),
				ns(zone, "ns1.brokendnssec.test.", 3600),
				DNSKEYRecord(zone),
				a(zone, "203.0.113.30", 300),
			},
		},
	}
}

// testKey is an Ed25519 DNSSEC key used to build realistically signed fixtures.
type testKey struct {
	priv   ed25519.PrivateKey
	pub    ed25519.PublicKey
	keyTag uint16
}

func newTestKey() *testKey {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	return &testKey{priv: priv, pub: pub, keyTag: rfc4034KeyTag(257, 3, 15, pub)}
}

// rfc4034KeyTag computes the DNSKEY key tag per RFC 4034 Appendix B over the
// full DNSKEY RDATA (flags, protocol, algorithm, public key).
func rfc4034KeyTag(flags uint16, protocol, algo uint8, key []byte) uint16 {
	rdata := make([]byte, 4+len(key))
	binary.BigEndian.PutUint16(rdata[0:2], flags)
	rdata[2] = protocol
	rdata[3] = algo
	copy(rdata[4:], key)
	var ac uint32
	for i := 0; i < len(rdata); i++ {
		if i&1 == 0 {
			ac += uint32(rdata[i]) << 8
		} else {
			ac += uint32(rdata[i])
		}
	}
	ac += (ac >> 16) & 0xffff
	return uint16(ac & 0xffff)
}

// dnskeyRR returns the DNSKEY record for the key (flags 257: KSK+SEP).
func (k *testKey) dnskeyRR(zone string) *dns.DNSKEY {
	dk := new(dns.DNSKEY)
	dk.Hdr = dns.RR_Header{Name: name(zone), Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600}
	dk.Flags = 257
	dk.Protocol = 3
	dk.Algorithm = 15 // Ed25519
	dk.PublicKey = base64.StdEncoding.EncodeToString(k.pub)
	return dk
}

// dsRR returns the DS record at the delegation matching the DNSKEY (SHA-256).
// The digest is computed per RFC 4034 §5.1.4 over the canonical owner name
// concatenated with the DNSKEY RDATA.
func (k *testKey) dsRR(zone string, dk *dns.DNSKEY) *dns.DS {
	keyRData := make([]byte, 4+len(k.pub))
	binary.BigEndian.PutUint16(keyRData[0:2], dk.Flags)
	keyRData[2] = dk.Protocol
	keyRData[3] = dk.Algorithm
	copy(keyRData[4:], k.pub)
	digest := sha256.Sum256(append(dnsutil.CanonicalName(zone), keyRData...))
	return &dns.DS{
		Hdr:        dns.RR_Header{Name: name(zone), Rrtype: dns.TypeDS, Class: dns.ClassINET, Ttl: 3600},
		KeyTag:     k.keyTag,
		Algorithm:  15,
		DigestType: 2,
		Digest:     hex.EncodeToString(digest[:]),
	}
}

// signRRset returns an RRSIG over the RRset, constructed per RFC 4035 §5.3.2:
// RRSIG RDATA (minus signature, canonical signer name) followed by each RR in
// canonical form and canonical order. When tamper is true the signature bytes
// are corrupted so verification must fail.
func (k *testKey) signRRset(zone string, rrs []dns.RR, tamper bool) *dns.RRSIG {
	owner := dns.Fqdn(rrs[0].Header().Name)
	rtype := rrs[0].Header().Rrtype
	ttl := rrs[0].Header().Ttl
	labels := len(strings.Split(strings.TrimSuffix(owner, "."), "."))
	inc := uint32(time.Now().Add(-time.Hour).Unix())     //#nosec G115 -- test fixture: Unix time fits in uint32
	exp := uint32(time.Now().Add(48 * time.Hour).Unix()) //#nosec G115 -- test fixture: Unix time fits in uint32

	hdr := make([]byte, 18)
	binary.BigEndian.PutUint16(hdr[0:2], rtype)
	hdr[2] = 15           // Ed25519
	hdr[3] = byte(labels) //#nosec G115 -- test fixture: label count fits in uint8
	binary.BigEndian.PutUint32(hdr[4:8], ttl)
	binary.BigEndian.PutUint32(hdr[8:12], exp)
	binary.BigEndian.PutUint32(hdr[12:16], inc)
	binary.BigEndian.PutUint16(hdr[16:18], k.keyTag)

	msg := append(append([]byte{}, hdr...), dnsutil.CanonicalName(zone)...)
	rdatas := make([][]byte, 0, len(rrs))
	for _, rr := range rrs {
		rdatas = append(rdatas, dnsutil.RRData(rr))
	}
	sort.Slice(rdatas, func(i, j int) bool { return bytes.Compare(rdatas[i], rdatas[j]) < 0 })
	for _, rd := range rdatas {
		msg = append(msg, dnsutil.CanonicalName(owner)...)
		var rh [8]byte
		binary.BigEndian.PutUint16(rh[0:2], rtype)
		binary.BigEndian.PutUint16(rh[2:4], dns.ClassINET)
		binary.BigEndian.PutUint32(rh[4:8], ttl)
		msg = append(msg, rh[:]...)
		var rl [2]byte
		binary.BigEndian.PutUint16(rl[:], uint16(len(rd)))
		msg = append(msg, rl[:]...)
		msg = append(msg, rd...)
	}

	sig := ed25519.Sign(k.priv, msg)
	if tamper {
		sig[0] ^= 0xff
	}
	return &dns.RRSIG{
		Hdr:         dns.RR_Header{Name: owner, Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: ttl},
		TypeCovered: rtype,
		Algorithm:   15,
		Labels:      uint8(labels), //#nosec G115 -- test fixture: label count fits in uint8
		OrigTtl:     ttl,
		Expiration:  exp,
		Inception:   inc,
		KeyTag:      k.keyTag,
		SignerName:  name(zone),
		Signature:   base64.StdEncoding.EncodeToString(sig),
	}
}

// UnsignedParentNSEC is an unsigned zone whose negative responses carry NSEC
// records signed by the parent zone, as real delegations do.
func UnsignedParentNSEC() *resolver.Zone {
	zone := "unsignedparent.test."
	parent := "test."
	nsecRR := &dns.NSEC{
		Hdr:        dns.RR_Header{Name: name(zone), Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: 3600},
		NextDomain: name(zone),
		TypeBitMap: []uint16{dns.TypeNS, dns.TypeSOA, dns.TypeRRSIG, dns.TypeNSEC},
	}
	now := time.Now()
	exp := uint32(now.Add(48 * time.Hour).Unix()) //#nosec G115 -- test fixture: Unix time fits in uint32
	inc := uint32(now.Add(-1 * time.Hour).Unix()) //#nosec G115 -- test fixture: Unix time fits in uint32
	sig := signRR(nsecRR, dns.TypeNSEC, exp, inc, 257, 15)
	if rrsig, ok := sig.(*dns.RRSIG); ok {
		rrsig.SignerName = name(parent) // signed by the parent, not this zone
	}
	return &resolver.Zone{
		Name: zone,
		Records: map[string][]dns.RR{
			zone: {
				soa(zone, "ns1.unsignedparent.test.", "admin.unsignedparent.test.", 2024010101, 7200, 1800, 1209600, 3600, 3600),
				ns(zone, "ns1.unsignedparent.test.", 3600),
				a(zone, "203.0.113.200", 300),
				nsecRR,
				sig,
			},
			"ns1.unsignedparent.test.": {a("ns1.unsignedparent.test.", "198.51.100.200", 3600)},
		},
	}
}

// DNSSECSigned returns a fully and correctly signed zone: real Ed25519
// signatures over the apex RRsets, a matching DS at the delegation, and an
// NSEC record for authenticated denial of existence.
func DNSSECSigned() *resolver.Zone {
	return signedZone(false)
}

// DNSSECTampered returns a signed zone whose apex A RRSIG is corrupted, so
// cryptographic verification must fail.
func DNSSECTampered() *resolver.Zone {
	return signedZone(true)
}

func signedZone(tamper bool) *resolver.Zone {
	zone := "signed.test."
	k := newTestKey()

	soaRR := soa(zone, "ns1.signed.test.", "admin.signed.test.", 2024010101, 7200, 1800, 1209600, 3600, 3600)
	ns1 := ns(zone, "ns1.signed.test.", 3600)
	ns2 := ns(zone, "ns2.signed.test.", 3600)
	aRR := a(zone, "93.184.216.34", 300)
	txtRR := txt(zone, "v=spf1 -all", 300)
	dk := k.dnskeyRR(zone)
	dsRR := k.dsRR(zone, dk)
	nsecRR := &dns.NSEC{
		Hdr:        dns.RR_Header{Name: name(zone), Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: 3600},
		NextDomain: name(zone),
		TypeBitMap: []uint16{dns.TypeA, dns.TypeNS, dns.TypeSOA, dns.TypeTXT, dns.TypeRRSIG, dns.TypeNSEC, dns.TypeDNSKEY},
	}

	return &resolver.Zone{
		Name: zone,
		Records: map[string][]dns.RR{
			zone: {
				soaRR, ns1, ns2, aRR, txtRR, dk, dsRR, nsecRR,
				k.signRRset(zone, []dns.RR{soaRR}, false),
				k.signRRset(zone, []dns.RR{ns1, ns2}, false),
				k.signRRset(zone, []dns.RR{aRR}, tamper),
				k.signRRset(zone, []dns.RR{txtRR}, false),
				k.signRRset(zone, []dns.RR{dk}, false),
				k.signRRset(zone, []dns.RR{nsecRR}, false),
			},
			"ns1.signed.test.": {a("ns1.signed.test.", "1.1.1.1", 3600)},
			"ns2.signed.test.": {a("ns2.signed.test.", "1.0.0.1", 3600)},
		},
	}
}
