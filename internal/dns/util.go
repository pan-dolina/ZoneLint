// Package dns provides defensive DNS message parsing and record-extraction
// helpers built on top of github.com/miekg/dns. All functions are tolerant of
// hostile or malformed input: they never panic and always bound their work.
package dnsutil

import (
	"encoding/binary"
	"encoding/hex"
	"net"
	"strings"

	"github.com/miekg/dns"
)

func decodeHexField(s string) ([]byte, error) {
	return hex.DecodeString(strings.TrimSpace(s))
}

// ipTo4 returns the 4-byte form of an IPv4 address for wire-format RDATA.
func ipTo4(ip net.IP) []byte {
	if v4 := ip.To4(); v4 != nil {
		return append([]byte{}, v4...)
	}
	return append([]byte{}, ip...)
}

// SafeNewMsg returns a well-formed query message.
func SafeNewMsg(name string, qtype uint16) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)
	m.RecursionDesired = false
	return m
}

// SetEDNS configures EDNS0 with the DO (DNSSEC-OK) bit when dnssec is true and
// a reasonable udp size. It never fails.
func SetEDNS(m *dns.Msg, udpSize int, dnssec bool) {
	if udpSize <= 0 {
		udpSize = 1232
	}
	edns := m.IsEdns0()
	if edns == nil {
		return
	}
	edns.SetUDPSize(uint16(udpSize))
	edns.SetDo(dnssec)
}

// RRByName groups resource records by their name (lowercased, no trailing dot).
func RRByName(records []dns.RR) map[string][]dns.RR {
	out := map[string][]dns.RR{}
	for _, rr := range records {
		if rr == nil {
			continue
		}
		name := dns.Fqdn(rr.Header().Name)
		out[normName(name)] = append(out[normName(name)], rr)
	}
	return out
}

func normName(n string) string {
	return strings.ToLower(n)
}

// Names returns the set of hostnames referenced by NS records.
func NSNames(records []dns.RR) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, rr := range records {
		ns, ok := rr.(*dns.NS)
		if !ok {
			continue
		}
		n := normName(ns.Ns)
		if _, dup := seen[n]; !dup {
			seen[n] = struct{}{}
			out = append(out, n)
		}
	}
	return out
}

// Addrs returns the addresses referenced by A/AAAA records, normalized.
func Addrs(records []dns.RR) []net.IP {
	var out []net.IP
	for _, rr := range records {
		switch r := rr.(type) {
		case *dns.A:
			if r.A != nil {
				out = append(out, r.A)
			}
		case *dns.AAAA:
			if r.AAAA != nil {
				out = append(out, r.AAAA)
			}
		}
	}
	return out
}

// TTL returns the TTL of a record header, guarding against nil.
func TTL(rr dns.RR) uint32 {
	if rr == nil || rr.Header() == nil {
		return 0
	}
	return rr.Header().Ttl
}

// SOA extracts an SOA record from a record set, if present.
func SOA(records []dns.RR) *dns.SOA {
	for _, rr := range records {
		if soa, ok := rr.(*dns.SOA); ok {
			return soa
		}
	}
	return nil
}

// First returns the first record of a given type, or nil.
func First(records []dns.RR, typ uint16) dns.RR {
	for _, rr := range records {
		if rr == nil {
			continue
		}
		if rr.Header().Rrtype == typ {
			return rr
		}
	}
	return nil
}

// RRsOfType returns records of a given type.
func RRsOfType(records []dns.RR, typ uint16) []dns.RR {
	var out []dns.RR
	for _, rr := range records {
		if rr != nil && rr.Header().Rrtype == typ {
			out = append(out, rr)
		}
	}
	return out
}

// RRData returns the wire-format RDATA of a record, or nil if unavailable.
// Names are emitted in uncompressed form (RFC 4034 §3.1.3 canonical form).
func RRData(rr dns.RR) []byte {
	if rr == nil {
		return nil
	}
	switch r := rr.(type) {
	case *dns.A:
		if r.A == nil {
			return nil
		}
		return ipTo4(r.A)
	case *dns.AAAA:
		if r.AAAA == nil {
			return nil
		}
		return r.AAAA
	case *dns.NS:
		return uncompressedName(r.Ns)
	case *dns.SOA:
		return uncompressedName(r.Ns)
	case *dns.TXT:
		return txtRdata(r)
	case *dns.CNAME:
		return uncompressedName(r.Target)
	case *dns.MX:
		pref := make([]byte, 2)
		binary.BigEndian.PutUint16(pref, r.Preference)
		return append(pref, uncompressedName(r.Mx)...)
	case *dns.CAA:
		return caaRdata(r)
	case *dns.DNSKEY:
		return dnskeyRdata(r)
	case *dns.DS:
		return dsRdata(r)
	}
	return nil
}

// uncompressedName returns the dot-labeled, zero-terminated form of a name.
func uncompressedName(n string) []byte {
	n = dns.Fqdn(n)
	var out []byte
	for _, label := range splitLabels(n) {
		if len(label) > 63 {
			label = label[:63]
		}
		out = append(out, byte(len(label)))
		out = append(out, label...)
	}
	return append(out, 0x00)
}

func splitLabels(n string) []string {
	n = n[:len(n)-1] // strip trailing dot
	if n == "" {
		return []string{""}
	}
	return strings.Split(n, ".")
}

func soaRdata(r *dns.SOA) []byte {
	return uncompressedName(r.Ns)
}

func txtRdata(r *dns.TXT) []byte {
	var out []byte
	for _, s := range r.Txt {
		if len(s) > 255 {
			s = s[:255]
		}
		out = append(out, byte(len(s)))
		out = append(out, s...)
	}
	return out
}

func caaRdata(r *dns.CAA) []byte {
	out := []byte{r.Flag}
	tag := []byte(r.Tag)
	if len(tag) > 63 {
		tag = tag[:63]
	}
	out = append(out, byte(len(tag)))
	out = append(out, tag...)
	return append(out, r.Value...)
}

func dnskeyRdata(r *dns.DNSKEY) []byte {
	out := make([]byte, 3)
	binary.BigEndian.PutUint16(out, r.Flags)
	out = append(out, byte(r.Algorithm))
	return append(out, r.PublicKey...)
}

func dsRdata(r *dns.DS) []byte {
	out := make([]byte, 4)
	binary.BigEndian.PutUint16(out, r.KeyTag)
	out = append(out, byte(r.Algorithm), byte(r.DigestType))
	d, err := decodeHexField(r.Digest)
	if err == nil {
		out = append(out, d...)
	}
	return out
}

// RRSIGData returns the wire-format RDATA of an RRSIG (without the header).
func RRSIGData(rr *dns.RRSIG) []byte {
	buf := make([]byte, 18)
	binary.BigEndian.PutUint16(buf[0:2], uint16(rr.TypeCovered))
	buf[2] = byte(rr.Algorithm)
	buf[3] = rr.Labels
	binary.BigEndian.PutUint32(buf[4:8], rr.OrigTtl)
	binary.BigEndian.PutUint32(buf[8:12], rr.Expiration)
	binary.BigEndian.PutUint32(buf[12:16], rr.Inception)
	binary.BigEndian.PutUint16(buf[16:18], rr.KeyTag)
	return append(buf, rr.Signature...)
}

// RcodeString is a safe Rcode string.
func RcodeString(m *dns.Msg) string {
	if m == nil {
		return "nil"
	}
	return dns.RcodeToString[m.Rcode]
}
