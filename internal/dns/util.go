// Package dns provides defensive DNS message parsing and record-extraction
// helpers built on top of github.com/miekg/dns. All functions are tolerant of
// hostile or malformed input: they never panic and always bound their work.
package dnsutil

import (
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"net"
	"strings"

	"github.com/miekg/dns"
)

func decodeHexField(s string) ([]byte, error) {
	return hex.DecodeString(strings.TrimSpace(s))
}

// decodeBase64Field decodes base64 text as used in DNS presentation/wire
// formats. If the input is not valid base64 it is returned raw, so callers
// work with both base64 text and already-decoded bytes.
func decodeBase64Field(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	if b, err := base64.RawStdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return []byte(s), nil
}

// decodeBase32HexField decodes base32hex (RFC 4648, no padding) text as used
// for NSEC3 next-domain fields.
func decodeBase32HexField(s string) ([]byte, error) {
	s = strings.TrimSpace(strings.ToUpper(s))
	if s == "" {
		return nil, nil
	}
	return base32.HexEncoding.WithPadding(base32.NoPadding).DecodeString(s)
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
	// Recursion is desired by default: the primary resolver is a recursive
	// resolver (system resolver or a configured public resolver). Authoritative
	// server probes disable recursion explicitly.
	m.RecursionDesired = true
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

// RRData returns the wire-format RDATA of a record in canonical form
// (RFC 4034 §3.1.3: names lowercase and uncompressed), or nil if unavailable.
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
		out := uncompressedName(r.Ns)
		out = append(out, uncompressedName(r.Mbox)...)
		var tail [20]byte
		binary.BigEndian.PutUint32(tail[0:4], r.Serial)
		binary.BigEndian.PutUint32(tail[4:8], r.Refresh)
		binary.BigEndian.PutUint32(tail[8:12], r.Retry)
		binary.BigEndian.PutUint32(tail[12:16], r.Expire)
		binary.BigEndian.PutUint32(tail[16:20], r.Minttl)
		return append(out, tail[:]...)
	case *dns.TXT:
		return txtRdata(r)
	case *dns.CNAME:
		return uncompressedName(r.Target)
	case *dns.PTR:
		return uncompressedName(r.Ptr)
	case *dns.MX:
		pref := make([]byte, 2)
		binary.BigEndian.PutUint16(pref, r.Preference)
		return append(pref, uncompressedName(r.Mx)...)
	case *dns.SRV:
		out := make([]byte, 6)
		binary.BigEndian.PutUint16(out[0:2], r.Priority)
		binary.BigEndian.PutUint16(out[2:4], r.Weight)
		binary.BigEndian.PutUint16(out[4:6], r.Port)
		return append(out, uncompressedName(r.Target)...)
	case *dns.CAA:
		return caaRdata(r)
	case *dns.DNSKEY:
		return dnskeyRdata(r)
	case *dns.DS:
		return dsRdata(r)
	case *dns.NSEC:
		out := uncompressedName(r.NextDomain)
		return append(out, typeBitmap(r.TypeBitMap)...)
	case *dns.NSEC3:
		salt, err := decodeHexField(r.Salt)
		if err != nil {
			return nil
		}
		next, err := decodeBase32HexField(r.NextDomain)
		if err != nil {
			return nil
		}
		out := []byte{r.Hash, r.Flags}
		out = append(out, byte(r.Iterations>>8), byte(r.Iterations))
		out = append(out, byte(len(salt))) //#nosec G115 -- salt length fits in uint8 on the wire
		out = append(out, salt...)
		out = append(out, byte(len(next))) //#nosec G115 -- hash length fits in uint8 on the wire
		out = append(out, next...)
		return append(out, typeBitmap(r.TypeBitMap)...)
	}
	return nil
}

// typeBitmap encodes an NSEC/NSEC3 type bitmap (RFC 4034 §4.1.2).
func typeBitmap(types []uint16) []byte {
	sorted := make([]int, 0, len(types))
	seen := map[int]bool{}
	for _, t := range types {
		if !seen[int(t)] {
			seen[int(t)] = true
			sorted = append(sorted, int(t))
		}
	}
	// Insertion sort: type bitmaps are tiny.
	for i := 1; i < len(sorted); i++ {
		for j := i; j > 0 && sorted[j] < sorted[j-1]; j-- {
			sorted[j], sorted[j-1] = sorted[j-1], sorted[j]
		}
	}
	var out []byte
	for i := 0; i < len(sorted); {
		window := byte(sorted[i] >> 8)
		last := i
		for last < len(sorted) && byte(sorted[last]>>8) == window {
			last++
		}
		bits := make([]byte, 32)
		for _, t := range sorted[i:last] {
			bits[(t&0xff)>>3] |= 0x80 >> (uint(t) & 7)
		}
		out = append(out, window, 0)
		n := 32
		for n > 0 && bits[n-1] == 0 {
			n--
		}
		out[len(out)-1] = byte(n)
		out = append(out, bits[:n]...)
		i = last
	}
	return out
}

// CanonicalName returns the canonical wire form of a DNS name: lowercase,
// dot-labeled, zero-terminated (RFC 4034 §6.2).
func CanonicalName(n string) []byte {
	return uncompressedName(n)
}

// uncompressedName returns the canonical wire form of a name: lowercase and
// uncompressed (RFC 4034 §6.2). DNS presentation escapes (e.g. \000) are
// decoded by the packer.
func uncompressedName(n string) []byte {
	n = dns.Fqdn(strings.ToLower(n))
	buf := make([]byte, 256)
	off, err := dns.PackDomainName(n, buf, 0, nil, false)
	if err != nil {
		return nil
	}
	return buf[:off]
}

func splitLabels(n string) []string {
	n = n[:len(n)-1] // strip trailing dot
	if n == "" {
		return []string{""}
	}
	return strings.Split(n, ".")
}

func txtRdata(r *dns.TXT) []byte {
	var out []byte
	for _, s := range r.Txt {
		if len(s) > 255 {
			s = s[:255]
		}
		out = append(out, byte(len(s))) //#nosec G115 -- name length is bounded to 255 by the check above
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
	out = append(out, byte(len(tag))) //#nosec G115 -- CAA tag length is bounded to 63 by the check above
	out = append(out, tag...)
	return append(out, r.Value...)
}

// dnskeyRdata returns the canonical wire-format DNSKEY RDATA:
// Flags (uint16), Protocol (uint8), Algorithm (uint8), PublicKey.
func dnskeyRdata(r *dns.DNSKEY) []byte {
	key, err := decodeBase64Field(r.PublicKey)
	if err != nil {
		return nil
	}
	out := make([]byte, 4)
	binary.BigEndian.PutUint16(out[0:2], r.Flags)
	out[2] = r.Protocol
	out[3] = r.Algorithm
	return append(out, key...)
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
